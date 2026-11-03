"""Server-side Esaalat client.

    from esaalat import EsaalatClient

    esaalat = EsaalatClient.from_env()
    session = esaalat.create_session(order_id="order-123", amount=5000)
    # browser: checkout.open({ sessionToken: session["session_token"] })

    event = esaalat.verify_webhook(request.data, request.headers["X-Esaalat-Signature"])

The client owns the three parts a merchant backend always writes by hand: the
1-hour token (cached, refreshed from its own ``exp`` claim), the idempotency
key (generated per create, reused on every retry) and the webhook HMAC (raw
body, constant-time compare, replay window). Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from decimal import Decimal
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from .errors import EsaalatError, EsaalatWebhookError

DEFAULT_API_BASE = "https://api.esaalat.com/api/v1"
DEFAULT_TIMEOUT = 20.0
DEFAULT_TOKEN_SKEW = 60.0
# The JWT lives one hour and its `exp` is authoritative; this is the fallback
# for an opaque token.
DEFAULT_TOKEN_TTL = 3300.0
DEFAULT_WEBHOOK_TOLERANCE = 300
RETRY_BASE_SECONDS = 0.4

Amount = Union[str, int, float, Decimal]

# transport(method, url, headers, body, timeout) -> (status, headers, body)
Transport = Callable[
    [str, str, Mapping[str, str], Optional[bytes], float],
    Tuple[int, Mapping[str, str], bytes],
]


def format_amount(value: Amount) -> str:
    """Whole riyals, as the API requires.

    ``5000``, ``5000.0``, ``Decimal("5000")`` and ``"5000"`` all become
    ``"5000"``; a fraction is refused here rather than by the API after the
    buyer has clicked pay.
    """
    if isinstance(value, bool):
        raise EsaalatError(
            "Amount must be a whole number of riyals, got a boolean.",
            code="configuration",
        )
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        if value != value.to_integral_value():
            raise EsaalatError(
                "Amount must be a whole number of riyals, got %s." % value,
                code="configuration",
            )
        return str(int(value))
    if isinstance(value, float):
        if not value.is_integer():
            raise EsaalatError(
                "Amount must be a whole number of riyals, got %s." % value,
                code="configuration",
            )
        return str(int(value))
    text = str(value).strip()
    if not text.isdigit():
        raise EsaalatError(
            'Amount must be a whole number of riyals, got "%s".' % text,
            code="configuration",
        )
    return text


def _jwt_expiry(token: str) -> Optional[float]:
    """The token's ``exp`` claim in epoch seconds, when it has one."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:  # noqa: BLE001 - an opaque token is not an error here
        return None
    exp = data.get("exp") if isinstance(data, dict) else None
    if isinstance(exp, (int, float)):
        return float(exp)
    return None


def _urllib_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: Optional[bytes],
    timeout: float,
) -> Tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(
        url, data=body, headers=dict(headers), method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers or {}), error.read()
    except urllib.error.URLError as error:
        raise EsaalatError(
            "Could not reach Esaalat at %s." % url, code="network"
        ) from error
    except TimeoutError as error:
        raise EsaalatError(
            "Esaalat did not answer within %s s." % timeout, code="timeout"
        ) from error


def _api_error(status: int, raw: bytes) -> EsaalatError:
    detail = ""
    attr: Optional[str] = None
    errors: list = []
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        parsed = {}
    if isinstance(parsed, dict):
        items = parsed.get("errors")
        if not isinstance(items, list):
            items = [parsed["detail"]] if "detail" in parsed else []
        for item in items:
            if isinstance(item, str):
                errors.append({"code": "error", "detail": item, "attr": None})
            elif isinstance(item, dict):
                errors.append(
                    {
                        "code": item.get("code") or "error",
                        "detail": item.get("detail") or "",
                        "attr": item.get("attr"),
                    }
                )
        if errors:
            detail = errors[0]["detail"] or ""
            attr = errors[0]["attr"]
    if not detail:
        detail = "Esaalat rejected the request (HTTP %s)." % status
    return EsaalatError(detail, code="api", status=status, detail=detail,
                        attr=attr, errors=errors)


class EsaalatClient:
    """Create sessions, intents and verify webhooks — with your client secret."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = 2,
        webhook_secret: Optional[str] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        self.client_id = client_id or os.environ.get("ESAALAT_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get(
            "ESAALAT_CLIENT_SECRET", ""
        )
        if not self.client_id or not self.client_secret:
            raise EsaalatError(
                "Missing API credentials. Pass client_id/client_secret or set "
                "ESAALAT_CLIENT_ID and ESAALAT_CLIENT_SECRET.",
                code="configuration",
            )
        self.base_url = (
            base_url
            or os.environ.get("ESAALAT_BASE_URL")
            or DEFAULT_API_BASE
        ).rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            raise EsaalatError(
                'base_url must be an http(s) URL, got "%s".' % self.base_url,
                code="configuration",
            )
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.webhook_secret = webhook_secret or os.environ.get(
            "ESAALAT_WEBHOOK_SECRET"
        )
        self._transport = transport or _urllib_transport
        self._token: Optional[str] = None
        self._token_expires_at = 0.0

    @classmethod
    def from_env(cls, **kwargs: Any) -> "EsaalatClient":
        """Build the client from ``ESAALAT_*`` environment variables."""
        return cls(**kwargs)

    # -- public surface ----------------------------------------------------

    def create_session(self, **input: Any) -> Dict[str, Any]:
        """Create a hosted checkout session and return the API's 201 payload.

        ``order_id``/``external_order_id`` become ``external_order_id``;
        ``amount`` must be whole riyals. The browser only needs
        ``session_token`` from the response.
        """
        body = _session_body(input)
        return self._request(
            "POST",
            "/checkout/merchant/sessions/",
            body,
            idempotency_key=input.get("idempotency_key")
            or _uuid4(),
        )

    def create_intent(self, **input: Any) -> Dict[str, Any]:
        """Create a payment intent (server-driven orders: marketplaces, Shopify)."""
        body = {
            "wallet": input.get("wallet"),
            "currency": input.get("currency"),
            "external_order_id": input.get("order_id")
            or input.get("external_order_id"),
            "notes": input.get("notes"),
        }
        if input.get("amount") is not None:
            body["amount"] = format_amount(input["amount"])
        if input.get("items"):
            body["items"] = _items(input["items"])
        return self._request(
            "POST",
            "/merchant/intents/",
            body,
            idempotency_key=input.get("idempotency_key") or _uuid4(),
        )

    def retrieve_intent(self, intent_id: str) -> Dict[str, Any]:
        """Read one intent's current status."""
        return self._request("GET", "/merchant/intents/%s/" % intent_id)

    def attach_reference(self, intent_id: str, reference: str) -> Dict[str, Any]:
        """Attach the buyer's wallet reference to a pending intent."""
        return self._request(
            "PATCH",
            "/merchant/intents/%s/" % intent_id,
            {"reference": reference},
        )

    def verify_webhook(
        self,
        raw_body: Union[bytes, str],
        signature: str,
        *,
        secret: Optional[str] = None,
        tolerance: int = DEFAULT_WEBHOOK_TOLERANCE,
    ) -> Dict[str, Any]:
        """Verify ``X-Esaalat-Signature`` over the raw body and return the event.

        Pass the bytes you received, not a re-serialized object: the HMAC is
        computed over exactly what Esaalat sent. Raises ``EsaalatWebhookError``
        when the signature, its age, or the body itself does not hold up — catch
        it and answer ``400``.
        """
        secret = secret or self.webhook_secret
        if not secret:
            raise EsaalatError(
                "No webhook secret. Pass webhook_secret to EsaalatClient, set "
                "ESAALAT_WEBHOOK_SECRET, or pass secret= per call.",
                code="configuration",
            )

        timestamp, provided = _parse_signature(signature)
        if tolerance and abs(time.time() - timestamp) > tolerance:
            raise EsaalatWebhookError(
                "Webhook timestamp is outside the %ss window (possible replay)."
                % tolerance
            )

        body = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
        expected = hmac.new(
            secret.encode("utf-8"),
            ("%s." % timestamp).encode("utf-8") + body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, provided):
            raise EsaalatWebhookError(
                "Webhook signature does not match. Verify against the raw "
                "request body and this endpoint's secret."
            )

        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            raise EsaalatWebhookError("Webhook body is not JSON.") from error
        if not isinstance(payload, dict):
            raise EsaalatWebhookError("Webhook body is not a JSON object.")
        return payload

    # -- internals ---------------------------------------------------------

    def _access_token(self) -> str:
        now = time.time()
        if self._token and self._token_expires_at - DEFAULT_TOKEN_SKEW > now:
            return self._token

        status, _headers, raw = self._transport(
            "POST",
            self.base_url + "/merchant/token",
            {
                "ESAALAT-CLIENT-ID": self.client_id,
                "ESAALAT-CLIENT-SECRET": self.client_secret,
                "Accept": "application/json",
            },
            None,
            self.timeout,
        )
        if not 200 <= status < 300:
            raise _api_error(status, raw)

        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            data = {}
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise EsaalatError(
                "Esaalat did not return an access token.", status=status
            )

        self._token = token
        self._token_expires_at = _jwt_expiry(token) or (now + DEFAULT_TOKEN_TTL)
        return token

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = self.base_url + path
        body = (
            json.dumps(_prune(payload)).encode("utf-8")
            if payload is not None
            else None
        )
        authorization = self._access_token()
        refreshed = False
        retries = 0

        while True:
            headers = {"Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            if authorization:
                headers["Authorization"] = "Bearer " + authorization
            if idempotency_key:
                headers["ESAALAT-IDEMPOTENCY-KEY"] = idempotency_key

            try:
                status, response_headers, raw = self._transport(
                    method, url, headers, body, self.timeout
                )
            except EsaalatError as error:
                if error.code in ("network", "timeout") and retries < self.max_retries:
                    time.sleep(RETRY_BASE_SECONDS * (2 ** retries))
                    retries += 1
                    continue
                raise

            if 200 <= status < 300:
                if not raw:
                    return {}
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as error:
                    raise EsaalatError(
                        "Esaalat returned a response that is not JSON.",
                        status=status,
                    ) from error
                return parsed if isinstance(parsed, dict) else {"data": parsed}

            if status == 401 and not refreshed and authorization:
                refreshed = True
                self._token = None
                authorization = self._access_token()
                continue

            if (status == 429 or status >= 500) and retries < self.max_retries:
                delay = _retry_after(response_headers)
                time.sleep(delay if delay is not None
                           else RETRY_BASE_SECONDS * (2 ** retries))
                retries += 1
                continue

            raise _api_error(status, raw)


def _session_body(input: Dict[str, Any]) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "currency": input.get("currency"),
        "external_order_id": input.get("order_id")
        or input.get("external_order_id"),
        "wallet": input.get("wallet"),
        "notes": input.get("notes"),
    }
    if input.get("amount") is not None:
        body["amount"] = format_amount(input["amount"])
    if input.get("items"):
        body["items"] = _items(input["items"])
    if input.get("show_testing_wallet") is not None:
        body["show_testing_wallet"] = bool(input["show_testing_wallet"])
    return body


def _items(items: Any) -> list:
    normalized = []
    for item in items:
        entry = {
            "name": item.get("name"),
            "description": item.get("description"),
            "price": format_amount(item["price"]),
            "quantity": item.get("quantity"),
        }
        normalized.append(_prune(entry))
    return normalized


def _prune(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {key: value for key, value in (payload or {}).items()
            if value is not None}


def _parse_signature(header: str) -> Tuple[int, str]:
    timestamp: Optional[int] = None
    signature = ""
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                timestamp = None
        elif key == "v1":
            signature = value.lower()
    if timestamp is None or not signature:
        raise EsaalatWebhookError("Malformed X-Esaalat-Signature header.")
    return timestamp, signature


def _retry_after(headers: Mapping[str, str]) -> Optional[float]:
    for key, value in headers.items():
        if key.lower() == "retry-after":
            try:
                return max(0.0, float(value))
            except ValueError:
                return None
    return None


def _uuid4() -> str:
    import uuid

    return str(uuid.uuid4())
