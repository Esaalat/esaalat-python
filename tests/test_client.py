"""Tests for the Esaalat Python server client (standard library only)."""

from __future__ import annotations

import json
import time
import unittest

from esaalat import EsaalatClient, EsaalatError, EsaalatWebhookError, format_amount

SECRET = "whsec_test"
TOKEN = "token-abc"


class ScriptedTransport:
    """Answers from a script and records what was sent."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append(
            {"method": method, "url": url, "headers": dict(headers), "body": body}
        )
        if len(self._responses) > 1:
            status, extra_headers, payload = self._responses.pop(0)
        else:
            status, extra_headers, payload = self._responses[0]
        if isinstance(payload, bytes):
            raw = payload
        else:
            raw = json.dumps(payload).encode("utf-8")
        return status, extra_headers, raw


def _client(*responses, **kwargs):
    transport = ScriptedTransport(list(responses))
    client = EsaalatClient(
        "cid",
        "secret",
        webhook_secret=SECRET,
        transport=transport,
        **kwargs,
    )
    return client, transport


def _sign(body: bytes, timestamp: int, secret: str = SECRET) -> str:
    import hashlib
    import hmac

    digest = hmac.new(
        secret.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    return "t=%s,v1=%s" % (timestamp, digest)


class SessionTests(unittest.TestCase):
    def test_token_is_issued_once_and_reused(self):
        client, transport = _client(
            (200, {}, {"access_token": TOKEN}),
            (201, {}, {"session_token": "s-1"}),
            (201, {}, {"session_token": "s-2"}),
        )

        client.create_session(order_id="order-1", amount=5000)
        client.create_session(order_id="order-2", amount=6000)

        self.assertEqual(len(transport.calls), 3)
        self.assertTrue(transport.calls[0]["url"].endswith("/merchant/token"))
        self.assertEqual(
            transport.calls[1]["headers"]["Authorization"], "Bearer " + TOKEN
        )
        self.assertEqual(
            transport.calls[2]["headers"]["Authorization"], "Bearer " + TOKEN
        )

    def test_session_sends_amount_order_id_and_idempotency_key(self):
        client, transport = _client(
            (200, {}, {"access_token": TOKEN}),
            (201, {}, {"session_token": "s-1"}),
        )

        client.create_session(order_id="order-123", amount="5000")

        request = transport.calls[1]
        self.assertTrue(
            request["url"].endswith("/checkout/merchant/sessions/")
        )
        self.assertEqual(
            json.loads(request["body"]),
            {"amount": "5000", "external_order_id": "order-123"},
        )
        self.assertIn("ESAALAT-IDEMPOTENCY-KEY", request["headers"])

    def test_retries_a_429_with_the_same_idempotency_key(self):
        client, transport = _client(
            (200, {}, {"access_token": TOKEN}),
            (429, {"Retry-After": "0"}, {}),
            (201, {}, {"session_token": "s-1"}),
        )

        session = client.create_session(order_id="order-9", amount=2500)

        self.assertEqual(session["session_token"], "s-1")
        creates = [call for call in transport.calls if "/sessions/" in call["url"]]
        self.assertEqual(len(creates), 2)
        self.assertEqual(
            creates[0]["headers"]["ESAALAT-IDEMPOTENCY-KEY"],
            creates[1]["headers"]["ESAALAT-IDEMPOTENCY-KEY"],
        )

    def test_api_error_carries_the_field(self):
        client, _ = _client(
            (200, {}, {"access_token": TOKEN}),
            (
                400,
                {},
                {
                    "type": "validation_error",
                    "errors": [
                        {"code": "invalid", "detail": "Wallet not found.", "attr": "wallet"}
                    ],
                },
            ),
        )

        with self.assertRaises(EsaalatError) as caught:
            client.create_intent(wallet="missing", amount=1000)

        self.assertEqual(caught.exception.code, "api")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(caught.exception.attr, "wallet")
        self.assertEqual(caught.exception.detail, "Wallet not found.")


class WebhookTests(unittest.TestCase):
    def test_verifies_a_signed_body(self):
        client, _ = _client((200, {}, {"access_token": TOKEN}))
        body = json.dumps({"event": "payment.verified", "intent_id": "i1"}).encode()
        timestamp = int(time.time())

        payload = client.verify_webhook(body, _sign(body, timestamp))

        self.assertEqual(payload["event"], "payment.verified")
        self.assertEqual(payload["intent_id"], "i1")

    def test_rejects_a_tampered_body(self):
        client, _ = _client((200, {}, {"access_token": TOKEN}))
        body = b'{"event":"payment.verified","intent_id":"i1"}'
        timestamp = int(time.time())

        with self.assertRaises(EsaalatWebhookError):
            client.verify_webhook(body.replace(b"i1", b"i2"), _sign(body, timestamp))

    def test_rejects_a_stale_signature(self):
        client, _ = _client((200, {}, {"access_token": TOKEN}))
        body = b'{"event":"payment.verified"}'
        stale = int(time.time()) - 3600

        with self.assertRaises(EsaalatWebhookError):
            client.verify_webhook(body, _sign(body, stale))


class AmountTests(unittest.TestCase):
    def test_whole_riyals_only(self):
        self.assertEqual(format_amount(5000), "5000")
        self.assertEqual(format_amount("5000"), "5000")
        self.assertEqual(format_amount(5000.0), "5000")
        with self.assertRaises(EsaalatError):
            format_amount(5000.5)


if __name__ == "__main__":
    unittest.main()
