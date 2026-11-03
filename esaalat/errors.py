"""Errors raised by the Esaalat server client."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class EsaalatError(Exception):
    """Every failure the client raises.

    ``code`` says whose fault it is in the caller's terms:

    * ``configuration`` — a key, a URL or a missing webhook secret.
    * ``network`` / ``timeout`` — retry later.
    * ``api`` — the request reached Esaalat and was rejected; ``status``,
      ``detail`` and ``attr`` say what.
    * ``webhook`` — a signature that does not verify.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "api",
        status: Optional[int] = None,
        detail: Optional[str] = None,
        attr: Optional[str] = None,
        errors: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.detail = detail
        self.attr = attr
        self.errors = errors or []

    def __str__(self) -> str:  # pragma: no cover - inherited message is enough
        return str(self.args[0]) if self.args else self.code


class EsaalatWebhookError(EsaalatError):
    """A webhook body that does not match its signature (or is stale)."""

    def __init__(self, message: str, *, status: int = 400) -> None:
        super().__init__(message, code="webhook", status=status)
