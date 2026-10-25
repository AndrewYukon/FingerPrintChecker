"""Exception types raised by the SDK."""
from __future__ import annotations

from typing import Any, Optional


class FpCheckerApiError(Exception):
    """Raised for any non-2xx API response, and for network failures (status 0).

    2xx bodies (including ``{"ok": false, ...}`` refusals) are returned as data.
    """

    def __init__(
        self,
        status: int,
        code: Optional[str],
        retry_after: Optional[int] = None,
        body: Any = None,
    ) -> None:
        suffix = f" ({code})" if code else ""
        super().__init__(f"FpChecker API error: HTTP {status}{suffix}")
        self.status = status
        #: ``body["error"]`` or ``body["reason"]``; ``"network_error"`` / ``"timeout"`` for status 0.
        self.code = code
        #: Retry-After in seconds, or None.
        self.retry_after = retry_after
        self.body = body


class SealedResultError(Exception):
    """``code`` is bad_format | unknown_key | decrypt_failed | invalid_key | unsupported_version."""

    def __init__(self, code: str) -> None:
        super().__init__(f"sealed result: {code}")
        self.code = code


class WebhookSignatureError(Exception):
    """``code`` is expired | future | bad_signature | malformed_header."""

    def __init__(self, code: str) -> None:
        super().__init__(f"webhook signature: {code}")
        self.code = code
