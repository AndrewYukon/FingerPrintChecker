"""Verify the ``FPC-Signature`` header on webhook deliveries."""
from __future__ import annotations

import hashlib
import hmac
import math
import re
import time
from typing import List, Optional, Tuple, Union

from .errors import WebhookSignatureError

_WS = re.compile(r"[ \t\r\n]")
_T = re.compile(r"[0-9]{1,12}")
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")


def _parse_header(header: object) -> Tuple[str, int, List[str]]:
    if not isinstance(header, str) or _WS.search(header):
        raise WebhookSignatureError("malformed_header")
    t: Optional[str] = None
    v1: List[str] = []
    for part in header.split(","):
        key, sep, value = part.partition("=")
        if part == "" or not sep:
            raise WebhookSignatureError("malformed_header")
        if key == "t":
            if t is not None:
                raise WebhookSignatureError("malformed_header")
            t = value
        elif key == "v1":
            v1.append(value)
    if t is None or not _T.fullmatch(t) or not v1:
        raise WebhookSignatureError("malformed_header")
    return t, int(t), v1


def _to_bytes(raw_body: Union[bytes, bytearray, memoryview, str]) -> bytes:
    if isinstance(raw_body, str):
        # Same as Node's Buffer.from(str, "utf8"): a lone surrogate becomes U+FFFD
        # (so the MAC simply will not match) instead of raising.
        return raw_body.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")
    return bytes(raw_body)


def verify_webhook_signature(
    raw_body: Union[bytes, bytearray, memoryview, str],
    header: str,
    secret: str,
    tolerance_sec: Union[int, float] = 300,
    now: Optional[Union[int, float]] = None,
) -> None:
    """Return None if ``header`` is a valid, fresh signature of ``raw_body``,
    else raise WebhookSignatureError. ``raw_body`` must be the exact bytes received."""
    if (
        isinstance(tolerance_sec, bool)
        or not isinstance(tolerance_sec, (int, float))
    ):
        raise TypeError("tolerance_sec must be a finite number >= 0")
    if not math.isfinite(tolerance_sec) or tolerance_sec < 0:
        raise ValueError("tolerance_sec must be a finite number >= 0")
    if not isinstance(secret, str) or secret == "":
        raise ValueError("webhook secret must be a non-empty string")
    clock = time.time() if now is None else now
    t_raw, t, v1 = _parse_header(header)

    body = _to_bytes(raw_body)
    expected = hmac.new(secret.encode("utf-8"), t_raw.encode("ascii") + b"." + body, hashlib.sha256).digest()
    match = False
    for candidate in v1:
        if _HEX64.fullmatch(candidate) and hmac.compare_digest(bytes.fromhex(candidate), expected):
            match = True
    if not match:
        raise WebhookSignatureError("bad_signature")

    if clock - t > tolerance_sec:
        raise WebhookSignatureError("expired")
    if t - clock > tolerance_sec:
        raise WebhookSignatureError("future")
