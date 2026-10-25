"""Decrypt the ``sealedResult`` blob returned by /v2/identify."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Dict, Iterable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import SealedResultError

_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_MAGIC = b"fps1"
_MIN_LEN = 4 + 4 + 12 + 16


def _strict_b64(value: Any) -> Optional[bytes]:
    """Canonical standard base64 only (regex, length, decode, re-encode equality)."""
    if not isinstance(value, str) or len(value) % 4 != 0 or not _B64.fullmatch(value):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        return None
    return raw if base64.b64encode(raw).decode("ascii") == value else None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON constant {name}")


def unseal_result(blob: str, keys: Iterable[str]) -> Dict[str, Any]:
    """Decrypt a sealed result. ``keys`` are base64 32-byte project keys
    (pass active and previous during rotation). Raises SealedResultError."""
    if isinstance(keys, (str, bytes)) or not isinstance(keys, (list, tuple)):
        raise SealedResultError("invalid_key")
    key_bytes = []
    for k in keys:
        b = _strict_b64(k)
        if b is None or len(b) != 32:
            raise SealedResultError("invalid_key")
        key_bytes.append(b)

    raw = _strict_b64(blob)
    if raw is None or len(raw) < _MIN_LEN or raw[:4] != _MAGIC:
        raise SealedResultError("bad_format")

    aad = raw[:8]
    key_id = raw[4:8]
    candidates = [k for k in key_bytes if hashlib.sha256(k).digest()[:4] == key_id]
    if not candidates:
        raise SealedResultError("unknown_key")

    nonce, ct_and_tag = raw[8:20], raw[20:]
    plain: Optional[bytes] = None
    for key in candidates:
        try:
            plain = AESGCM(key).decrypt(nonce, ct_and_tag, aad)
            break
        except InvalidTag:
            continue
    if plain is None:
        raise SealedResultError("decrypt_failed")

    try:
        parsed = json.loads(plain.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # includes UnicodeDecodeError
        raise SealedResultError("decrypt_failed") from None
    if not isinstance(parsed, dict):
        raise SealedResultError("decrypt_failed")
    version = parsed.get("version")
    if isinstance(version, bool) or version != 1:
        raise SealedResultError("unsupported_version")
    return parsed
