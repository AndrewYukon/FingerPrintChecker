import hashlib
import hmac
import json
import math
from pathlib import Path

import pytest

from fpchecker import WebhookSignatureError, verify_webhook_signature

V = json.loads((Path(__file__).parents[3] / "test-vectors" / "webhook-signature.json").read_text())
CASES = V["cases"]


def test_vector_count_is_not_filtered():
    assert len(CASES) == 17


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_webhook_vector(case):
    args = (case["body"].encode("utf-8"), case["header"], V["secret"])
    if case["expect"] is True:
        assert verify_webhook_signature(*args, now=case["now"]) is None
    else:
        with pytest.raises(WebhookSignatureError) as ei:
            verify_webhook_signature(*args, now=case["now"])
        assert ei.value.code == case["expect"]["error"]


def _sign(body: bytes, t: int, secret=V["secret"]):
    mac = hmac.new(secret.encode(), str(t).encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


def test_str_body_accepted_and_default_now():
    import time

    t = int(time.time())
    body = '{"a":"é"}'
    verify_webhook_signature(body, _sign(body.encode(), t), V["secret"])


@pytest.mark.parametrize("tol", [True, False, math.nan, math.inf, -math.inf, -1, -0.5, "300", None])
def test_tolerance_must_be_finite_nonnegative_number(tol):
    body = b"{}"
    with pytest.raises((TypeError, ValueError)):
        verify_webhook_signature(body, _sign(body, 1000), V["secret"], tolerance_sec=tol, now=1000)


def test_tolerance_zero_and_float():
    body = b"{}"
    verify_webhook_signature(body, _sign(body, 1000), V["secret"], tolerance_sec=0, now=1000)
    with pytest.raises(WebhookSignatureError) as ei:
        verify_webhook_signature(body, _sign(body, 1000), V["secret"], tolerance_sec=0, now=1001)
    assert ei.value.code == "expired"
    verify_webhook_signature(body, _sign(body, 1000), V["secret"], tolerance_sec=1.5, now=1001)


@pytest.mark.parametrize("header", [None, 5, b"t=1,v1=" + b"0" * 64])
def test_non_string_header_malformed(header):
    with pytest.raises(WebhookSignatureError) as ei:
        verify_webhook_signature(b"{}", header, V["secret"], now=1)
    assert ei.value.code == "malformed_header"


def test_unicode_digits_in_t_malformed():
    with pytest.raises(WebhookSignatureError) as ei:
        verify_webhook_signature(b"{}", "t=١٢,v1=" + "0" * 64, V["secret"], now=1)
    assert ei.value.code == "malformed_header"


def test_uses_constant_time_compare(monkeypatch):
    import fpchecker.webhook as w

    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(w.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    body = b"{}"
    verify_webhook_signature(body, _sign(body, 5), V["secret"], now=5)
    assert calls


def test_lone_surrogate_str_body_matches_node_replacement_semantics():
    # Node's Buffer.from(str,'utf8') turns a lone surrogate into U+FFFD; so do we.
    body = "a\ud800b"
    good = _sign("a�b".encode(), 7)
    verify_webhook_signature(body, good, V["secret"], now=7)
    with pytest.raises(WebhookSignatureError) as ei:
        verify_webhook_signature(body, _sign(b"a?b", 7), V["secret"], now=7)
    assert ei.value.code == "bad_signature"


def test_empty_secret_rejected_even_when_signed_with_empty_key():
    body = b"{}"
    header = _sign(body, 1000)
    with pytest.raises(ValueError, match="non-empty"):
        verify_webhook_signature(body, header, "", now=1000)
    # a header signed with the empty key must not verify
    forged = "t=1000,v1=" + hmac.new(b"", b"1000." + body, hashlib.sha256).hexdigest()
    with pytest.raises(ValueError):
        verify_webhook_signature(body, forged, "", now=1000)
