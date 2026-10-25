import base64
import json
from pathlib import Path

import pytest

from fpchecker import SealedResultError, unseal_result

VECTORS = json.loads((Path(__file__).parents[3] / "test-vectors" / "sealed-result-v1.json").read_text())
CASES = VECTORS["cases"]


def test_vector_count_is_not_filtered():
    assert len(CASES) == 16


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_sealed_vector(case):
    keys = [VECTORS["keys"][k] for k in case["keys"]]
    expect = case["expect"]
    if "error" in expect:
        with pytest.raises(SealedResultError) as ei:
            unseal_result(case["blob"], keys)
        assert ei.value.code == expect["error"]
    else:
        assert unseal_result(case["blob"], keys) == expect


def test_error_codes_covered_by_vectors():
    codes = {c["expect"]["error"] for c in CASES if "error" in c["expect"]}
    assert codes == {"bad_format", "unknown_key", "decrypt_failed", "invalid_key", "unsupported_version"}


def test_invalid_key_checked_before_blob():
    with pytest.raises(SealedResultError) as ei:
        unseal_result("!!!", [VECTORS["keys"]["short"]])
    assert ei.value.code == "invalid_key"


@pytest.mark.parametrize("keys", [None, "abc", [None], [123], ["not base64!"]])
def test_non_list_or_bad_keys(keys):
    with pytest.raises(SealedResultError) as ei:
        unseal_result(CASES[0]["blob"], keys)
    assert ei.value.code == "invalid_key"


@pytest.mark.parametrize("blob", [None, 123, b"abc", ""])
def test_non_string_blob_is_bad_format(blob):
    with pytest.raises(SealedResultError) as ei:
        unseal_result(blob, [VECTORS["keys"]["a"]])
    assert ei.value.code == "bad_format"


def test_unicode_digits_not_base64():
    with pytest.raises(SealedResultError) as ei:
        unseal_result("Ａ" * 48, [VECTORS["keys"]["a"]])
    assert ei.value.code == "bad_format"


def test_error_message_has_no_key_material():
    with pytest.raises(SealedResultError) as ei:
        unseal_result(CASES[0]["blob"], [VECTORS["keys"]["b"]])
    assert VECTORS["keys"]["b"] not in str(ei.value)
    assert base64.b64decode(VECTORS["keys"]["b"]) not in str(ei.value).encode()


def _seal(payload: bytes, key_b64=VECTORS["keys"]["a"]):
    import hashlib
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = base64.b64decode(key_b64)
    head = b"fps1" + hashlib.sha256(key).digest()[:4]
    nonce = os.urandom(12)
    return base64.b64encode(head + nonce + AESGCM(key).encrypt(nonce, payload, head)).decode()


@pytest.mark.parametrize(
    "payload",
    [b'{"version":NaN}', b'{"version":1,"x":Infinity}', b'{"version":1,"x":-Infinity}', b"[" * 100000 + b"]" * 100000, b"\xff\xfe", b"", b'{"version":1,"x":"\xff"}'],
    ids=["nan", "inf", "neg_inf", "deep", "bad_utf8", "empty", "bad_utf8_in_string"],
)
def test_json_edge_cases_are_decrypt_failed(payload):
    with pytest.raises(SealedResultError) as ei:
        unseal_result(_seal(payload), [VECTORS["keys"]["a"]])
    assert ei.value.code == "decrypt_failed"


def test_seal_helper_positive_control():
    assert unseal_result(_seal(b'{"version":1,"x":2}'), [VECTORS["keys"]["a"]]) == {"version": 1, "x": 2}
