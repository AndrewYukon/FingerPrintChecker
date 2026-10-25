import io
import json
import threading
import urllib.error
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest

from fpchecker import FpChecker, FpCheckerApiError

SPEC = json.loads((Path(__file__).parents[3] / "openapi" / "fpchecker-api.json").read_text())
SK = "sk_test_123"
PK = "pk_test_9"


class FakeResponse:
    def __init__(self, status, body, headers):
        self.status = status
        self._body = body
        self.headers = headers

    def read(self):
        return self._body

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def resp(status, body=None, headers=None):
    raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    msg = Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return (status, raw, msg)


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append(req)
        if not self.responses:
            raise AssertionError("no more responses")
        r = self.responses.pop(0)
        if isinstance(r, BaseException):
            raise r
        status, raw, msg = r
        if 200 <= status < 300:
            return FakeResponse(status, raw, msg)
        raise urllib.error.HTTPError(req.full_url, status, "x", msg, io.BytesIO(raw))


def mk(responses, **kw):
    opener = FakeOpener(responses)
    sleeps = []
    client = FpChecker(SK, opener=opener, sleep=sleeps.append, **kw)
    return client, opener.calls, sleeps


def hdr(req, name):
    return {k.lower(): v for k, v in req.header_items()}.get(name.lower())


# --- surface ---
def operations():
    ops = []
    for path, item in SPEC["paths"].items():
        for method, op in item.items():
            if isinstance(op, dict) and op.get("operationId"):
                params = [*(item.get("parameters", [])), *(op.get("parameters", []))]
                params = [_deref(p) for p in params]
                sec = [k for s in op.get("security", SPEC.get("security", [])) for k in s]
                ops.append((op["operationId"], method.upper(), path, params, "requestBody" in op, sec))
    return ops


def _deref(p):
    if "$ref" in p:
        o = SPEC
        for k in p["$ref"].split("/")[1:]:
            o = o[k]
        return o
    return p


def snake(name):
    out = ""
    for ch in name:
        out += ("_" + ch.lower()) if ch.isupper() else ch
    return out


OPS = operations()


def test_op_table_complete():
    assert len(OPS) == 17


def test_every_operation_id_has_method():
    client, _, _ = mk([])
    assert [snake(o[0]) for o in OPS if not callable(getattr(client, snake(o[0]), None))] == []


@pytest.mark.parametrize("op", OPS, ids=[o[0] for o in OPS])
def test_operation_table(op):
    op_id, method, path, params, has_body, sec = op
    client, calls, _ = mk([resp(200, {"ok": True})], publishable_key=PK)
    path_params = [p for p in params if p["in"] == "path"]
    query_params = [p for p in params if p["in"] == "query"]
    args = [f"id/{i} x" for i in range(len(path_params))]
    if has_body:
        args.append({"a": 1})
    elif query_params:
        args.append({"intent": "i"})
    assert getattr(client, snake(op_id))(*args) == {"ok": True}
    req = calls[0]
    expected = path
    for i, p in enumerate(path_params):
        expected = expected.replace("{" + p["name"] + "}", quote(f"id/{i} x", safe=""))
    assert urlsplit(req.full_url).path == expected
    assert req.get_method() == method
    assert (hdr(req, "X-Secret-Key") is not None) == ("secretKey" in sec)
    assert (hdr(req, "X-Publishable-Key") is not None) == ("publishableKey" in sec)
    if "secretKey" in sec:
        assert hdr(req, "X-Secret-Key") == SK
    if "publishableKey" in sec:
        assert hdr(req, "X-Publishable-Key") == PK
    assert "sk_test" not in req.full_url and "pk_test" not in req.full_url


def test_requires_secret_key():
    for bad in ("", None, 5):
        with pytest.raises(TypeError):
            FpChecker(bad)


def test_repr_and_str_hide_key():
    c = FpChecker(SK)
    assert SK not in repr(c) and SK not in str(c)
    assert PK not in repr(FpChecker(SK, publishable_key=PK))


# --- requests ---
def test_query_encoding_and_base_url():
    client, calls, _ = mk([resp(200, {})], base_url="https://x.test/")
    client.search_events({"visitorId": "v 1", "bot": True, "off": False, "limit": 5, "linkedId": None})
    assert calls[0].full_url == "https://x.test/v1/events?visitorId=v+1&bot=true&off=false&limit=5"


def test_path_param_encoded():
    client, calls, _ = mk([resp(200, {})])
    client.get_visitor("a/b")
    assert calls[0].full_url == "https://api.fpchecker.com/v1/visitors/a%2Fb"


def test_post_sends_json():
    client, calls, _ = mk([resp(200, {"ok": True})])
    client.check_eligibility({"visitorId": "v_1"})
    r = calls[0]
    assert r.get_method() == "POST"
    assert r.data == b'{"visitorId":"v_1"}'
    assert hdr(r, "Content-Type") == "application/json"


def test_secret_not_sent_on_publishable_ops_and_vice_versa():
    client, calls, _ = mk([resp(200, {}), resp(200, {})], publishable_key=PK)
    client.identify({})
    client.get_health()
    assert hdr(calls[0], "X-Secret-Key") is None and hdr(calls[0], "X-Publishable-Key") == PK
    assert hdr(calls[1], "X-Secret-Key") is None and hdr(calls[1], "X-Publishable-Key") is None


def test_publishable_ops_need_key():
    client, calls, _ = mk([])
    with pytest.raises(TypeError):
        client.identify({})
    with pytest.raises(TypeError):
        client.get_challenge({"intent": "i"})
    assert calls == []


def test_2xx_ok_false_returned_as_data():
    client, _, _ = mk([resp(200, {"ok": False, "reason": "quota_exhausted"})])
    assert client.check_quota({}) == {"ok": False, "reason": "quota_exhausted"}


def test_2xx_empty_or_non_json_is_empty_dict():
    client, _, _ = mk([resp(204), resp(200, b"<html>")])
    assert client.get_health() == {}
    assert client.get_health() == {}


# --- errors ---
def test_non_2xx_error_code():
    client, _, _ = mk([resp(403, {"ok": False, "error": "forbidden"})])
    with pytest.raises(FpCheckerApiError) as ei:
        client.get_event("e")
    e = ei.value
    assert (e.status, e.code, e.retry_after) == (403, "forbidden", None)
    assert e.body == {"ok": False, "error": "forbidden"}


def test_code_falls_back_to_reason_then_none():
    client, _, _ = mk([resp(400, {"ok": False, "reason": "bad_input"}), resp(502, b"<html>")])
    with pytest.raises(FpCheckerApiError) as a:
        client.update_event("e", {})
    assert a.value.code == "bad_input"
    with pytest.raises(FpCheckerApiError) as b:
        client.create_intent({})
    assert (b.value.status, b.value.code) == (502, None)


def test_error_never_contains_secret():
    client, _, _ = mk([resp(401, {"error": "bad_key"})])
    with pytest.raises(FpCheckerApiError) as ei:
        client.get_event("e")
    import traceback

    text = repr(ei.value) + str(ei.value) + "".join(traceback.format_exception(ei.value))
    assert SK not in text


# --- retries ---
def test_get_retried_on_503_with_retry_after():
    client, calls, sleeps = mk([resp(503, {"error": "u"}, {"Retry-After": "2"}), resp(200, {"ok": True})])
    assert client.get_visitor("v") == {"ok": True}
    assert len(calls) == 2 and sleeps == [2]


def test_get_gives_up_after_two_retries():
    client, calls, _ = mk([resp(500, {}), resp(500, {}), resp(429, {"error": "rate"}, {"Retry-After": "1"})])
    with pytest.raises(FpCheckerApiError) as ei:
        client.get_health()
    assert len(calls) == 3 and ei.value.status == 429 and ei.value.retry_after == 1


def test_retry_after_capped():
    client, _, sleeps = mk([resp(429, {}, {"Retry-After": "3600"}), resp(200, {})])
    client.get_status()
    assert sleeps[0] <= 10


def test_no_retry_on_other_4xx():
    client, calls, _ = mk([resp(404, {"error": "not_found"})])
    with pytest.raises(FpCheckerApiError):
        client.get_event("x")
    assert len(calls) == 1


@pytest.mark.parametrize("status", [429, 503])
def test_billed_post_never_retried(status):
    client, calls, _ = mk([resp(status, {"error": "x"}, {"Retry-After": "1"}), resp(200, {})])
    with pytest.raises(FpCheckerApiError):
        client.check_eligibility({"visitorId": "v"})
    assert len(calls) == 1


def test_patch_delete_never_retried():
    a, ac, _ = mk([resp(503, {}), resp(200, {})])
    with pytest.raises(FpCheckerApiError):
        a.update_event("e", {})
    b, bc, _ = mk([resp(503, {}), resp(200, {})])
    with pytest.raises(FpCheckerApiError):
        b.delete_visitor("v")
    assert len(ac) == 1 and len(bc) == 1


# --- network ---
def test_network_error_wrapped_with_cause():
    cause = urllib.error.URLError("refused")
    client, calls, _ = mk([cause])
    with pytest.raises(FpCheckerApiError) as ei:
        client.check_quota({})
    e = ei.value
    assert (e.status, e.code) == (0, "network_error")
    assert e.__cause__ is cause
    assert len(calls) == 1


@pytest.mark.parametrize(
    "exc", [TimeoutError("t"), urllib.error.URLError(TimeoutError("t")), __import__("socket").timeout("t")]
)
def test_timeouts_wrapped(exc):
    client, _, _ = mk([exc, exc, exc])
    with pytest.raises(FpCheckerApiError) as ei:
        client.get_health()
    assert (ei.value.status, ei.value.code) == (0, "timeout")
    assert ei.value.__cause__ is exc


def test_get_retries_network_failures_at_most_twice():
    client, calls, _ = mk([OSError("a"), OSError("b"), OSError("c"), resp(200, {})])
    with pytest.raises(FpCheckerApiError) as ei:
        client.get_visitor("v")
    assert len(calls) == 3 and ei.value.code == "network_error"
    ok, _, _ = mk([OSError("a"), resp(200, {"ok": True})])
    assert ok.get_visitor("v") == {"ok": True}


def test_non_get_never_retries_network_failures():
    for call in (
        lambda c: c.update_event("e", {}),
        lambda c: c.delete_visitor("v"),
        lambda c: c.check_eligibility({}),
    ):
        client, calls, _ = mk([OSError("x"), resp(200, {})])
        with pytest.raises(FpCheckerApiError):
            call(client)
        assert len(calls) == 1


# --- base_url ---
def test_base_url_validation():
    for bad in ("http://api.example.com", "not a url", "ftp://x.test", "https://", ""):
        with pytest.raises(ValueError):
            FpChecker("sk", base_url=bad)
    for ok in ("http://localhost:8787", "http://127.0.0.1:1", "http://[::1]:2", "https://x.test"):
        FpChecker("sk", base_url=ok)


# --- redirects (real sockets) ---
class _Server:
    def __init__(self, handler):
        self.httpd = HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.mark.parametrize("code", [301, 302, 307, 308])
def test_redirects_not_followed(code):
    seen = []

    class Target(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST

        def log_message(self, *a):
            pass

    target = _Server(Target)

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(code)
            self.send_header("Location", f"http://127.0.0.1:{target.port}/x")
            self.end_headers()

        do_GET = do_POST

        def log_message(self, *a):
            pass

    red = _Server(Redirector)
    try:
        for call in (lambda c: c.check_quota({}), lambda c: c.get_health()):
            client = FpChecker(SK, base_url=f"http://127.0.0.1:{red.port}", timeout=5, sleep=lambda s: None)
            with pytest.raises(FpCheckerApiError) as ei:
                call(client)
            assert ei.value.status == 0 and ei.value.code == "network_error"
        assert seen == []
    finally:
        red.close()
        target.close()


def test_real_roundtrip_sends_secret_header():
    got = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            got["h"] = dict(self.headers)
            got["path"] = self.path
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    s = _Server(H)
    try:
        c = FpChecker(SK, base_url=f"http://127.0.0.1:{s.port}")
        assert c.get_event("e 1") == {"ok": True}
        assert got["h"]["X-Secret-Key"] == SK and SK not in got["path"]
        assert got["path"] == "/v1/events/e%201"
    finally:
        s.close()
