import json

import pytest

from fpchecker import FpChecker, FpCheckerApiError, bot_check_headers, parse_webhook_event
from test_client import FakeOpener, hdr, resp

VERDICT = {
    "bot": {
        "result": "good",
        "types": [],
        "info": {"id": "googlebot", "name": "Googlebot", "provider": "Google", "category": "search_crawler", "identity": "verified"},
    },
    "ip": {"country": "US", "asn": 15169, "asName": "Google LLC", "datacenter": True, "tor": False, "relay": False,
           "blocklist": {"result": False, "sources": []}},
    "vpn": {"result": False, "methods": []},
    "proxy": {"result": False, "type": None},
}
REQ = dict(method="GET", url="https://shop.example/pricing", ip="66.249.66.1", headers={"user-agent": "Googlebot/2.1"})


def mk(responses):
    opener = FakeOpener(responses)
    return FpChecker("sk_test_123", opener=opener, sleep=lambda s: None), opener.calls


def test_bot_check_posts_body_and_parses_verdict():
    client, calls = mk([resp(200, VERDICT)])
    out = client.bot_check(**REQ)
    req = calls[0]
    assert req.full_url == "https://api.fpchecker.com/v1/bot-check"
    assert req.get_method() == "POST"
    assert json.loads(req.data) == REQ
    assert hdr(req, "X-Secret-Key") == "sk_test_123"
    assert out["bot"]["result"] == "good"
    assert out["bot"]["info"]["identity"] == "verified"


def test_bot_check_is_keyword_only():
    client, _ = mk([])
    with pytest.raises(TypeError):
        client.bot_check("GET", "https://x.test/", "1.1.1.1", {})  # type: ignore[misc]


def test_bot_check_400_carries_error_and_field():
    client, _ = mk([resp(400, {"ok": False, "error": "invalid_ip", "field": "ip"})])
    with pytest.raises(FpCheckerApiError) as e:
        client.bot_check(**REQ)
    assert e.value.status == 400 and e.value.code == "invalid_ip"
    assert e.value.body["field"] == "ip"


@pytest.mark.parametrize("status", [401, 429])
def test_bot_check_401_429_raise_without_retry(status):
    client, calls = mk([resp(status, {"ok": False, "error": "x"}), resp(200, VERDICT)])
    with pytest.raises(FpCheckerApiError) as e:
        client.bot_check(**REQ)
    assert e.value.status == status
    assert len(calls) == 1


def test_header_helper_keeps_allowed_set_and_drops_cookie_authorization():
    allowed = {
        "User-Agent": "UA", "Accept": "text/html", "Accept-Language": "en", "Accept-Encoding": "gzip",
        "Sec-CH-UA": '"x"', "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"macOS"',
        "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
        "Signature": "sig1=:a:", "Signature-Input": "sig1=()", "Signature-Agent": '"https://chatgpt.com"',
        "Upgrade-Insecure-Requests": "1",
    }
    out = bot_check_headers({**allowed, "Cookie": "sid=1", "Authorization": "Bearer x", "X-Forwarded-For": "1.1.1.1"})
    assert out == {k.lower(): v for k, v in allowed.items()}


def test_header_helper_handles_repeated_pairs():
    class Pairs:
        def items(self):
            return [("Accept", "a"), ("accept", "b"), ("Cookie", "c")]

    assert bot_check_headers(Pairs()) == {"accept": "a, b"}


def _ev(signals):
    return json.dumps({"id": "e", "type": "identify", "data": {"visitorId": "v_1", "signals": signals}})


def test_v1_event_parses_without_info():
    e = parse_webhook_event(_ev({"version": 1, "bot": {"result": "bad", "types": ["webdriver"]}}))
    assert e.signals_version == 1
    assert (e.bot.result, e.bot.types, e.bot.info) == ("bad", ("webdriver",), None)


def test_v2_event_parses_good_and_info():
    info = {"id": "googlebot", "name": "Googlebot", "provider": "Google", "category": "search_crawler", "identity": "verified"}
    e = parse_webhook_event(_ev({"version": 2, "bot": {"result": "good", "types": [], "info": info}}))
    assert e.signals_version == 2 and e.bot.result == "good"
    assert (e.bot.info.id, e.bot.info.category, e.bot.info.identity) == ("googlebot", "search_crawler", "verified")
    assert parse_webhook_event(_ev({"version": 2, "bot": {"result": "not_detected", "types": [], "info": None}})).bot.info is None


def test_event_without_signals_has_no_bot():
    e = parse_webhook_event(json.dumps({"data": {"visitorId": "v_1"}}))
    assert e.bot is None and e.signals_version is None


def test_search_events_passes_bot_filters_as_query():
    client, calls = mk([resp(200, {"ok": True})])
    client.search_events({"bot_result": "good", "bot_category": "ai_crawler", "bot_identity": "signed", "bot_id": "googlebot"})
    assert calls[0].full_url.endswith("/v1/events?bot_result=good&bot_category=ai_crawler&bot_identity=signed&bot_id=googlebot")


SIG_INPUT = 'sig1=("@authority" "content-type" "X-Custom" "cookie" "signature-agent");created=1;keyid="k";tag="web-bot-auth"'


def test_header_helper_keeps_signature_input_covered_components():
    out = bot_check_headers({
        "Signature-Input": SIG_INPUT, "Signature-Agent": '"https://chatgpt.com"', "Content-Type": "text/plain",
        "X-Custom": "v", "X-Other": "no", "Cookie": "sid=1", "Authorization": "x",
    })
    assert out["content-type"] == "text/plain" and out["x-custom"] == "v"
    assert "x-other" not in out and "cookie" not in out and "authorization" not in out


def test_header_helper_no_extras_without_signature_input():
    assert bot_check_headers({"content-type": "x", "user-agent": "u"}) == {"user-agent": "u"}
