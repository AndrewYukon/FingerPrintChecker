import json
from pathlib import Path

import pytest

from fpchecker import parse_eligibility_answer, parse_webhook_event, verify_webhook_signature

V = json.loads((Path(__file__).parents[3] / "test-vectors" / "webhook-signature.json").read_text())


def _ev(**data):
    return json.dumps({"id": "evt_1", "type": "identify", "data": {"visitorId": "v_1", **data}})


def test_ok_rule_action_vector_verifies_and_parses():
    c = next(x for x in V["cases"] if x["name"] == "ok_rule_action")
    verify_webhook_signature(c["body"].encode(), c["header"], V["secret"], now=c["now"])
    e = parse_webhook_event(c["body"])
    assert e.proxied is True
    ra = e.rule_action
    assert (ra.type, ra.rule_id, ra.rule_name, ra.ruleset_version) == ("deny", "r_0a1b2c3d", "Block hosting", 3)


@pytest.mark.parametrize("t", ["allow", "human_check", "deny", "none"])
def test_rule_action_types(t):
    e = parse_webhook_event(_ev(ruleAction={"type": t, "rulesetVersion": 1}, proxied=False))
    assert e.rule_action.type == t and e.rule_action.rule_id is None
    assert e.proxied is False


def test_null_and_missing_rule_action():
    n = parse_webhook_event(_ev(ruleAction=None))
    assert n.rule_action is None and n.rule_action_present is True
    old = parse_webhook_event(_ev())
    assert old.rule_action is None and old.rule_action_present is False and old.proxied is None


def test_unknown_rule_type_does_not_raise():
    assert parse_webhook_event(_ev(ruleAction={"type": "captcha", "rulesetVersion": 2})).rule_action.type == "captcha"


def test_rejects_non_event():
    with pytest.raises(ValueError):
        parse_webhook_event('{"a":1}')


def test_eligibility_rule_id():
    a = parse_eligibility_answer({"ok": True, "eligible": False, "action": "deny", "reason": "rule_deny", "ruleId": "r_1"})
    assert a.rule_id == "r_1" and a.reason == "rule_deny" and a.eligible is False
    assert parse_eligibility_answer({"ok": True, "eligible": True, "reason": "brand_new"}).rule_id is None


def test_ok_mobile_signals_vector_verifies_and_parses():
    c = next(x for x in V["cases"] if x["name"] == "ok_mobile_signals")
    verify_webhook_signature(c["body"].encode(), c["header"], V["secret"], now=c["now"])
    e = parse_webhook_event(c["body"])
    m = e.mobile
    assert (m.rooted, m.hooked, m.developer_mode, m.vpn, m.location_spoofed, m.factory_reset_at) == (
        True, False, True, True, None, None)
    assert "os_vpn" in e.vpn_methods


def test_old_payload_new_fields_are_none():
    m = parse_webhook_event(_ev(signals={"mobile": {"emulator": False, "attested": True, "integrity": "strong"}})).mobile
    assert m.rooted is None and m.cloned_app is None and m.factory_reset_at is None
    assert parse_webhook_event(_ev(signals={"mobile": None})).mobile is None
    e = parse_webhook_event(_ev())
    assert e.mobile is None and e.vpn_methods == ()


def test_non_boolean_reads_as_none_and_unknown_vpn_method_kept():
    e = parse_webhook_event(_ev(signals={"vpn": {"result": True, "methods": ["os_vpn", "future"]},
                                         "mobile": {"rooted": "yes", "factoryResetAt": 5}}))
    assert e.mobile.rooted is None and e.mobile.factory_reset_at is None
    assert e.vpn_methods == ("os_vpn", "future")
