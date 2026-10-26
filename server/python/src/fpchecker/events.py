"""Typed views of webhook events and eligibility answers.

Reasons and rule types are open strings: the server may add values, and an
unknown one never raises.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union


@dataclass(frozen=True)
class RuleAction:
    """What the project's ruleset decided. ``type``: allow | human_check | deny | none (open)."""

    type: str
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    ruleset_version: int = 0


@dataclass(frozen=True)
class WebhookEvent:
    """``rule_action`` and ``proxied`` are None when the payload lacks them (queued before server 0.45.0);
    ``rule_action_present`` tells a JSON null from a missing key."""

    visitor_id: str
    proxied: Optional[bool] = None
    rule_action: Optional[RuleAction] = None
    rule_action_present: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EligibilityAnswer:
    ok: bool
    eligible: Optional[bool] = None
    action: Optional[str] = None
    reason: Optional[str] = None
    rule_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


def _opt_str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _parse_rule_action(v: Any) -> Optional[RuleAction]:
    if not isinstance(v, dict) or not isinstance(v.get("type"), str):
        return None
    version = v.get("rulesetVersion")
    return RuleAction(
        type=v["type"],
        rule_id=_opt_str(v.get("ruleId")),
        rule_name=_opt_str(v.get("ruleName")),
        ruleset_version=version if isinstance(version, int) and not isinstance(version, bool) else 0,
    )


def parse_webhook_event(raw_body: Union[str, bytes]) -> WebhookEvent:
    """Parse a webhook body (verify its signature first)."""
    body = json.loads(raw_body)
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("visitorId"), str):
        raise ValueError("parse_webhook_event: not a webhook event")
    proxied = data.get("proxied")
    return WebhookEvent(
        visitor_id=data["visitorId"],
        proxied=proxied if isinstance(proxied, bool) else None,
        rule_action=_parse_rule_action(data.get("ruleAction")),
        rule_action_present="ruleAction" in data,
        raw=body,
    )


def parse_eligibility_answer(body: Any) -> EligibilityAnswer:
    """Narrow a ``check_eligibility`` response; ``rule_id`` is surfaced when present."""
    if not isinstance(body, dict):
        raise ValueError("parse_eligibility_answer: not an object")
    eligible = body.get("eligible")
    return EligibilityAnswer(
        ok=body.get("ok") is True,
        eligible=eligible if isinstance(eligible, bool) else None,
        action=_opt_str(body.get("action")),
        reason=_opt_str(body.get("reason")),
        rule_id=_opt_str(body.get("ruleId")),
        raw=body,
    )
