"""Typed views of webhook events and eligibility answers.

Reasons and rule types are open strings: the server may add values, and an
unknown one never raises.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, Union


@dataclass(frozen=True)
class RuleAction:
    """What the project's ruleset decided. ``type``: allow | human_check | deny | none (open)."""

    type: str
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    ruleset_version: int = 0


@dataclass(frozen=True)
class MobileSignals:
    """Device-state signals of an android, ios or macos event. Each flag is True (detected), False (checked,
    nothing found) or None (not checked: old SDK, probes switched off, unsupported platform). Not a guarantee
    either way. ``factory_reset_at`` is reserved and currently always None."""

    emulator: Optional[bool] = None
    attested: Optional[bool] = None
    integrity: Optional[str] = None
    rooted: Optional[bool] = None
    hooked: Optional[bool] = None
    debugger: Optional[bool] = None
    developer_mode: Optional[bool] = None
    mitm: Optional[bool] = None
    vpn: Optional[bool] = None
    location_spoofed: Optional[bool] = None
    cloned_app: Optional[bool] = None
    factory_reset_at: Optional[str] = None


@dataclass(frozen=True)
class BotInfo:
    """One entry of the Bot directory and how well the request matched it. ``category`` and ``identity`` are
    open strings: treat an unknown category as ``other``."""

    id: str
    name: str
    provider: str
    category: str
    identity: str


@dataclass(frozen=True)
class BotSignals:
    """``signals.bot``. ``result``: not_detected | good | bad (open; treat an unknown value as ``bad``), None when
    not checked. ``info`` is None for version 1 events (stored before server 0.48.0) and when the request did not
    name a directory bot."""

    result: Optional[str] = None
    types: Tuple[str, ...] = ()
    info: Optional[BotInfo] = None


@dataclass(frozen=True)
class WebhookEvent:
    """``rule_action`` and ``proxied`` are None when the payload lacks them (queued before server 0.45.0);
    ``rule_action_present`` tells a JSON null from a missing key."""

    visitor_id: str
    proxied: Optional[bool] = None
    rule_action: Optional[RuleAction] = None
    rule_action_present: bool = False
    mobile: Optional[MobileSignals] = None
    signals_version: Optional[int] = None
    bot: Optional[BotSignals] = None
    vpn_methods: Tuple[str, ...] = ()
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


def _tri(v: Any) -> Optional[bool]:
    return v if isinstance(v, bool) else None


def _parse_mobile(v: Any) -> Optional[MobileSignals]:
    if not isinstance(v, dict):
        return None
    integrity = v.get("integrity")
    return MobileSignals(
        emulator=_tri(v.get("emulator")),
        attested=_tri(v.get("attested")),
        integrity=integrity if integrity in ("strong", "basic", "failed") else None,
        rooted=_tri(v.get("rooted")),
        hooked=_tri(v.get("hooked")),
        debugger=_tri(v.get("debugger")),
        developer_mode=_tri(v.get("developerMode")),
        mitm=_tri(v.get("mitm")),
        vpn=_tri(v.get("vpn")),
        location_spoofed=_tri(v.get("locationSpoofed")),
        cloned_app=_tri(v.get("clonedApp")),
        factory_reset_at=_opt_str(v.get("factoryResetAt")),
    )


def _parse_vpn_methods(v: Any) -> Tuple[str, ...]:
    methods = v.get("methods") if isinstance(v, dict) else None
    return tuple(m for m in methods if isinstance(m, str)) if isinstance(methods, list) else ()


def _parse_bot(v: Any) -> Optional[BotSignals]:
    if not isinstance(v, dict):
        return None
    info = v.get("info")
    parsed = None
    if isinstance(info, dict) and isinstance(info.get("id"), str):
        parsed = BotInfo(
            id=info["id"],
            name=_opt_str(info.get("name")) or "",
            provider=_opt_str(info.get("provider")) or "",
            category=_opt_str(info.get("category")) or "other",
            identity=_opt_str(info.get("identity")) or "unknown",
        )
    types = v.get("types")
    return BotSignals(
        result=_opt_str(v.get("result")),
        types=tuple(t for t in types if isinstance(t, str)) if isinstance(types, list) else (),
        info=parsed,
    )


def parse_webhook_event(raw_body: Union[str, bytes]) -> WebhookEvent:
    """Parse a webhook body (verify its signature first)."""
    body = json.loads(raw_body)
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("visitorId"), str):
        raise ValueError("parse_webhook_event: not a webhook event")
    proxied = data.get("proxied")
    signals = data.get("signals") if isinstance(data.get("signals"), dict) else {}
    return WebhookEvent(
        visitor_id=data["visitorId"],
        proxied=proxied if isinstance(proxied, bool) else None,
        rule_action=_parse_rule_action(data.get("ruleAction")),
        rule_action_present="ruleAction" in data,
        mobile=_parse_mobile(signals.get("mobile")),
        signals_version=signals["version"] if type(signals.get("version")) is int and signals["version"] in (1, 2) else None,
        bot=_parse_bot(signals.get("bot")),
        vpn_methods=_parse_vpn_methods(signals.get("vpn")),
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
