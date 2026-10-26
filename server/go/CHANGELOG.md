# Changelog

## Unreleased (tag with the next v0.3.0)

- Add typed mobile device-state signals: `signals.mobile` gains `rooted`, `hooked`, `debugger`, `developerMode`, `mitm`, `vpn`, `locationSpoofed`, `clonedApp` (true / false / null) and `factoryResetAt` (reserved, currently always null).
- `vpn.methods` may now contain `os_vpn` (the device reports an active VPN); unknown methods never throw.
- Event search accepts the filters `rooted`, `hooked`, `emulator`, `mitm`, `locationSpoofed`, `clonedApp`.
- Test vectors and OpenAPI updated to fp-guard 2065ee2 (new webhook vector `ok_mobile_signals`).
- Pairs with the Android and Apple SDKs 0.7.0; the results reach your server through the events API and webhooks only.

## 0.2.0

- Add `ParseWebhookEvent` and `ParseEligibilityAnswer` with the types `WebhookEvent`, `RuleAction` and `EligibilityAnswer`.
- Events carry `ruleAction` (nullable) and `proxied`; both are optional because older webhook payloads lack them.
- Eligibility answers surface the optional `ruleId`. Reasons and rule types are open strings: an unknown value never throws.
- Test vectors and OpenAPI updated to fp-guard d8d326d (new webhook vector `ok_rule_action`).

## 0.1.0

- First release.
