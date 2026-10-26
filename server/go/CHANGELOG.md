# Changelog

## Unreleased (tag with the next v0.2.0)

- Add `ParseWebhookEvent` and `ParseEligibilityAnswer` with the types `WebhookEvent`, `RuleAction` and `EligibilityAnswer`.
- Events carry `ruleAction` (nullable) and `proxied`; both are optional because older webhook payloads lack them.
- Eligibility answers surface the optional `ruleId`. Reasons and rule types are open strings: an unknown value never throws.
- Test vectors and OpenAPI updated to fp-guard d8d326d (new webhook vector `ok_rule_action`).

## 0.1.0

- First release.
