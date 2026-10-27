# Changelog

## Unreleased (tag with the next v0.4.0)

- `VerifyWebhookSignature` returns an error for an empty secret instead of verifying against an empty HMAC key.
- Add `Client.BotCheck(ctx, BotCheckRequest) (*BotCheckResult, error)` (`POST /v1/bot-check`) with the types `BotCheckRequest`, `BotCheckResult`, `BotSignal`, `BotInfo`, and the `BotCheckHeaders(http.Header)` helper that builds the forwardable header map (never Cookie or Authorization).
- `EventSignals` gains `Version` (1 or 2) and `Bot` (`BotSignal`): `Result` may be `good`, and v2 events carry `Info` (nil when no directory bot was named, always nil for version 1).
- Event search accepts the filters `bot_result`, `bot_category`, `bot_identity`, `bot_id`.
- `BotCheckHeaders` also keeps the headers named in the request's `signature-input` (never Cookie or Authorization), so signed agents verify.
- OpenAPI updated to fp-guard ba3762c (branch feat/bot-classification).

## 0.3.0

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
