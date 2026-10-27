# Changelog

## 0.1.0

- First release: `FpChecker` client with one async method per OpenAPI `operationId`, `Sealed.UnsealResult`, `Webhook.VerifyWebhookSignature`, `BotHeaders.Filter` and typed `Events.ParseWebhookEvent` / `Events.ParseEligibilityAnswer`.
- Targets .NET 8.
- Redirects are never followed; only GET requests retry.
- An empty webhook secret throws `ArgumentException`. `FpCheckerOptions.SecretKey` is written as `[redacted]` by `System.Text.Json`.
