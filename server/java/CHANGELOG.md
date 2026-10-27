# Changelog

## 0.1.0

- First release of the Java server SDK (`com.fpchecker:fpchecker-server-java`).
- `FpChecker` client with one method per OpenAPI `operationId`; redirects are never followed; only GET requests retry.
- `Sealed.unsealResult` decrypts the `sealedResult` blob of `/v2/identify`.
- `Webhook.verifyWebhookSignature` checks the `FPC-Signature` header (multiple `v1` values, time window, constant-time compare).
- `botCheck` and `BotHeaders.filter`, which builds the forwardable header map (never Cookie or Authorization).
- Typed views of webhook events and eligibility answers: `Events.parseWebhookEvent`, `Events.parseEligibilityAnswer`.
- An unchecked exception thrown by the JDK HTTP client surfaces as `FpCheckerApiException` with status 0 and code `network_error`.
- The timeout now bounds the whole call (headers and body). An empty webhook secret throws `IllegalArgumentException`. Adds a LICENSE file.
