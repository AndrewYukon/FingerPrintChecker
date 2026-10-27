# Changelog

## 0.1.0

- First release: `FpChecker` client with one method per OpenAPI `operationId` (camelCase), `Sealed::unsealResult`, `Webhook::verifyWebhookSignature`, `BotHeaders::filter` and typed `Events::parseWebhookEvent` / `Events::parseEligibilityAnswer`.
- Requires PHP 8.2 or newer with the curl, json and openssl extensions.
- Redirects are never followed; only GET requests retry.
- Invalid UTF-8 in `botCheck` headers or URL is substituted (U+FFFD) instead of throwing. An empty webhook secret throws `InvalidArgumentException`; a null signature header is `malformed_header`.
- Composer metadata carries `version` so the release zip installs from an `artifact` repository.
