# fpchecker-server-java

Server SDK for [FingerPrintChecker](https://fpchecker.com). Java 11+, JDK `HttpClient` for HTTP, one runtime dependency (Jackson, for JSON). Requests and responses are Jackson `JsonNode` trees.

## Install

Maven:

```xml
<dependency>
  <groupId>com.fpchecker</groupId>
  <artifactId>fpchecker-server-java</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("com.fpchecker:fpchecker-server-java:0.1.0")
```

## Quick start

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fpchecker.server.FpChecker;
import java.util.Map;

FpChecker fp = new FpChecker(System.getenv("FPCHECKER_SECRET_KEY"));
JsonNode verdict = fp.checkEligibility(Map.of("visitorId", "v_..."));
if (verdict.path("ok").asBoolean(true) == false) {
    System.out.println("refused: " + verdict.path("error").asText(verdict.path("reason").asText()));
}
```

## Client

`new FpChecker(secretKey)` or `FpChecker.builder(secretKey).publishableKey(...).baseUrl(...).timeout(Duration)...build()` (defaults: `https://api.fpchecker.com`, 10 s). The client has one method per OpenAPI `operationId`: `createIntent`, `getChallenge`, `identify`, `botCheck`, `checkEligibility`, `releaseEligibility`, `checkQuota`, `bindSubject`, `relateSubjects`, `sendFeedback`, `getClaimFlags`, `searchEvents`, `getEvent`, `updateEvent`, `getVisitor`, `deleteVisitor`, `getHealth`, `getStatus`. Request bodies are any object Jackson can serialise (a `Map`, a POJO, a `JsonNode`); query parameters are a `Map`; responses are `JsonNode`.

- The secret key goes in the `X-Secret-Key` header, never in a URL, and is not shown by `toString()`. `getChallenge` and `identify` use the publishable key in `X-Publishable-Key` instead; `getHealth` and `getStatus` send no key.
- 2xx responses are returned as data, **including** refusals such as `{"ok": false, "error": ...}`. Check `ok`. A 2xx response whose body is not JSON (a proxy error page) returns an empty object.
- Non-2xx throws `FpCheckerApiException` (unchecked) with `status()`, `code()` (`error` or `reason` from the body), `retryAfter()` (seconds) and `body()`.
- Network failures and timeouts also throw `FpCheckerApiException`, with `status()` 0 and `code()` `"network_error"` or `"timeout"`.
- Redirects are never followed (they would forward the secret key to another origin); a 3xx is reported as `network_error`. `baseUrl` must be https, except localhost, 127.0.0.1 and [::1] (otherwise `IllegalArgumentException`).
- Only GET requests retry (429, 5xx, network failures and timeouts; at most 2 retries, honouring `Retry-After`, wait capped at 10 s). POST, PATCH and DELETE are never retried.

## Verifying an identification

The browser sends your backend an `eventId`. Do not trust it: fetch the event with your secret key and check it.

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fpchecker.server.FpChecker;
import com.fpchecker.server.FpCheckerApiException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

static final Pattern EVENT_ID = Pattern.compile("^ev_[0-9A-HJKMNP-TV-Z]{20}$");
static final Set<String> used = ConcurrentHashMap.newKeySet(); // use a shared store with expiry in production

static boolean verifyEvent(FpChecker fp, String eventId) {
    if (eventId == null || !EVENT_ID.matcher(eventId).matches()) {
        return false;
    }
    JsonNode event;
    try {
        event = fp.getEvent(eventId);
    } catch (FpCheckerApiException e) {
        return false; // unknown event or an outage: do not accept
    }
    if (!eventId.equals(event.path("eventId").asText(null))) {
        return false; // the response must be for the event you asked about
    }
    try {
        Instant created = Instant.parse(event.path("createdAt").asText(""));
        long ageMs = Duration.between(created, Instant.now()).toMillis();
        if (Math.abs(ageMs) > Duration.ofMinutes(5).toMillis()) {
            return false; // too old (or from the future)
        }
    } catch (java.time.format.DateTimeParseException e) {
        return false; // missing or unparseable createdAt fails closed
    }
    return used.add(eventId); // each eventId counts once
}
```

## Bot check

`botCheck(method, url, ip, headers)` classifies a request your backend received (header-only: no script ran in the sender). It is not charged and writes no event. Forward the original URL (the host and scheme the visitor used, not your origin behind a CDN or load balancer) and the client IP. `botCheck` passes `headers` through `BotHeaders.filter`, which keeps only the headers the check needs and drops Cookie, Authorization and everything else.

```java
// `request`, `originalUrl`, `clientIp`, `headersAsMap`, `chain` and `forbidden()` are placeholders
// for your web framework (servlet filter, Spring interceptor, ...); they are not part of this SDK.
JsonNode verdict;
try {
    verdict = fp.botCheck(request.getMethod(), originalUrl, clientIp, headersAsMap(request));
} catch (FpCheckerApiException e) {
    return chain.next(request); // fail open: an outage of the check must not take your site down
}
if ("bad".equals(verdict.path("bot").path("result").asText())) {
    return forbidden();
}
```

`bot.result` is `good`, `bad` or `not_detected`; `bot.info` (`id`, `name`, `provider`, `category`, `identity`) is set when the request named a directory bot. A 400 throws `FpCheckerApiException` with `code()` `invalid_request` or `invalid_ip` and the offending `field` in `body()`.

Rules of use:
- Call `botCheck` once per request and reuse the answer; do not call it again for the same request.
- Never retry a signed request: a retry replays the signature nonce and the request is then judged `spoofed` (`bad`).
- `ip` must be the trusted client IP, not an address a client can set.
- Limits: 3,000 checks per minute per client IP and 1,200 per minute per project (429 beyond that).
- `BotHeaders.filter` also forwards any header named in the request's `signature-input`, so signed agents verify; Cookie and Authorization are never forwarded.

`Events.parseWebhookEvent` returns `signalsVersion` (1 before server 0.48.0, 2 since) and `bot` (`BotSignals`: `result` may be `good`, `types`, `info` as `BotInfo` or null). `searchEvents` also filters by `bot_result`, `bot_category`, `bot_identity` and `bot_id`.

## Sealed results

```java
JsonNode result = Sealed.unsealResult(identifyResponse.path("sealedResult").asText(), List.of(System.getenv("FPC_SEALED_KEY")));
```

Pass every active key (active and previous during rotation). Throws `SealedResultException` with `code()` of `bad_format`, `unknown_key`, `decrypt_failed`, `invalid_key` or `unsupported_version`.

## Webhooks

```java
import com.fpchecker.server.Webhook;
import com.fpchecker.server.events.Events;
import com.fpchecker.server.events.WebhookEvent;
import java.nio.charset.StandardCharsets;

// `request` and `rawBody` (byte[]) come from your web framework. rawBody must be the exact bytes
// received, not a re-serialised object.
Webhook.verifyWebhookSignature(rawBody, request.getHeader("FPC-Signature"), System.getenv("FPC_WEBHOOK_SECRET"));
WebhookEvent event = Events.parseWebhookEvent(new String(rawBody, StandardCharsets.UTF_8)); // only after verifying
```

Throws `WebhookSignatureException` with `code()` of `malformed_header`, `bad_signature`, `expired` or `future`. `toleranceSec` (default 300) must be >= 0, else `IllegalArgumentException`. The full signature is `verifyWebhookSignature(rawBody, header, secret, toleranceSec, now)`, where `now` is a `Long` of unix seconds or null for the system clock.

`Events.parseWebhookEvent` and `Events.parseEligibilityAnswer` return immutable typed views (`WebhookEvent`, `RuleAction`, `MobileSignals`, `BotSignals`, `BotInfo`, `EligibilityAnswer`). Reasons and rule types are open strings: an unknown value never throws.

## License

Apache-2.0
