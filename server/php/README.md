# fpchecker-php

Server SDK for [FingerPrintChecker](https://fpchecker.com). PHP 8.2+ with the `curl`, `json` and `openssl` extensions; no other runtime dependency.

The package is not on Packagist yet. Download `fpchecker-php-0.1.0.zip` from the GitHub release into a directory (`vendor-packages/` below; any path works) and install it through a Composer `artifact` repository, then run `composer install`. The zip's `composer.json` carries `"version": "0.1.0"`, which Composer requires for artifact repositories. For an unpacked copy use a `path` repository instead.

```json
{
    "repositories": [
        { "type": "artifact", "url": "vendor-packages/" }
    ],
    "require": {
        "fpchecker/fpchecker-php": "0.1.0"
    }
}
```

```php
use FpChecker\FpChecker;
use FpChecker\FpCheckerApiError;

$fp = new FpChecker(getenv('FPCHECKER_SECRET_KEY') ?: throw new \RuntimeException('FPCHECKER_SECRET_KEY is not set'));
$verdict = $fp->checkEligibility(['visitorId' => 'v_...']);
if (($verdict['ok'] ?? null) === false) {
    echo 'refused: ', $verdict['error'] ?? $verdict['reason'] ?? 'unknown', "\n";
}
```

## Client

`new FpChecker(string $secretKey, ?string $publishableKey = null, string $baseUrl = 'https://api.fpchecker.com', int|float $timeout = 10)` has one method per OpenAPI `operationId`, in camelCase: `createIntent`, `getChallenge`, `identify`, `botCheck`, `checkEligibility`, `releaseEligibility`, `checkQuota`, `bindSubject`, `relateSubjects`, `sendFeedback`, `getClaimFlags`, `searchEvents`, `getEvent`, `updateEvent`, `getVisitor`, `deleteVisitor`, `getHealth`, `getStatus`. Bodies and query parameters are plain arrays; responses are arrays.

- The secret key goes in the `X-Secret-Key` header, never in a URL, and is kept out of accidental logs and dumps (`var_dump`, `print_r`, `var_export`, exception traces show only a masked form). This masking is not encryption: code that can read the object's memory can recover the key. `getChallenge` and `identify` use the publishable key in `X-Publishable-Key` instead; `getHealth` and `getStatus` send no key.
- 2xx responses are returned as data, **including** refusals such as `['ok' => false, 'error' => ...]`. Check `ok`.
- Non-2xx throws `FpCheckerApiError` with `status()`, `code()` (`error` or `reason` from the body), `retryAfter()` (seconds) and `body()`.
- Network failures and timeouts also throw `FpCheckerApiError`, with status 0 and code `network_error` or `timeout`.
- Redirects are never followed (they would forward the secret key to another origin). `baseUrl` must be https, except localhost, 127.0.0.1 and [::1] (otherwise `InvalidArgumentException`).
- `timeout` must be a positive finite number (int or float, in seconds); anything else throws `InvalidArgumentException`.
- Only GET requests retry (429, 5xx, network failures and timeouts; at most 2 retries, honouring `Retry-After`, wait capped at 10 s). POST, PATCH and DELETE are never retried.

## Verifying an eventId

When the browser reports an `eventId`, fetch the event from your server and check it before trusting anything. Do not accept the browser's own claims about the visitor.

```php
use FpChecker\FpChecker;

/** Your own store; `markUsed` returns false when the id was seen before (database unique key, Redis SET NX). */
interface UsedEvents
{
    public function markUsed(string $eventId): bool;
}

function verifyEvent(FpChecker $fp, string $eventId, UsedEvents $used): array
{
    // 1. Shape: ev_ followed by 20 Crockford base32 characters.
    if (preg_match('/\Aev_[0-9A-HJKMNP-TV-Z]{20}\z/', $eventId) !== 1) {
        throw new \RuntimeException('bad event id');
    }
    $event = $fp->getEvent($eventId);
    // 2. The event the server returns must be the one you asked for.
    if (($event['eventId'] ?? null) !== $eventId) {
        throw new \RuntimeException('event id mismatch');
    }
    // 3. Fresh: created within the last 5 minutes. An unparseable createdAt fails closed.
    // createdAt looks like 2026-10-27T12:00:00Z or 2026-10-27T12:00:00.123Z; anything else is refused.
    $created = null;
    foreach (['!Y-m-d\TH:i:sp', '!Y-m-d\TH:i:s.vp'] as $format) {
        $created ??= \DateTimeImmutable::createFromFormat($format, is_string($event['createdAt'] ?? null) ? $event['createdAt'] : '') ?: null;
    }
    if ($created === null || abs(time() - $created->getTimestamp()) > 300) {
        throw new \RuntimeException('event too old or unreadable');
    }
    // 4. Single use: an event id is accepted once.
    if (!$used->markUsed($eventId)) {
        throw new \RuntimeException('event already used');
    }
    return $event;
}
```

## Bot check

`botCheck(string $method, string $url, string $ip, array $headers)` classifies a request your backend received (header-only: no script ran in the sender). It is not charged and writes no event. Forward the original URL (the host and scheme the visitor used, not your origin behind a CDN or load balancer) and the client IP. `botCheck` passes `$headers` through `BotHeaders::filter` itself: only the headers the check needs are sent, and Cookie and Authorization never leave your process.

```php
use FpChecker\FpChecker;
use FpChecker\FpCheckerApiError;

$fp = new FpChecker(getenv('FPCHECKER_SECRET_KEY') ?: throw new \RuntimeException('FPCHECKER_SECRET_KEY is not set'));

try {
    $verdict = $fp->botCheck(
        $_SERVER['REQUEST_METHOD'],
        'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], // the host the visitor used
        $_SERVER['REMOTE_ADDR'],                                      // the trusted client IP
        getallheaders(),
    );
} catch (FpCheckerApiError) {
    $verdict = null; // fail open: an outage of the check must not take your site down
}
if ($verdict !== null && ($verdict['bot']['result'] ?? null) === 'bad') {
    http_response_code(403);
    exit;
}
```

`bot.result` is `good`, `bad` or `not_detected`; `bot.info` (`id`, `name`, `provider`, `category`, `identity`) is set when the request named a directory bot. A 400 throws `FpCheckerApiError` with code `invalid_request` or `invalid_ip` and the offending `field` in `body()`.

Rules of use:
- Call `botCheck` once per request and reuse the answer.
- Never retry a signed request: a retry replays the signature nonce and the request is then judged `spoofed` (`bad`).
- `ip` must be the trusted client IP, not an address a client can set.
- Limits: 3,000 checks per minute per client IP and 1,200 per minute per project (429 beyond that).
- `BotHeaders::filter` also keeps any header named in the request's `signature-input`, so signed agents verify.

`Events::parseWebhookEvent` returns `signalsVersion` (1 before server 0.48.0, 2 since) and `bot` (`BotSignals`: `result` may be `good`, `types`, `info` as `BotInfo` or null). `searchEvents` also filters by `bot_result`, `bot_category`, `bot_identity` and `bot_id`.

## Sealed results

```php
use FpChecker\Sealed;
use FpChecker\SealedResultError;

try {
    $result = Sealed::unsealResult($identifyResponse['sealedResult'], [getenv('FPC_SEALED_KEY') ?: throw new \RuntimeException('FPC_SEALED_KEY is not set')]);
} catch (SealedResultError $e) {
    // $e->code(): bad_format | unknown_key | decrypt_failed | invalid_key | unsupported_version
}
```

Pass every active key (active and previous during rotation); any iterable of base64 32-byte keys works.

## Webhooks

```php
use FpChecker\Events;
use FpChecker\Webhook;
use FpChecker\WebhookSignatureError;

$secret = getenv('FPC_WEBHOOK_SECRET');
if ($secret === false || $secret === '') {
    throw new \RuntimeException('FPC_WEBHOOK_SECRET is not set'); // fail closed: never verify against an empty secret
}
$rawBody = file_get_contents('php://input'); // the exact bytes received, not a re-serialised object
try {
    Webhook::verifyWebhookSignature($rawBody, $_SERVER['HTTP_FPC_SIGNATURE'] ?? null, $secret);
} catch (WebhookSignatureError $e) {
    http_response_code(400); // $e->code(): malformed_header | bad_signature | expired | future
    exit;
}
$event = Events::parseWebhookEvent($rawBody);
echo $event->visitorId, ' ', $event->ruleAction?->type ?? 'none';
```

An empty secret throws `InvalidArgumentException`, and a missing header (`null`) is `malformed_header`. `toleranceSec` (default 300) must be a finite number >= 0, else `InvalidArgumentException`. `Events::parseEligibilityAnswer($verdict)` narrows a `checkEligibility` response the same way. Reasons and rule types are open strings: an unknown value never throws.

## License

Apache-2.0
