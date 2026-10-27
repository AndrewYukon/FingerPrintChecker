# @fingerprintchecker/node

Server SDK for [FingerPrintChecker](https://fpchecker.com). Zero runtime dependencies (built-in `fetch` and `node:crypto`), Node 18+, ESM and CommonJS.

```ts
import { FpChecker, unsealResult, verifyWebhookSignature, FpCheckerApiError } from '@fingerprintchecker/node';

const fp = new FpChecker({ secretKey: process.env.FPCHECKER_SECRET_KEY! });

const verdict = await fp.checkEligibility({ visitorId: 'v_…' });
if (verdict.ok === false) console.log('refused:', verdict.error ?? verdict.reason);
```

## Client

One async method per OpenAPI `operationId`: `createIntent`, `getChallenge`, `identify`, `botCheck`, `checkEligibility`, `releaseEligibility`, `checkQuota`, `bindSubject`, `relateSubjects`, `sendFeedback`, `getClaimFlags`, `searchEvents`, `getEvent`, `updateEvent`, `getVisitor`, `deleteVisitor`, `getHealth`, `getStatus`.

- The secret key goes in the `X-Secret-Key` header, never in a URL. `getChallenge` and `identify` use the publishable key (`publishableKey` option).
- 2xx responses are returned as data, **including** refusals such as `{ ok: false, error }`. Check `ok`.
- Non-2xx throws `FpCheckerApiError` with `status`, `code` (`error ?? reason` from the body) and `retryAfter` (seconds).
- Network failures and timeouts also throw `FpCheckerApiError`, with `status` 0, `code` `network_error` or `timeout`, and the original error as `cause`.
- Redirects are never followed (they would forward the secret key to another origin). `baseUrl` must be https, except localhost, 127.0.0.1 and [::1].
- Only GET requests retry (including after network failures and timeouts) (429 and 5xx, at most 2 retries, honouring `Retry-After`, wait capped at 10 s). POST, PATCH and DELETE are never retried.

## Bot check

`botCheck` classifies a request your backend received (header-only: no script ran in the sender). It is not charged and writes no event. Forward the original URL (the host and scheme the visitor used, not your origin behind a CDN or load balancer) and the client IP. `botCheckHeaders` keeps only the headers the check needs and drops Cookie, Authorization and everything else.

```ts
import express from 'express';
import { FpChecker, botCheckHeaders } from '@fingerprintchecker/node';

const fp = new FpChecker({ secretKey: process.env.FPCHECKER_SECRET_KEY! });
const app = express();
app.set('trust proxy', true); // so req.ip is the client, not your load balancer

app.use(async (req, res, next) => {
  const verdict = await fp.botCheck({
    method: req.method,
    url: `${req.protocol}://${req.get('host')}${req.originalUrl}`, // original host and scheme
    ip: req.ip!,
    headers: botCheckHeaders(req.headers),
  });
  if (verdict.bot.result === 'bad') return res.status(403).end();
  next(); // 'good' = a verified or signed directory bot; verdict.bot.info says which
});
```

`bot.result` is `good`, `bad` or `not_detected`; `bot.info` (`id`, `name`, `provider`, `category`, `identity`) is set when the request named a directory bot. A 400 throws `FpCheckerApiError` with `code` `invalid_request` or `invalid_ip` and the offending `field` in `body`.

Event signals come in two versions: `signals.version` 1 (before server 0.48.0, no `good`, no `bot.info`) and 2. `searchEvents` also filters by `botResult`, `botCategory`, `botIdentity` and `botId`.

## Sealed results

```ts
const result = unsealResult(identifyResponse.sealedResult, [process.env.FPC_SEALED_KEY!]);
```

Pass every active key (active and previous during rotation). Throws `SealedResultError` with `code` of `bad_format`, `unknown_key`, `decrypt_failed`, `invalid_key` or `unsupported_version`.

## Webhooks

```ts
// rawBody must be the exact bytes received, not a re-serialised object.
verifyWebhookSignature({ rawBody, header: req.headers['fpc-signature'] as string, secret: process.env.FPC_WEBHOOK_SECRET! });
```

Throws `WebhookSignatureError` with `code` of `malformed_header`, `bad_signature`, `expired` or `future` (default tolerance 300 s; `toleranceSec` must be a finite number >= 0 or a TypeError is thrown).

## License

Apache-2.0
