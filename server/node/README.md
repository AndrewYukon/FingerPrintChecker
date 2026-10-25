# @fpchecker/node

Server SDK for [FingerPrintChecker](https://fpchecker.com). Zero runtime dependencies (built-in `fetch` and `node:crypto`), Node 18+, ESM and CommonJS.

```ts
import { FpChecker, unsealResult, verifyWebhookSignature, FpCheckerApiError } from '@fpchecker/node';

const fp = new FpChecker({ secretKey: process.env.FPCHECKER_SECRET_KEY! });

const verdict = await fp.checkEligibility({ visitorId: 'v_…' });
if (verdict.ok === false) console.log('refused:', verdict.error ?? verdict.reason);
```

## Client

One async method per OpenAPI `operationId`: `createIntent`, `getChallenge`, `identify`, `checkEligibility`, `releaseEligibility`, `checkQuota`, `bindSubject`, `relateSubjects`, `sendFeedback`, `getClaimFlags`, `searchEvents`, `getEvent`, `updateEvent`, `getVisitor`, `deleteVisitor`, `getHealth`, `getStatus`.

- The secret key goes in the `X-Secret-Key` header, never in a URL. `getChallenge` and `identify` use the publishable key (`publishableKey` option).
- 2xx responses are returned as data, **including** refusals such as `{ ok: false, error }`. Check `ok`.
- Non-2xx throws `FpCheckerApiError` with `status`, `code` (`error ?? reason` from the body) and `retryAfter` (seconds).
- Only GET requests retry (429 and 5xx, at most 2 retries, honouring `Retry-After`, wait capped at 10 s). POST, PATCH and DELETE are never retried.

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

Throws `WebhookSignatureError` with `code` of `malformed_header`, `bad_signature`, `expired` or `future` (default tolerance 300 s).

## License

Apache-2.0
