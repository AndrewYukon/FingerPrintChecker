# @fingerprintchecker/agent

Browser agent for [FingerPrintChecker](https://fpchecker.com). Loads the agent once per page, calls `identify`, and can keep a short-lived result cache.

```ts
import { load } from '@fingerprintchecker/agent';

const fp = await load({ publishableKey: 'pk_live_...' });
// intentToken comes from your server (POST /v2/intents)
const { eventId, sealedResult, attestation } = await fp.identify({ intentToken, linkedId: 'order-42', tags: { plan: 'pro' } });
```

Send `eventId` / `sealedResult` / `attestation` to your backend and decide there with a server SDK. Never trust the browser result on its own.

## API

- `load({ publishableKey, endpoint? })` returns an `FpAgent`. `endpoint` defaults to `https://api.fpchecker.com`.
- `fp.identify({ intentToken, linkedId?, tags?, cache? })` returns `{ attestation?, eventId, sealedResult?, expiresIn?, fromCache }`.
- Errors are `FpCheckerAgentError` with `code`: `ssr`, `invalid_option`, `load_failed`, `identify_failed`. For `identify_failed`, `reason` and `status` carry the server's values.

## Server-side rendering

`load()` rejects with `code: 'ssr'` when there is no `window` and touches nothing. Call it from client-only code (an effect, an event handler). Calling `load()` repeatedly or concurrently injects the agent script once.

## Result cache (off by default)

```ts
await fp.identify({ intentToken, linkedId: userId, cache: { ttlSeconds: 300, storage: 'session' } });
```

- `ttlSeconds` is 1..3600; `storage` is `'memory' | 'session' | 'local'`.
- Key = publishableKey + SHA-256(linkedId) + SHA-256(canonical JSON of `tags`, keys sorted). The raw `linkedId` never reaches storage. The `intentToken` is **not** part of the key.
- A cache hit is the result of an **earlier** identify (an earlier intent). It returns `{ eventId, sealedResult, fromCache: true }` with **no `attestation` and no `expiresIn`**, so it must not be used for eligibility or quota decisions. For those, pass `cache: false` (or leave the cache off) to force a fresh request.
- Only `eventId` and `sealedResult` are stored, never the attestation. Expired, malformed or too-far-future entries (more than 3600 s ahead) are treated as a miss and deleted from storage.
- Storage errors (private mode, blocked storage, quota) count as a miss and identify still works.

## Content Security Policy

By default the agent is bundled in this package as a string and injected as an inline `<script>` (no fetch for the script itself). Your CSP then needs one of:

- `script-src 'nonce-<value>'` plus a `<meta name="csp-nonce" content="<value>">` tag, which this package copies onto the injected script; or
- `script-src 'unsafe-inline'` (not recommended).

**Strict CSP (for example `script-src 'self'`):** pass `scriptUrl` and the agent is loaded with `<script src>` instead of inline.

```ts
const fp = await load({ publishableKey, scriptUrl: '/static/fp-agent.min.js' });
```

Either self-host a copy of `node_modules/@fingerprintchecker/agent/vendor/fp-agent.min.js` (it matches this package version), or use `https://fpchecker.com/static/fp-agent.min.js`. The hosted file tracks the website's agent version, not this package's, and needs `https://fpchecker.com` in `script-src`. If the script fails to load, `load()` rejects with `code: 'load_failed'`, the element is removed, and a later `load()` tries again.

Also allow the API endpoint in `connect-src` (`https://api.fpchecker.com` by default).

## Vendored file

`vendor/fp-agent.min.js` is an unmodified copy of the FingerPrintChecker agent (see its first-line comment for the source commit and version). Do not edit it; re-copy instead. The agent's TypeScript source is not part of this package.

## Development

```
npm install
npm test    # regenerates src/vendor-source.generated.ts, then vitest (happy-dom)
npm run build
```

Node >= 18.
