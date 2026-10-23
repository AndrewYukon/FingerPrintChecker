# fpchecker identify protocol v2

For SDK and client implementers. v1 ([PROTOCOL.md](PROTOCOL.md)) stays supported; component keys, component
rules, proofs (Play Integrity, App Attest, DeviceCheck) and proof of work are the same in both versions. The
backend-side decision endpoints (`/v1/eligibility`, `/v1/quota`, `/v1/subjects/*`) are shared.
Conformance vectors: [`test-vectors/protocol-v2.json`](test-vectors/protocol-v2.json); every client must reproduce them.

What changes for the client:

| v1 | v2 |
|---|---|
| The client holds a seal key and sends an HMAC `sig` over `nonce\|key=value\|...` | No client secret, no `sig` |
| `\|`-joined canonical string | RFC 8785 (JCS) bytes of a fixed JSON object |
| Anyone with the publishable key can identify | Each identify needs an **intent token** that the app's backend created with its secret key |
| The answer carries `visitorId`, `trustScore`, ... | The answer carries one **opaque** `attestation` |

Treat `intentToken`, `challenge` and `attestation` as opaque strings: never parse them.

## 1. Flow

```
app backend ── POST /v2/intents (X-Secret-Key) ───────────────▶ fpchecker   → intentToken
app backend ── intentToken ───────────────────────────────────▶ app / client
client ─────── GET  /v2/challenge?intent=... (X-Publishable-Key) ▶ fpchecker → challenge
client         collect components, build proofs over SHA-256(canonical bytes)
client ─────── POST /v2/identify (X-Publishable-Key) ──────────▶ fpchecker   → attestation
client ─────── attestation ───────────────────────────────────▶ app backend
app backend ── POST /v1/eligibility | /v1/quota (X-Secret-Key) ▶ fpchecker
```

The SDK never holds a secret key and never calls `/v2/intents`: the app hands it the `intentToken`.
For reference, the backend call is `POST /v2/intents` with `{ "purpose": "claim:trial", "subject": "user-123" }`
(`subject` optional) and the end user's IP as `clientIp`; it answers `{ "ok": true, "intentToken": "fpi1....", "expiresIn": 600 }`.
An intent is not single use: until it expires a client may fetch several challenges with it (for example a second
identify after a proof-of-work challenge).

## 2. `GET /v2/challenge?intent=<intentToken>[&difficulty=N]`

Header `X-Publishable-Key`. The intent token must be URL-encoded. Native requests have no `Origin` check.

```json
{ "ok": true, "protocolVersion": 2, "challenge": "v4....", "expiresIn": 300 }
```

Failure: `{ "ok": false, "error": "bad_intent" | ... }` with HTTP 400, 401, 402 or 429. `bad_intent` means the intent is
missing, expired or belongs to another project. `difficulty` (8-28) asks for a proof-of-work challenge exactly as in v1.
A v1 nonce cannot be used on `/v2/identify` and a `v4.` challenge cannot be used on `/v1/identify`.

## 3. Collecting components

Exactly as v1: same keys per platform, same per-component rules. Native free text may not contain `|`.
Native components never carry `hash` (only the web agent sends it).

## 4. Canonical bytes (JCS)

The canonical object is:

```json
{
  "agentVersion": "<as sent>",
  "challenge": "<as received>",
  "components": [ { "key": "...", "value": "..." } ],
  "domain": "fpchecker.identify.v2",
  "platform": "android | ios | macos | cli | web",
  "protocolVersion": 2
}
```

Its canonical bytes are the UTF-8 encoding of its RFC 8785 serialisation:

- object members sorted by key (as UTF-16 code units; every key here is ASCII), no whitespace;
- the only number is `2`;
- `components` sorted by `key`, compared as UTF-16 code units (uppercase before lowercase, digits first);
  each component's members are `key`, `value` (the web agent may add `hash`, which sorts first);
- strings as ECMAScript `JSON.stringify` writes them: `"` becomes `\"`, `\` becomes `\\`, `\b \f \n \r \t` use those
  escapes, every other code point below U+0020 is `\u00xx` with **lower-case** hex, and everything else is raw UTF-8,
  including U+007F, U+2028, U+2029, `/`, `<`, `&` and non-BMP characters.

Write a small dedicated serializer for this fixed object. Do not use a platform JSON encoder (`JSONSerialization`,
`org.json`, Go `encoding/json`, ...): they escape `/`, `<`, `&`, U+2028 and U+007F differently.

Refuse locally, without sending a request, what the server refuses (`bad_request`):

- a duplicate component key;
- a key not matching `^[A-Za-z0-9._-]{1,64}$`;
- a string that is not well-formed UTF-16 (a lone surrogate; in languages whose strings cannot hold one, invalid UTF-8);
- `agentVersion` longer than 64 characters;
- more components than v1 allows.

`requestBinding = SHA-256(canonical bytes)`:

| Platform | What is bound |
|---|---|
| Android | Play Integrity `requestHash` = lower-case hex of `requestBinding` |
| iOS / macOS | App Attest `clientDataHash` = the 32 raw bytes of `requestBinding` |
| CLI, web | nothing |

The server rebuilds the canonical bytes from the parsed request; the client never sends a digest.
The vectors give, for each accept case, `canonical`, `requestBindingHex` and `clientDataHashBase64`, and list inputs
that must be refused.

## 5. `POST /v2/identify`

Header `X-Publishable-Key`.

```json
{
  "protocolVersion": 2,
  "platform": "ios",
  "intentToken": "fpi1....",
  "challenge": "v4....",
  "agentVersion": "ios-0.2.0",
  "components": [ { "key": "ios.idfv", "value": "..." } ],
  "pow": "1904",
  "proof": { "type": "app_attest", "keyId": "...", "assertion": "..." },
  "deviceCheckToken": "..."
}
```

`pow`, `proof` and `deviceCheckToken` are optional and mean what they mean in v1; proof of work is computed over the
challenge string (`SHA-256(challenge + ":" + counter)` with the required number of leading zero bits). There is no `sig`.
The challenge must have been issued for this intent.

Success:

```json
{ "ok": true, "protocolVersion": 2, "attestation": "fpa1....", "expiresIn": 600, "proofStatus": "checked" }
```

- `proofStatus` appears for native platforms, with the v1 values. `unknown_key` keeps its v1 meaning: re-attest
  the App Attest key and retry once.
- There is no `visitorId` or score unless the project enabled score details, in which case `visitorId`,
  `trustScore`, `identityConfidence`, `isNew`, `trustDeductions`, `rulesVersion` (and `shadowDeductions`) are added.
  Do not gate anything on them client-side.
- **A success without a non-empty string `attestation` must be treated as a failure.**

Failure: `{ "ok": false, "protocolVersion": 2, "reason": "..." }`, with the v1 reasons plus `bad_intent`.
HTTP status as in v1 (429 for rate limits and the identify cap, 402 without credits).

## 6. After identify

Send the `attestation` string, unchanged, to your backend. The backend passes it as `attestation` to
`/v1/eligibility` or `/v1/quota`, with the secret key. It is valid for 10 minutes and only for the purpose (and subject,
if any) of its intent; a mismatch is denied. The eligibility answer already carries the project-scoped `visitorId`.
