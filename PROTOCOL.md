# fpchecker native client protocol v1

This document describes what a client must send and what it gets back. Reference implementation:
[`android/`](android). Conformance vectors: [`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json).

## 1. Flow

```
GET  {baseUrl}/v1/challenge[?difficulty=N]   ->  { "nonce": "...", "expiresIn": 300 }
POST {baseUrl}/v1/identify                   ->  identify response
```

Both requests carry the header `X-Publishable-Key: <publishable key>`. Native requests have no `Origin` check.
A nonce is single use and short lived; fetch a fresh one for every identify call. The project must have the platform enabled,
otherwise the server answers `platform_not_enabled`.

## 2. Request body

```json
{
  "platform": "android",
  "nonce": "<from /v1/challenge>",
  "sig": "<lowercase hex HMAC-SHA256>",
  "components": [ { "key": "android.id", "value": "1a2b3c4d5e6f7081" } ],
  "agentVersion": "android-0.1.0",
  "pow": "1904",
  "proof": { "type": "play_integrity", "token": "..." }
}
```

`pow` and `proof` are optional. `pow` is a decimal **string**; a JSON number is treated as "no proof of work".
`Content-Type: application/json`.

Only keys from the table for the declared platform are accepted. Unknown keys, duplicate keys, values longer than 256
characters or values with a wrong format reject the whole request with `bad_request`, so clients validate locally and
**omit** any key they cannot obtain. Never send placeholders, all-zero ids or `9774d56d682e549c`.
At least one identity key (marked below) is required.

## 3. Android components

| Key | Format | Source |
|---|---|---|
| `android.id` (identity) | `^[0-9a-f]{16}$` | `Settings.Secure.ANDROID_ID`, lowercase, left-padded with `0` to 16 chars. Omit if missing, all zeros, or `9774d56d682e549c`. |
| `android.mediaDrmId` (identity) | `^[0-9a-f]{64}$` | `hex(SHA-256(Widevine PROPERTY_DEVICE_UNIQUE_ID))`. Omit on error or all-zero bytes. The raw id never leaves the device. |
| `android.simCountry` | `^[a-z]{2}$` or empty | `TelephonyManager.getSimCountryIso()`; empty string when absent. |
| `android.networkCountry` | `^[a-z]{2}$` or empty | `TelephonyManager.getNetworkCountryIso()`; empty string when absent. |
| `android.timezone` | IANA zone id | `TimeZone.getDefault().id` |
| `android.buildFingerprint` | up to 256 chars | `Build.FINGERPRINT` |
| `android.hardware` | up to 64 chars | `Build.HARDWARE` |
| `android.sdkInt` | `^[0-9]{1,3}$` | `Build.VERSION.SDK_INT` |
| `android.model` | up to 64 chars | `Build.MODEL` |

Over-long values are truncated by the client.

## 4. Canonical form and seal

```
canonical = nonce + for each part in sort(["key=value", ...]): "|" + part
sig       = lowercase-hex( HMAC-SHA256( key = UTF-8(sealKey), message = UTF-8(canonical) ) )
```

The sort is on the joined `key=value` strings using plain UTF-16 code unit order (JavaScript `Array.prototype.sort()`
default). The order of `components` in the JSON body does not matter.

## 5. Proof of work (optional)

When the project requires it, request the challenge with `?difficulty=N` (8..28) and send `pow`: the smallest decimal
counter `c >= 0` such that `SHA-256(UTF-8(nonce + ":" + c))` has at least `N` leading zero bits.

## 6. Play Integrity (optional)

Use the Standard API with the integrator's Google Cloud project number. Bind the token to the request:

```
requestHash = lowercase-hex( SHA-256( UTF-8(canonical) ) )
```

and send `"proof": { "type": "play_integrity", "token": "<token>" }`. Changing the nonce or any component invalidates the
token. If a token cannot be obtained, send the request without `proof`; it is then treated as unattested.

## 7. Response

Success:

```json
{
  "ok": true, "platform": "android", "visitorId": "a4_...",
  "identityConfidence": 100, "trustScore": 55,
  "trustDeductions": ["..."], "shadowDeductions": ["..."],
  "rulesVersion": "n2", "isNew": false, "attestation": "..."
}
```

Pass `attestation` to your backend, which verifies it with the fpchecker API (`/v1/eligibility`, `/v1/quota`).

Failure is always fail-closed: `{ "ok": false, "visitorId": null, "trustScore": 0, "reason": "..." }`, with `reason` one of
`bad_request`, `bad_nonce`, `seal_invalid`, `platform_not_enabled`, `nonce_reused`, `project_write_budget`,
`identify_daily_limit`, `internal_error`.

The Android SDK additionally reports client-side reasons: `network` (transport error), `challenge_failed`,
`bad_response` (unparseable body) and `no_device_id` (no identity key could be collected).
