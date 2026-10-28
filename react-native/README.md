# @fingerprintchecker/react-native

React Native module for [FingerPrintChecker](https://fpchecker.com). It is a thin wrapper over the native Android and iOS SDKs
and exposes one operation: `identify`, the v2 flow. Your backend creates an intent with the secret key, the app passes the
intent token to `identify`, and your backend verifies the returned attestation.

Requires React Native 0.76 or later.

## Install

```sh
npm install @fingerprintchecker/react-native
cd ios && pod install
```

**Expo**: it works in a development build or after `expo prebuild`. It does not work in Expo Go, because it contains native code.

## Use

```ts
import { FingerPrintChecker } from '@fingerprintchecker/react-native';

const fp = new FingerPrintChecker({ publishableKey: 'pk_...' });

// intentToken comes from your backend, which created the intent with the secret key.
const result = await fp.identify(intentToken, { linkedId: 'user-123', tags: { plan: 'free' } });

if (result.ok) {
  // Send result.attestation to your backend, which verifies it.
  // visitorId and the score fields are present only when the project
  // enables score details; otherwise they are undefined.
  await sendToBackend(result.attestation);
} else {
  console.warn(`identify failed: ${result.reason} (${result.httpStatus})`);
}
```

`identify` never rejects; every outcome is `{ ok: true, ... }` or `{ ok: false, reason, httpStatus }`. Do not decide anything
from the app alone: the backend verifies the attestation.

### Config

`publishableKey` (required), `baseUrl`, `powDifficulty`, `integrityProbes`.
Android only: `cloudProjectNumber`, `integrityTimeoutMillis`.
iOS only: `useAppAttest`, `useDeviceCheck`.
A field the current platform does not have is ignored.

`baseUrl` must be `https`. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`.

### Errors

`reason` is passed through unchanged from the native SDK. The wrapper adds these:

| reason | meaning |
|---|---|
| `bad_config` | empty `publishableKey`; `baseUrl` that is not a valid URL; `baseUrl` that is not `https` (plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`); `powDifficulty` outside 8 to 28; a `cloudProjectNumber` that is zero or negative (Android); or a field of the wrong type (`baseUrl` not a string, `integrityProbes` not a boolean, a numeric field that is not a whole number) |
| `bad_intent_token` | the intent token is empty |
| `invalid_tags` | `tags` holds something that is not a string, number, bool, null, or a list or object (string keys) of those |
| `not_linked` | the native module is missing: rebuild the app after installing, run `pod install`, and avoid Expo Go |
| `bridge_error` | any other unexpected failure on the native side |

## Platform notes

- **Android**: `minSdk` 23. To use Play Integrity, set `cloudProjectNumber` in the config.
- **iOS**: your React Native version's minimum (15.1 for React Native 0.76). App Attest needs the App Attest entitlement on your own app. The privacy manifest ships with the pod.

## Example

A runnable app is in the repository under `react-native/example`.
