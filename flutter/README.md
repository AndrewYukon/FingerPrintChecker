# fingerprintchecker (Flutter)

Flutter plugin for [FingerPrintChecker](https://fpchecker.com). It is a thin wrapper over the native Android and iOS SDKs and
exposes one operation: `identify`, the v2 flow. Your backend creates an intent with the secret key, the app passes the intent
token to `identify`, and your backend verifies the returned attestation.

## Install

The plugin is installed as a git dependency only; it is not on pub.dev.

```yaml
dependencies:
  fingerprintchecker:
    git:
      url: https://github.com/AndrewYukon/FingerPrintChecker
      path: flutter
      ref: flutter/v0.1.0
```

## Use

```dart
import 'package:fingerprintchecker/fingerprintchecker.dart';

final fp = FingerPrintChecker(
  const FpConfig(publishableKey: 'pk_...'),
);

// intentToken comes from your backend, which created the intent with the secret key.
final result = await fp.identify(intentToken, linkedId: 'user-123', tags: {'plan': 'free'});

switch (result) {
  case FpSuccess():
    // Send result.attestation to your backend, which verifies it.
    // visitorId and the score fields are present only when the project
    // enables score details; otherwise they are null.
    await sendToBackend(result.attestation);
  case FpFailure(:final reason, :final httpStatus):
    debugPrint('identify failed: $reason ($httpStatus)');
}
```

`identify` never throws; every outcome is an `FpSuccess` or an `FpFailure`. Do not decide anything from the app alone: the
backend verifies the attestation.

### Config

`publishableKey` (required), `baseUrl`, `powDifficulty`, `integrityProbes`.
Android only: `cloudProjectNumber`, `integrityTimeoutMillis`.
iOS only: `useAppAttest`, `useDeviceCheck`.
A field the current platform does not have is ignored.

`baseUrl` must be `https`. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`.

### Errors

`FpFailure.reason` is passed through unchanged from the native SDK. The plugin adds these:

| reason | meaning |
|---|---|
| `bad_config` | empty `publishableKey`; `baseUrl` that is not a valid URL; `baseUrl` that is not `https` (plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`); or `powDifficulty` outside 8 to 28 |
| `bad_intent_token` | the intent token is empty |
| `invalid_tags` | `tags` holds something that is not a string, number, bool, null, or a list or map (string keys) of those |
| `bridge_error` | any other unexpected failure on the native side |

## Platform notes

- **Android**: `minSdk` 23. To use Play Integrity, set `cloudProjectNumber` in `FpConfig`.
- **iOS**: 14.0 or later. App Attest needs the App Attest entitlement on your own app. The privacy manifest ships with the pod.

## Example

A runnable app is in [`example/`](example).
