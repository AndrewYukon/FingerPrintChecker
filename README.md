# FingerPrintChecker

Open-source client SDKs for the [fpchecker](https://fpchecker.com) native device-identification protocol.
A client collects a small set of device signals, seals them with an HMAC, optionally attaches a platform
attestation, and receives a stable `visitorId`, a trust score, and an `attestation` token that your own backend verifies.

| Platform | Status |
|---|---|
| Android (Kotlin / Java) | Available: [`android/`](android) |
| iOS, macOS, CLI | Coming |

The wire format is specified in [PROTOCOL.md](PROTOCOL.md); conformance vectors live in
[`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json) and every SDK must reproduce them.

## Android quick start

```kotlin
val checker = FpChecker(
    context,
    FpCheckerConfig(
        baseUrl = "https://api.fpchecker.com",
        publishableKey = "pk_...",          // from your fpchecker project
        sealKey = "...",                    // from your fpchecker project
        cloudProjectNumber = 123456789012L, // optional: enables the Play Integrity proof
        powDifficulty = null,               // optional: 8..28 when your project uses proof-of-work
    ),
)

lifecycleScope.launch {
    when (val r = checker.identify()) {
        is FpResult.Success -> sendToBackend(r.attestation)   // verify server-side!
        is FpResult.Failure -> log("identify failed: ${r.reason}")
    }
}
```

Java callers use `checker.identify(result -> { ... })` (callback on the main thread).

Requirements: minSdk 23. The library declares the `INTERNET` permission. Play Integrity uses
`com.google.android.play:integrity` and is only used when you pass `cloudProjectNumber`; if it is
unavailable or slow (5 s default) the request is still sent without a proof and is scored as unattested.

### Demo app

`android/demo` is a one-screen app. Provide your values without committing them, e.g. in `~/.gradle/gradle.properties`:

```
fpcheckerPk=pk_...
fpcheckerSealKey=...
fpcheckerBaseUrl=https://api.fpchecker.com
fpcheckerCloudProject=123456789012
```

Build and test (JDK 17, Android SDK 35):

```
cd android
./gradlew :fpchecker:testDebugUnitTest :fpchecker:assembleRelease :demo:assembleDebug :demo:assembleRelease lint
```

The release APK is unsigned unless `fpcheckerStoreFile`, `fpcheckerStorePassword`, `fpcheckerKeyAlias` and
`fpcheckerKeyPassword` are all set.

## Verify the attestation on YOUR backend

The seal key ships inside your app, so anything computed on the device can be forged by a determined attacker.
The `attestation` in a successful result is the only value you should trust: send it to your backend and verify it there
with the fpchecker API (for example `/v1/eligibility`, `/v1/quota`) using your secret key. Do not gate entitlements on
`trustScore` or `visitorId` as reported to the client.

## Privacy

What leaves the device (Android):

- `ANDROID_ID` (app-signing-key scoped, resettable by factory reset).
- A SHA-256 of the Widevine `deviceUniqueId`. The raw MediaDrm id never leaves the device.
- SIM / network country codes, time zone, `Build.FINGERPRINT`, `Build.HARDWARE`, `Build.MODEL`, SDK level.
- If enabled, a Play Integrity token (which Google issues about the app and device, not the user).

The SDK does not read the advertising id, accounts, contacts, location, phone number or IMEI. As the integrator you are
responsible for disclosing this in your privacy policy and Play Data safety form.

## License

Apache-2.0, see [LICENSE](LICENSE).
