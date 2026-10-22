# FingerPrint Checker

**English** | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md)

Device identity and free-trial abuse protection for **web apps, iOS apps and Android apps** (plus macOS apps and
command-line tools), from [FingerPrint Checker](https://fpchecker.com).

Your client collects a small set of device signals, seals them with an HMAC, optionally attaches a platform attestation
(Play Integrity on Android, App Attest and DeviceCheck on Apple devices), and receives a stable `visitorId`, a trust
score, and an `attestation` token. Your own backend sends that token to the FingerPrint Checker API and gets back
`allow`, a human check, or `deny` for free trials, coupons, sign-up bonuses, invite rewards and anonymous usage limits.

This repository holds the open-source native SDKs and the protocol they speak.

## Supported platforms

| Platform | How to integrate | Status |
|---|---|---|
| **Web apps** (any browser) | The FingerPrint Checker browser agent `fp-agent.min.js`, served from your own domain; see [Web apps](#web-apps) | Available |
| **Android apps** (Kotlin / Java) | `com.fpchecker:fpchecker-android` on Maven Central, source in [`android/`](android) | Available, 0.1.0 |
| **iOS apps** (Swift Package) | `https://github.com/AndrewYukon/FingerPrintChecker`, source in [`apple/`](apple) | Available, 0.1.1 |
| macOS apps (Swift Package) | Same package as iOS | Available, 0.1.1 |
| Command-line tools | Protocol + examples in [`cli/`](cli/README.md) | Examples |

Every platform ends the same way: the client gets an `attestation`, and only your backend, holding your secret key,
asks for a decision. The wire format of the native SDKs is specified in [PROTOCOL.md](PROTOCOL.md); conformance vectors
live in [`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json) and every SDK must reproduce them.

## Web apps

The browser agent is not part of this repository. Download `fp-agent.min.js` from
`https://fpchecker.com/static/fp-agent.min.js` and serve it from **your own domain** (ad blockers often block
third-party fingerprinting scripts, and the agent's first-party id only works on your origin). Your project page in
the fpchecker.com console shows these snippets with your keys filled in:

```html
<script src="/static/fp-agent.min.js"></script>
<script>
  async function identifyBrowser() {
    const { attestation } = await window.FpGuardAgent.identify({
      baseUrl: 'https://api.fpchecker.com',
      publishableKey: 'pk_...',   // from your project
      sealKey: '...',             // from your project
    });
    return attestation; // send it to your backend unchanged
  }
</script>
```

```js
// Server side only. Keep the secret key in an environment variable.
const response = await fetch('https://api.fpchecker.com/v1/eligibility', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'X-Secret-Key': process.env.FPCHECKER_SECRET_KEY },
  body: JSON.stringify({ attestation, email, claim: true, kind: 'trial', clientIp }),
});
const decision = await response.json(); // { ok, eligible, action, reason }
```

Add your site's origin to the project's allowed origins, or the browser call is refused.

## Android quick start

```kotlin
// build.gradle.kts (Maven Central)
dependencies {
    implementation("com.fpchecker:fpchecker-android:0.1.0")
}
```

```kotlin
val checker = FpChecker(
    context,
    FpCheckerConfig(
        baseUrl = "https://api.fpchecker.com",
        publishableKey = "pk_...",          // from your FingerPrint Checker project
        sealKey = "...",                    // from your FingerPrint Checker project
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

## iOS / macOS quick start

Swift Package Manager: add `https://github.com/AndrewYukon/FingerPrintChecker` (product `FingerPrintChecker`,
iOS 14+, macOS 11+), or in `Package.swift`:

```swift
.package(url: "https://github.com/AndrewYukon/FingerPrintChecker", from: "0.1.1")
```

```swift
import FingerPrintChecker

let checker = FingerPrintChecker(config: FPConfig(
    publishableKey: "pk_...",   // from your FingerPrint Checker project
    sealKey: "...",             // from your FingerPrint Checker project
    powDifficulty: nil          // optional: 8...28 when your project uses proof-of-work
))

switch await checker.identify() {
case .success(let r): try await sendToBackend(r.attestation)   // verify server-side!
case .failure(let reason, let httpStatus): print("identify failed: \(reason) \(httpStatus)")
}
```

`FPConfig` also has `baseURL` (default `https://api.fpchecker.com`), `useAppAttest` and `useDeviceCheck` (both default `true`).
Concurrent `identify()` calls are serialised. `swift build && swift test` at the repo root run the unit tests on macOS.
`apple/Demo` is a SwiftUI demo for both platforms, see [apple/Demo/README.md](apple/Demo/README.md).

### App Attest and DeviceCheck

- **App Attest** (real devices only; iOS 14+, supported macOS versions): the SDK creates one key per install, attests it on the
  first request and sends assertions afterwards. Add the App Attest capability to your app. In your FingerPrint Checker project configure the
  Team ID and Bundle ID of your app (and the environment, `development` vs `production`), otherwise the proof is not checked
  and the device is scored as unattested. If App Attest is unavailable or fails, identify still succeeds without a proof.
  A key is remembered only after the server confirmed its attestation; if the server forgets a key, or Apple reports it
  invalid (for example after a restore), the SDK attests a new one within the same `identify()` call (one extra request
  when the server forgot it), so the caller never sees an unattested result for it.
- **DeviceCheck**: the SDK sends a DeviceCheck token so FingerPrint Checker can remember per device whether a claim was already made.
  For this, create a DeviceCheck key in your Apple Developer account and upload it to your FingerPrint Checker project; without it
  the token is ignored.
- **The claimed bit is shared by every app of your Apple team.** Apple keeps only two DeviceCheck bits per device per
  developer team, so FingerPrint Checker uses bit 0 to mean "this device already claimed a free trial (default kind) in one of
  this team's apps". The trade-off: a device that claimed the trial in one of your apps is refused the trial in your
  other apps on the same team. Word the refusal accordingly ("this device has already used a free trial"), since the
  user may have claimed it elsewhere. Bit 1 is reserved. The only way to keep two apps independent is to publish them
  under separate Apple developer teams. Android's Play Integrity Device Recall works the same way: its bits are shared
  by all apps of one Play developer account.
- Simulators have neither feature and report `ios.simulator=true`.

## Command-line tools

No library: a CLI can be written in any language. [`cli/`](cli/README.md) has dependency-free
examples for Node, Python and Go (under 100 lines each). CLI devices are never attested; enable
PoW human verification for the project.

## Verify the attestation on YOUR backend

The seal key ships inside your app, so anything computed on the device can be forged by a determined attacker.
The `attestation` in a successful result is the only value you should trust: send it to your backend and verify it there
with the FingerPrint Checker API (for example `/v1/eligibility`, `/v1/quota`) using your secret key. Do not gate entitlements on
`trustScore` or `visitorId` as reported to the client.

## Privacy

Store disclosure answers (Google Play Data safety, App Store App Privacy): [docs/PRIVACY.md](docs/PRIVACY.md).

What leaves the device (Android):

- `ANDROID_ID` (app-signing-key scoped, resettable by factory reset).
- A SHA-256 of the Widevine `deviceUniqueId`. The raw MediaDrm id never leaves the device.
- SIM / network country codes, time zone, `Build.FINGERPRINT`, `Build.HARDWARE`, `Build.MODEL`, SDK level.
- If enabled, a Play Integrity token (which Google issues about the app and device, not the user).

The SDK does not read the advertising id, accounts, contacts, location, phone number or IMEI. As the integrator you are
responsible for disclosing this in your privacy policy and Play Data safety form.

What leaves the device (iOS / macOS):

- A random UUID stored in the Keychain (this device only, not synchronised, not backed up to other devices).
- iOS: `identifierForVendor`. macOS: the hardware `IOPlatformUUID`.
- Time zone identifier, hardware model (for example `iPhone17,1`, `Mac15,3`), OS version, simulator flag (iOS).
- A SHA-256 of the DeviceCheck token (the token itself is sent so the server can query Apple), and App Attest key id and
  attestation/assertion objects, when enabled.

The SDK stores one timestamp in UserDefaults (App Attest back-off). No advertising id, location, contacts or accounts are read. The package ships a `PrivacyInfo.xcprivacy` declaring
Device ID collection (not linked, not used for tracking) and no required-reason APIs. Disclose this in your App Privacy details.

## License

Apache-2.0, see [LICENSE](LICENSE).
