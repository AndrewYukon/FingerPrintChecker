# FingerPrint Checker

**English** | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md)

Device identity and free-trial abuse protection for **web apps, iOS apps and Android apps** (plus macOS apps and
command-line tools), from [FingerPrint Checker](https://fpchecker.com).

Your client collects a small set of device signals, seals them with an HMAC, optionally attaches a platform attestation
(Play Integrity on Android, App Attest and DeviceCheck on Apple devices), and receives a stable `visitorId`, a trust
score (only if the project's `scoreDetails` policy allows it), and an `attestation` token. Your own backend sends that token to the FingerPrint Checker API and gets back
`allow`, a human check, or `deny` for free trials, coupons, sign-up bonuses, invite rewards and anonymous usage limits.

This repository holds the open-source native SDKs and the protocol they speak.

## One household, one free trial

People who abuse free trials don't stop at one browser. They try a second browser, then the laptop, then the phone,
then your app. FingerPrint Checker refuses all of them once one has claimed. Every case below was tested on real
devices (a Mac with three browsers, an iPhone, two Android phones, one home Wi-Fi):

- **Every browser on one computer is one device.** Different browsers on the same computer and network get the same `visitorId`.
- **Every device on one Wi-Fi counts as one household.** Once a desktop, laptop, tablet or phone has claimed on a home
  network, the others on that network are refused. This also holds after they switch to mobile data, because each device
  remembers the networks it was seen on.
- **Your website and your apps share one limit.** Put your web project and your iOS and Android app projects in one
  *claim group* in the [console](https://fpchecker.com/console). A household that claimed on the website is then
  refused in the app, and the other way round.
- **Caught later, too.** A phone that claimed on mobile data and later joins the same home Wi-Fi is flagged. Your
  backend lists those claims with `GET /v1/claims/flags`. Nothing is revoked automatically.

## Supported platforms

| Platform | How to integrate | Status |
|---|---|---|
| **Web apps** (any browser) | The FingerPrint Checker browser agent `fp-agent.min.js`, served from your own domain; see [Web apps](#web-apps) | Available |
| **Android apps** (Kotlin / Java) | `com.fpchecker:fpchecker-android` on Maven Central, source in [`android/`](android) | Available, 0.7.0 |
| **iOS apps** (Swift Package) | `https://github.com/AndrewYukon/FingerPrintChecker`, source in [`apple/`](apple) | Available, 0.7.0 |
| macOS apps (Swift Package) | Same package as iOS | Available, 0.7.0 |
| Command-line tools | Protocol + examples in [`cli/`](cli/README.md) | Examples |

Every platform ends the same way: the client gets an `attestation`, and only your backend, holding your secret key,
asks for a decision. The wire format of the native SDKs is specified in [PROTOCOL.md](PROTOCOL.md); conformance vectors
live in [`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json) and every SDK must reproduce them.
The newer v2 protocol is described in [PROTOCOL-V2.md](PROTOCOL-V2.md).

## v2 (recommended for new integrations)

Protocol v2 removes the seal key from the client. Your **backend** creates a short-lived *intent* with its secret key and
hands the opaque `intentToken` to the app; the SDK runs identify with it and returns an opaque `attestation`; the app sends
that to your backend, which asks `/v1/eligibility` or `/v1/quota` for the decision.

```
backend  POST /v2/intents (secret key)      ->  intentToken
app      sdk.identify(intentToken)          ->  attestation
backend  POST /v1/eligibility (secret key)  ->  allow / human check / deny
```

SDK 0.2.0 adds `identify(intentToken)` next to the v1 `identify()`; `sealKey` is only needed for v1.
SDK 0.4.0 adds optional `linkedId` / `tags` and the result's `eventId`, see [Event fields](#event-fields-linkedid-tags-eventid-sdk-040).
SDK 0.5.0 adds the optional `sealedResult` on identify answers, see [Sealed results](#sealed-results-server-sdks-and-web-packages).
SDK 0.3.0: the v1 `trustScore` and `identityConfidence` are now optional (`Int?` / `null`), because servers from 0.35 omit them by default. The CLI examples take
`--intent <token>` (or `FPC_INTENT`). Wire format: [PROTOCOL-V2.md](PROTOCOL-V2.md); vectors:
[`test-vectors/protocol-v2.json`](test-vectors/protocol-v2.json).

A backend as a Cloudflare Worker (secret key in `wrangler secret put FPC_SECRET_KEY`):

```ts
interface Env { FPC_SECRET_KEY: string }
const API = 'https://api.fpchecker.com';

async function fpc(env: Env, path: string, body: unknown): Promise<Response> {
  return fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'X-Secret-Key': env.FPC_SECRET_KEY },
    body: JSON.stringify(body),
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== 'POST') return new Response('not found', { status: 404 });

    if (url.pathname === '/intent') { // the app calls this, then gives intentToken to the SDK
      const clientIp = request.headers.get('CF-Connecting-IP') ?? undefined;
      const res = await fpc(env, '/v2/intents', { purpose: 'claim:trial', clientIp });
      const { ok, intentToken } = (await res.json()) as { ok: boolean; intentToken?: string };
      return Response.json(ok ? { intentToken } : { error: 'intent_failed' }, { status: ok ? 200 : 502 });
    }

    if (url.pathname === '/claim') { // the app posts the SDK's attestation here
      const { attestation } = (await request.json()) as { attestation: string };
      const clientIp = request.headers.get('CF-Connecting-IP') ?? undefined;
      const res = await fpc(env, '/v1/eligibility', { attestation, clientIp, claim: true });
      const d = (await res.json()) as { eligible?: boolean; action?: string; reason?: string; powDifficulty?: number };
      // Grant on your side when d.eligible is true. Return the decision only: visitorId and
      // trustScore stay on your backend, so the client never learns what it is scored on.
      return Response.json({ eligible: d.eligible === true, action: d.action, reason: d.reason, powDifficulty: d.powDifficulty });
    }
    return new Response('not found', { status: 404 });
  },
};
```

To bind the result to one of your users, add `subject` (your user or session id, taken from your own session, never
from the request body) to both the `/v2/intents` and the `/v1/eligibility` call; a mismatch is denied (`attestation_subject`).
For a counted free allowance instead of a one-time trial, mint the intent with `purpose: 'quota:<name>'` and call `/v1/quota`.

## Event fields: `linkedId`, `tags`, `eventId` (SDK 0.4.0)

Identify can attach your own identifier and free-form tags to the event it writes, and returns the event's id, as the web
agent 0.9.0 does. Both are optional; `null` / absent sends nothing, and existing calls are unchanged.

- `linkedId`: a string of 1 to 256 characters, no control characters (U+0000 to U+001F, U+007F).
- `tags`: a JSON object of at most 4096 bytes (UTF-8), nested at most 3 levels (an array counts as a level).
- A value that breaks a rule fails **before any network call**, with `invalid_linked_id` or `invalid_tags`.
- They are client-supplied and sit beside the signed fields: they are not part of the seal, the canonical bytes or any
  platform proof. Read the stored event with your secret key (`GET /v1/events/:eventId`) or in a webhook.
- `eventId` on the success result is `null` / `nil` when the server predates events (v1 and v2).

```kotlin
// Android
val r = checker.identify(intentToken, FpEventOptions(linkedId = "order_42", tags = mapOf("page" to "checkout")))
if (r is FpIdentifyResult.Success) log(r.eventId)      // "ev_..."
// v1: checker.identify(FpEventOptions(linkedId = "order_42")); Java: new FpEventOptions("order_42", null)
```

```swift
// iOS / macOS
let result = await checker.identify(intentToken: token, linkedId: "order_42", tags: ["page": "checkout"])
if case .success(let r) = result { print(r.eventId ?? "-") }   // "ev_..."
// v1: await checker.identify(linkedId: "order_42")
```

CLI: `--linked-id order_42 --tags '{"page":"checkout"}'` (see [`cli/`](cli/README.md)).

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
    implementation("com.fpchecker:fpchecker-android:0.7.0")
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
.package(url: "https://github.com/AndrewYukon/FingerPrintChecker", from: "0.7.0")
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

## Device integrity probes (SDK 0.7.0)

From 0.7.0 the SDK also checks the state of the device it runs on and reports one yes / no / not-checked answer per item.
It detects, on the device types that support it: a rooted or jailbroken device, hooking or instrumentation frameworks,
an emulator or simulator, an attached debugger, developer options, an interception proxy or untrusted user certificates,
an active VPN, mock (spoofed) locations, and a cloned or parallel-space copy of your app. A macOS app reports the
debugger and hooking items only.

- **Switch.** `integrityProbes` (default `true`) in Android `FpCheckerConfig` and Swift `FPConfig`. With `false` the SDK
  runs no probe and reports every item as "not checked".
- **Where the results go.** They are sent with the identify request but are **never returned to the app**: the identify
  response, the `sealedResult` and the `attestation` do not contain them. They reach **your server** only through the
  events API (`signals.mobile`) and webhooks, and can drive project rules. See [Server SDKs](#sealed-results-server-sdks-and-web-packages).
- **Three states.** `true` = detected, `false` = checked and nothing found, `null` = not checked (older SDK, probes
  switched off, an item that cannot run on this device or OS). Detection is best effort and never a guarantee either way.
- **Factory reset date.** The field `factoryResetAt` exists in the server types but is reserved: SDK 0.7.0 does not
  detect factory resets, so it is always `null`.
- **Testing on your own build.** A debuggable Android build and an iOS run launched from Xcode report `debugger = true`,
  so your own test devices will show it. Release builds started normally do not.
- **iOS VPN meaning.** On iOS `vpn = false` only means "no legacy tunnel interface (`ppp`, `tap`, `tun`) was found". Modern
  VPN apps, Private Relay and Wi-Fi Calling use other interfaces (`utun*`, `ipsec*`), which are deliberately not counted, so
  an iOS device can be on a VPN while `vpn` is `false`.
- **No new permissions.** The SDK adds no `uses-permission`, no `<queries>`, and does not list the apps on the device.
  A location check uses only a location permission your app already holds, and on Android the device-VPN check runs only when your app already holds `ACCESS_NETWORK_STATE` (the SDK adds no permission); otherwise `vpn` is `null`.

Server side, filter the events API by `rooted`, `hooked`, `emulator`, `mitm`, `locationSpoofed` and `clonedApp`
(`true` / `false`), and read `signals.mobile` and `signals.vpn.methods` (which may contain `os_vpn`). Server SDKs 0.3.0 type these fields.

## Sealed results, server SDKs and web packages

When your project has a sealing key, identify answers carry an optional `sealedResult` string (SDK 0.5.0): `FpResult.Success.sealedResult` /
`FpIdentifyResult.Success.sealedResult` on Android, `FPSuccess.sealedResult` / `FPSuccessV2.sealedResult` on iOS and macOS. It is
`null` / `nil` when the project has no key or the server predates it. Forward it to YOUR backend, which opens it with the project key
(never on the device); the format and its test vectors are in [test-vectors/sealed-result-v1.json](test-vectors/sealed-result-v1.json).

| Package | Where | Install |
|---|---|---|
| Server SDK for Node.js, `@fingerprintchecker/node` | [`server/node`](server/node) | `npm install @fingerprintchecker/node` |
| Server SDK for Python, `fpchecker` | [`server/python`](server/python) | `pip install fingerprintchecker` |
| Server SDK for Go | [`server/go`](server/go) | `go get github.com/AndrewYukon/FingerPrintChecker/server/go` |
| Browser agent loader, `@fingerprintchecker/agent` | [`web/agent`](web/agent) | `npm install @fingerprintchecker/agent` |
| React wrapper, `@fingerprintchecker/react` | [`web/react`](web/react) | `npm install @fingerprintchecker/react` |
| Vue wrapper, `@fingerprintchecker/vue` | [`web/vue`](web/vue) | `npm install @fingerprintchecker/vue` |

These packages are not published to npm and PyPI yet. Until they are, install them from GitHub: clone this repository and run
`npm install ./web/agent` (or `./server/node`, ...) / `pip install ./server/python`, or use
`go get github.com/AndrewYukon/FingerPrintChecker/server/go@main` for Go. How the owner publishes them: [docs/PUBLISHING.md](docs/PUBLISHING.md).

## Cloudflare Worker proxy

Serve the agent and API first-party from your own domain with the open-source [Cloudflare Worker](integrations/cloudflare-worker/README.md).

## Command-line tools

No library: a CLI can be written in any language. [`cli/`](cli/README.md) has dependency-free
examples for Node, Python and Go. CLI devices are never attested; enable
PoW human verification for the project.

## Verify the attestation on YOUR backend

The seal key ships inside your app, so anything computed on the device can be forged by a determined attacker.
The `attestation` in a successful result is the only value you should trust: send it to your backend and verify it there
with the FingerPrint Checker API (for example `/v1/eligibility`, `/v1/quota`) using your secret key. Do not gate entitlements on
`trustScore` or `visitorId` as reported to the client.

Servers from 0.35 answer v1 `identify()` with a sealed `attestation` (`{ "token": "fpa1.…" }`) that the client cannot read, and leave
out `trustScore`, `identityConfidence`, `breakdown` and the other score fields unless the project's `scoreDetails` policy is
`live` or `all` (default `none`). Forward the attestation to your backend unchanged, and read `visitorId`, `isNew`,
`trustScore` and `identityConfidence` from the `/v1/eligibility` answer there.

## Privacy

Store disclosure answers (Google Play Data safety, App Store App Privacy): [docs/PRIVACY.md](docs/PRIVACY.md).

What leaves the device (Android):

- `ANDROID_ID` (app-signing-key scoped, resettable by factory reset).
- A SHA-256 of the Widevine `deviceUniqueId`. The raw MediaDrm id never leaves the device.
- SIM / network country codes, time zone, `Build.FINGERPRINT`, `Build.HARDWARE`, `Build.MODEL`, SDK level.
- If enabled, a Play Integrity token (which Google issues about the app and device, not the user).

The SDK does not read the advertising id, accounts, contacts, phone number or IMEI, and never sends coordinates (see the integrity paragraph below). As the integrator you are
responsible for disclosing this in your privacy policy and Play Data safety form.

What leaves the device (iOS / macOS):

- A random UUID stored in the Keychain (this device only, not synchronised, not backed up to other devices).
- iOS: `identifierForVendor`. macOS: the hardware `IOPlatformUUID`.
- Time zone identifier, hardware model (for example `iPhone17,1`, `Mac15,3`), OS version, simulator flag (iOS).
- A SHA-256 of the DeviceCheck token (the token itself is sent so the server can query Apple), and App Attest key id and
  attestation/assertion objects, when enabled.

The SDK stores one timestamp in UserDefaults (App Attest back-off). No advertising id, contacts or accounts are read, and no coordinates are sent. The package ships a `PrivacyInfo.xcprivacy` declaring
Device ID collection (not linked, not used for tracking) and its one required-reason API use (`UserDefaults`, reason `CA92.1`, for the App Attest back-off timestamp). Disclose this in your App Privacy details.

What the integrity probes add (SDK 0.7.0): only device-state booleans (detected / not detected / not checked) and a
probe version number, used for security and fraud prevention, not for tracking. The SDK does not collect or send
coordinates, the list of installed apps, certificates, proxy addresses or file paths. For Google Play **Data safety**
this stays in the existing "Device or other IDs" answer (purpose: fraud prevention, security and compliance); for App Store
**App Privacy** nothing new is tracked and the existing Device ID entry (not used for tracking) still describes the SDK.
Details: [docs/PRIVACY.md](docs/PRIVACY.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
