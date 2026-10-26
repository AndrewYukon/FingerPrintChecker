# FPChecker demo (iOS + macOS)

A one-screen SwiftUI app that depends on the local package (`../..`) and shows `visitorId`, `trustScore`,
deductions, `proofStatus` and the raw response.

```
cp Config.example.xcconfig Config.xcconfig   # gitignored; fill in your publishable key and seal key
brew install xcodegen                        # once
xcodegen generate                            # creates FingerPrintCheckerDemo.xcodeproj (gitignored)
open FingerPrintCheckerDemo.xcodeproj
```

Bundle id `com.fpchecker.demo`. The App Attest entitlement is `development` for Debug and `production` for Release.
To run on a real device set `DEVELOPMENT_TEAM` in `Config.xcconfig` and use a provisioning profile with the App Attest
capability. App Attest does not work in the Simulator (the SDK then sends no proof). In your fpchecker project the
`nativeConfig.apple` Team ID and Bundle ID must match this app.

Unsigned build check: `xcodebuild -project FingerPrintCheckerDemo.xcodeproj -scheme Demo -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build`
(or `generic/platform=macOS`).

## Seeing the device integrity signals (SDK 0.7.0)

The demo runs with `integrityProbes` on (the default), but the app never receives the results: they are not in the
identify response, the `sealedResult` or the `attestation`. Read them on your server (or in the console) with the
`eventId` of the run:

```
curl -s -H "X-Secret-Key: $FPCHECKER_SECRET_KEY" "https://api.fpchecker.com/v1/events/<eventId>" | jq .signals.mobile
curl -s -H "X-Secret-Key: $FPCHECKER_SECRET_KEY" "https://api.fpchecker.com/v1/events?rooted=true&limit=5"
```

Each of `rooted`, `hooked`, `debugger`, `developerMode`, `mitm`, `vpn`, `locationSpoofed`, `clonedApp` is `true`
(detected), `false` (checked, nothing found) or `null` (not checked; for example the simulator cannot run every item).
`developerMode` and `clonedApp` are Android items and stay `null` for Apple events. Keep the secret key out of the app.
