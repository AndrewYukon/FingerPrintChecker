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
