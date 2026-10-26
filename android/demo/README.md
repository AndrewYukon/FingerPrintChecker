# FPChecker Android demo

A one-screen app that depends on the local library (`:fpchecker`) and shows `visitorId`, `trustScore`, deductions,
`proofStatus` and the raw response. Build it from `android/` with `./gradlew :demo:assembleDebug -PfpcheckerPk=pk_... -PfpcheckerSealKey=...`
(Gradle properties; do not commit them).

## Seeing the device integrity signals (SDK 0.7.0)

The demo runs with `integrityProbes` on (the default `FpCheckerConfig`), but the app never receives the results: they
are not in the identify response, the `sealedResult` or the `attestation`. Read them on your server (or in the console)
with the `eventId` of the run:

```
curl -s -H "X-Secret-Key: $FPCHECKER_SECRET_KEY" "https://api.fpchecker.com/v1/events/<eventId>" | jq .signals.mobile
curl -s -H "X-Secret-Key: $FPCHECKER_SECRET_KEY" "https://api.fpchecker.com/v1/events?emulator=true&limit=5"
```

Each of `rooted`, `hooked`, `debugger`, `developerMode`, `mitm`, `vpn`, `locationSpoofed`, `clonedApp` is `true`
(detected), `false` (checked, nothing found) or `null` (not checked). Keep the secret key out of the app.
