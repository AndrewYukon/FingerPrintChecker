# Store privacy disclosures

What the SDKs collect, and how to answer the Google Play **Data safety** form and the App Store
**App Privacy** questions for it. This covers only what the fpchecker SDK adds; your own app's data
practices are yours to declare. It is guidance, not legal advice: you are the developer of record
and fpchecker processes this data on your behalf, for the purpose you configure.

## What leaves the device

| Platform | Sent | Never sent |
|---|---|---|
| Android | `ANDROID_ID` (per app-signing key, user and device), SHA-256 of the Widevine device id, SIM / network country, time zone, `Build.FINGERPRINT`, `Build.HARDWARE`, `Build.MODEL`, SDK level, a Play Integrity token (when you set a Cloud project number) | raw Widevine id, advertising id, IMEI, serial, phone number, location, contacts |
| iOS | a random id kept in the Keychain (this device only), `identifierForVendor`, time zone, model (`iPhone17,1`), OS version, simulator flag, an App Attest attestation / assertion, a DeviceCheck token | advertising id (IDFA), location, contacts |
| macOS | `IOPlatformUUID`, a random Keychain id, time zone, model, OS version, App Attest (macOS 27+), DeviceCheck (where supported) | serial number, MAC address |

### Device integrity probes (SDK 0.7.0 and later)

With `integrityProbes` on (the default), the SDK adds one more value to the request: a probe version number and, per
check, whether it fired, was clean, or could not be run. In practice these are device-state booleans (rooted or
jailbroken, hooking framework, emulator or simulator, debugger attached, developer options, interception proxy or
untrusted user certificate, active VPN, mock location, cloned app), plus a reserved date field that is currently always
empty (the SDK does not detect factory resets).

| Sent | Never sent |
|---|---|
| Booleans and one probe version number, nothing else | Coordinates, the list of installed apps, certificate contents, proxy addresses, file paths, process names |

The SDK adds no permission and no `<queries>` entry. A location check only uses a location permission your app already
holds, runs on the device, and sends one boolean. The values are used to detect fraud and abuse and are not used for
tracking, advertising or profiling. They are not returned to the app: your server reads them through the events API and
webhooks. Set `integrityProbes` to `false` to stop collecting them; the SDK then reports every item as "not checked".

The server stores keyed hashes of the identifiers, not the identifiers themselves, plus the IP
address and coarse network data (country, ASN) of each request. Device rows expire after the retention period
without activity; a user's deletion request is made by you, for your project, to fpchecker.

None of it is used for advertising or shared with data brokers, and the SDK has no tracking
domains.

## Google Play — Data safety

Answer for the SDK's part:

| Question | Answer |
|---|---|
| Does your app collect or share any of the required user data types? | **Yes** |
| Data type | **Device or other IDs** |
| Collected / shared | **Collected.** Not "shared": fpchecker is a service provider processing it on your behalf. |
| Processed ephemerally? | **No** (keyed hashes are kept to recognise the device) |
| Required or optional? | **Required** (if identify gates a feature), otherwise optional |
| Purposes | **Fraud prevention, security, and compliance** |
| Encrypted in transit? | **Yes** (HTTPS only) |
| Can users request deletion? | **Yes**, through you |

The integrity probes add no new Data safety data type. Declare them under the same **Device or other IDs** answer
(purpose: fraud prevention, security and compliance), or, if you prefer to list them separately, as **App info and
performance → Diagnostics** collected for security, not shared, not used for advertising. No location data type is
needed: no coordinates are collected.

If you also send the attestation's `visitorId` with your own account data, declare that in your
own answers (it is then linked to the user by you).

Play Integrity verdicts themselves are not user data in the form's sense; Google's own disclosure
covers the Play services side.

## App Store — App Privacy

| Question | Answer |
|---|---|
| Data type | **Identifiers → Device ID** |
| Used for tracking? | **No.** The SDK does not combine it with other companies' data or share it with data brokers (App Tracking Transparency does not apply). |
| Linked to the user's identity? | **No** for the SDK alone. **Yes** if your backend stores the `visitorId` with an account. |
| Purposes | **App Functionality** (Apple lists fraud prevention and security under it) |

The integrity probes add no data type to App Privacy: they are device-state booleans used for fraud prevention and
security, they are not used for tracking, and no coordinates, app list, certificates or proxy addresses leave the device.
Keep the answers above; if you list diagnostic data separately, choose **Other Diagnostic Data**, not linked, not tracking.

The Swift package ships a `PrivacyInfo.xcprivacy` declaring the collected Device ID
(not linked, not tracking, App Functionality) and its required-reason API use
(`UserDefaults`, reason `CA92.1`, for the App Attest back-off timestamp). Xcode merges it into your
app's privacy report.

App Attest and DeviceCheck need the App Attest capability (`com.apple.developer.devicecheck.appattest-environment`)
and, for DeviceCheck, a DeviceCheck key uploaded in the fpchecker console. Neither needs a user
prompt.

## CLI

A CLI distributed outside the stores has no store form. Tell your users what is sent: a random id
in `~/.config/<tenant>/device-id`, the macOS hardware UUID, time zone and OS version.
