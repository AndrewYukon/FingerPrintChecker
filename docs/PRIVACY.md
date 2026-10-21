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
