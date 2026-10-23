# FingerPrint Checker

[English](README.md) | [简体中文](README.zh-CN.md) | **日本語** | [Español](README.es.md) | [Français](README.fr.md)

**Web アプリ、iOS アプリ、Android アプリ**（および macOS アプリとコマンドラインツール）向けのデバイス識別と無料トライアル不正利用対策を、[FingerPrint Checker](https://fpchecker.com) が提供します。

クライアントは少数のデバイスシグナルを収集して HMAC で封印し、必要に応じてプラットフォームのアテステーション（Android では Play Integrity、Apple デバイスでは App Attest と DeviceCheck）を添付して、安定した `visitorId`、トラストスコア、`attestation` トークンを受け取ります。自社のバックエンドがそのトークンを FingerPrint Checker API に送ると、無料トライアル、クーポン、登録ボーナス、招待特典、匿名ユーザーの利用制限について、`allow`、人間による確認、または `deny` の判定が返ります。

このリポジトリには、オープンソースのネイティブ SDK と、それらが使うプロトコルが含まれています。

## 対応プラットフォーム

| プラットフォーム | 統合方法 | ステータス |
|---|---|---|
| **Web アプリ**（任意のブラウザ） | FingerPrint Checker ブラウザエージェント `fp-agent.min.js` を自社ドメインから配信します。[Web アプリ](#web-アプリ)を参照 | 利用可能 |
| **Android アプリ**（Kotlin / Java） | Maven Central の `com.fpchecker:fpchecker-android`、ソースは [`android/`](android) | 利用可能、0.2.0 |
| **iOS アプリ**（Swift Package） | `https://github.com/AndrewYukon/FingerPrintChecker`、ソースは [`apple/`](apple) | 利用可能、0.2.0 |
| macOS アプリ（Swift Package） | iOS と同じパッケージ | 利用可能、0.2.0 |
| コマンドラインツール | プロトコルとサンプルは [`cli/`](cli/README.md) | サンプル |

どのプラットフォームでも最終的な流れは同じです。クライアントは `attestation` を受け取り、シークレットキーを持つ自社のバックエンドだけが判定を要求します。ネイティブ SDK のワイヤーフォーマットは [PROTOCOL.md](PROTOCOL.md) に定められており、適合性テストベクターは [`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json) にあります。すべての SDK はこれらを再現できなければなりません。

## Web アプリ

ブラウザエージェントはこのリポジトリには含まれていません。`https://fpchecker.com/static/fp-agent.min.js` から `fp-agent.min.js` をダウンロードし、**自社ドメイン**から配信してください（広告ブロッカーはサードパーティのフィンガープリントスクリプトをよくブロックしますし、エージェントのファーストパーティ ID は自社のオリジンでしか機能しません）。fpchecker.com コンソールのプロジェクトページには、キーが入力済みのこれらのスニペットが表示されます。

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

サイトのオリジンをプロジェクトの許可オリジンに追加してください。追加しないと、ブラウザからの呼び出しは拒否されます。

## Android クイックスタート

```kotlin
// build.gradle.kts (Maven Central)
dependencies {
    implementation("com.fpchecker:fpchecker-android:0.2.0")
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

Java からは `checker.identify(result -> { ... })` を使います（コールバックはメインスレッドで呼ばれます）。

要件：minSdk 23。このライブラリは `INTERNET` パーミッションを宣言しています。Play Integrity は `com.google.android.play:integrity` を使用し、`cloudProjectNumber` を渡したときにのみ使われます。利用できない場合や遅い場合（デフォルト 5 秒）でも、リクエストは証明なしで送信され、未アテステーションとして採点されます。

### デモアプリ

`android/demo` は 1 画面のアプリです。値はコミットせずに指定してください。たとえば `~/.gradle/gradle.properties` に記述します。

```
fpcheckerPk=pk_...
fpcheckerSealKey=...
fpcheckerBaseUrl=https://api.fpchecker.com
fpcheckerCloudProject=123456789012
```

ビルドとテスト（JDK 17、Android SDK 35）：

```
cd android
./gradlew :fpchecker:testDebugUnitTest :fpchecker:assembleRelease :demo:assembleDebug :demo:assembleRelease lint
```

`fpcheckerStoreFile`、`fpcheckerStorePassword`、`fpcheckerKeyAlias`、`fpcheckerKeyPassword` がすべて設定されていない限り、リリース APK は未署名です。

## iOS / macOS クイックスタート

Swift Package Manager：`https://github.com/AndrewYukon/FingerPrintChecker`（プロダクト `FingerPrintChecker`、iOS 14+、macOS 11+）を追加するか、`Package.swift` に次のように記述します。

```swift
.package(url: "https://github.com/AndrewYukon/FingerPrintChecker", from: "0.2.0")
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

`FPConfig` には `baseURL`（デフォルトは `https://api.fpchecker.com`）、`useAppAttest`、`useDeviceCheck`（どちらもデフォルトは `true`）もあります。`identify()` の同時呼び出しは直列化されます。リポジトリのルートで `swift build && swift test` を実行すると、macOS 上でユニットテストが走ります。`apple/Demo` は両プラットフォーム向けの SwiftUI デモです。[apple/Demo/README.md](apple/Demo/README.md) を参照してください。

### App Attest と DeviceCheck

- **App Attest**（実機のみ。iOS 14+、サポート対象の macOS バージョン）：SDK はインストールごとに 1 つのキーを作成し、最初のリクエストでそれをアテストし、以降はアサーションを送ります。アプリに App Attest capability を追加してください。FingerPrint Checker のプロジェクトで、アプリの Team ID と Bundle ID（および環境、`development` か `production`）を設定してください。設定しないと証明は検証されず、デバイスは未アテステーションとして採点されます。App Attest が利用できない、または失敗した場合でも、identify は証明なしで成功します。キーはサーバーがそのアテステーションを確認した後にのみ記憶されます。サーバーがキーを忘れた場合、または Apple がキーを無効と報告した場合（たとえば復元後）、SDK は同じ `identify()` 呼び出しの中で新しいキーをアテストします（サーバーが忘れた場合は追加リクエストが 1 回発生します）。そのため、呼び出し側がこれが原因で未アテステーションの結果を目にすることはありません。
- **DeviceCheck**：SDK は DeviceCheck トークンを送信し、FingerPrint Checker がデバイスごとに、すでに特典が受け取られたかどうかを記憶できるようにします。そのためには、Apple Developer アカウントで DeviceCheck キーを作成し、FingerPrint Checker のプロジェクトにアップロードしてください。アップロードしないと、トークンは無視されます。
- **受け取り済みビットは、Apple チームのすべてのアプリで共有されます。** Apple は開発者チームごと・デバイスごとに DeviceCheck ビットを 2 つしか保持しないため、FingerPrint Checker は bit 0 を「このデバイスは、このチームのいずれかのアプリで無料トライアル（デフォルト種別）をすでに受け取った」という意味で使います。トレードオフとして、あるアプリでトライアルを受け取ったデバイスは、同じチームの他のアプリでもトライアルを拒否されます。ユーザーが別のアプリで受け取った可能性があるため、拒否メッセージもそれに合わせた文言にしてください（「このデバイスはすでに無料トライアルを利用しています」など）。Bit 1 は予約されています。2 つのアプリを独立に保つ唯一の方法は、別々の Apple デベロッパーチームで公開することです。Android の Play Integrity Device Recall も同様で、そのビットは 1 つの Play デベロッパーアカウントのすべてのアプリで共有されます。
- シミュレーターはどちらの機能も持たず、`ios.simulator=true` を報告します。

## コマンドラインツール

ライブラリは不要です。CLI は任意の言語で書けます。[`cli/`](cli/README.md) には、依存関係のない Node、Python、Go のサンプルがあります（それぞれ 100 行未満）。CLI デバイスがアテステーションされることはありません。プロジェクトで PoW による人間確認を有効にしてください。

## 自社バックエンドで attestation を検証する

シールキーはアプリの中に同梱されるため、デバイス上で計算されるものはすべて、決意の固い攻撃者に偽造され得ます。成功した結果に含まれる `attestation` が、信頼すべき唯一の値です。これをバックエンドに送り、そこでシークレットキーを使って FingerPrint Checker API（たとえば `/v1/eligibility`、`/v1/quota`）で検証してください。クライアントに報告された `trustScore` や `visitorId` を根拠に権利を付与してはいけません。

## プライバシー

ストアの申告回答（Google Play のデータセーフティ、App Store の App Privacy）：[docs/PRIVACY.md](docs/PRIVACY.md)。

デバイスから外に出るデータ（Android）：

- `ANDROID_ID`（アプリ署名キー単位のスコープで、初期化によりリセットされます）。
- Widevine `deviceUniqueId` の SHA-256。生の MediaDrm ID がデバイスの外に出ることはありません。
- SIM / ネットワークの国コード、タイムゾーン、`Build.FINGERPRINT`、`Build.HARDWARE`、`Build.MODEL`、SDK レベル。
- 有効にした場合は Play Integrity トークン（Google が発行するもので、対象はユーザーではなくアプリとデバイスです）。

SDK は広告 ID、アカウント、連絡先、位置情報、電話番号、IMEI を読み取りません。インテグレーターは、プライバシーポリシーと Play のデータセーフティフォームでこれを開示する責任があります。

デバイスから外に出るデータ（iOS / macOS）：

- Keychain に保存されるランダムな UUID（このデバイス限定で、同期されず、他のデバイスにバックアップされません）。
- iOS：`identifierForVendor`。macOS：ハードウェアの `IOPlatformUUID`。
- タイムゾーン識別子、ハードウェアモデル（例：`iPhone17,1`、`Mac15,3`）、OS バージョン、シミュレーターフラグ（iOS）。
- DeviceCheck トークンの SHA-256（サーバーが Apple に問い合わせられるよう、トークン自体も送信されます）、および有効な場合は App Attest のキー ID とアテステーション/アサーションオブジェクト。

SDK は UserDefaults に 1 つのタイムスタンプ（App Attest のバックオフ）を保存します。広告 ID、位置情報、連絡先、アカウントは読み取りません。パッケージには `PrivacyInfo.xcprivacy` が同梱されており、デバイス ID の収集（ユーザーに紐付けず、トラッキングには使用しない）を宣言し、理由の申告が必要な API は使用していません。App Privacy の詳細でこれを開示してください。

## ライセンス

Apache-2.0。[LICENSE](LICENSE) を参照してください。
