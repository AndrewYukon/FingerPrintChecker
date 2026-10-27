# FingerPrint Checker

[English](README.md) | **简体中文** | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md)

为 **Web 应用、iOS 应用和 Android 应用**（以及 macOS 应用和命令行工具）提供设备身份识别与免费试用滥用防护，由 [FingerPrint Checker](https://fpchecker.com) 提供。

你的客户端采集一小组设备信号，用 HMAC 对其封装，可选地附上平台认证（Android 上是 Play Integrity，Apple 设备上是 App Attest 和 DeviceCheck），然后得到一个稳定的 `visitorId`、一个信任分和一个 `attestation` 令牌。你自己的后端把该令牌发送给 FingerPrint Checker API，针对免费试用、优惠券、注册奖励、邀请奖励和匿名使用额度，得到 `allow`、人机验证或 `deny` 的结论。

本仓库包含开源的原生 SDK 及其使用的协议。

## 一户一次免费试用

薅羊毛的人不会只用一个浏览器：换个浏览器、换台笔记本、拿起手机、再装你的 App。只要其中一台领过，FingerPrint Checker
就会拒绝其余的。下面每一种情况都在真机上测过（一台装了三个浏览器的 Mac、一部 iPhone、两部 Android 手机、同一个家庭 Wi-Fi）：

- **一台电脑上的所有浏览器 = 一台设备。** 同一台电脑、同一个网络下的不同浏览器拿到同一个 `visitorId`。
- **同一个 Wi-Fi 下的所有设备 = 一户。** 台式机、笔记本、平板或手机里有一台在家里网络领取后，同一网络下的其余设备都会被拒绝；
  它们切到移动数据也一样，因为每台设备都会记住自己出现过的网络。
- **网站和 App 共用一个上限。** 在[控制台](https://fpchecker.com/console)里把网站项目和 iOS、Android App 项目放进同一个
  *领取组*：在网站上领过的一户，在 App 里会被拒绝，反过来也一样。
- **事后也能查出来。** 用移动数据领取、之后连上同一个家庭 Wi-Fi 的手机会被标记，你的后端用 `GET /v1/claims/flags`
  列出这些领取。系统不会自动撤销任何领取。

## 支持的平台

| 平台 | 集成方式 | 状态 |
|---|---|---|
| **Web 应用**（任意浏览器） | FingerPrint Checker 浏览器 agent `fp-agent.min.js`，部署在你自己的域名下；见 [Web 应用](#web-应用) | 可用 |
| **Android 应用**（Kotlin / Java） | Maven Central 上的 `com.fpchecker:fpchecker-android`，源码在 [`android/`](android) | 可用，0.7.0 |
| **iOS 应用**（Swift Package） | `https://github.com/AndrewYukon/FingerPrintChecker`，源码在 [`apple/`](apple) | 可用，0.7.0 |
| macOS 应用（Swift Package） | 与 iOS 使用同一个包 | 可用，0.7.0 |
| 命令行工具 | 协议 + 示例见 [`cli/`](cli/README.md) | 示例 |

所有平台的终点都一样：客户端拿到 `attestation`，只有持有密钥（secret key）的你的后端才去请求决策。原生 SDK 的传输格式在 [PROTOCOL.md](PROTOCOL.md) 中规定；一致性测试向量在 [`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json)，每个 SDK 都必须能复现这些向量。

## Web 应用

浏览器 agent 不在本仓库中。从 `https://fpchecker.com/static/fp-agent.min.js` 下载 `fp-agent.min.js`，并部署在**你自己的域名**下（广告拦截器经常拦截第三方指纹脚本，而且 agent 的第一方 id 只能在你的 origin 上工作）。fpchecker.com 控制台中你的项目页面会展示这些代码片段，并已填入你的密钥：

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

请把你网站的 origin 加入项目的允许来源列表，否则浏览器端调用会被拒绝。

## Android 快速开始

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

Java 调用方使用 `checker.identify(result -> { ... })`（回调在主线程执行）。

要求：minSdk 23。该库声明了 `INTERNET` 权限。Play Integrity 使用 `com.google.android.play:integrity`，且仅在你传入 `cloudProjectNumber` 时才会使用；如果它不可用或很慢（默认 5 秒），请求仍会在没有证明的情况下发出，并被评为未认证。

### 演示应用

`android/demo` 是一个单屏应用。请在不提交到仓库的前提下提供你的配置值，例如写在 `~/.gradle/gradle.properties` 中：

```
fpcheckerPk=pk_...
fpcheckerSealKey=...
fpcheckerBaseUrl=https://api.fpchecker.com
fpcheckerCloudProject=123456789012
```

构建与测试（JDK 17、Android SDK 35）：

```
cd android
./gradlew :fpchecker:testDebugUnitTest :fpchecker:assembleRelease :demo:assembleDebug :demo:assembleRelease lint
```

除非同时设置了 `fpcheckerStoreFile`、`fpcheckerStorePassword`、`fpcheckerKeyAlias` 和 `fpcheckerKeyPassword`，否则 release APK 不会签名。

## iOS / macOS 快速开始

Swift Package Manager：添加 `https://github.com/AndrewYukon/FingerPrintChecker`（product 为 `FingerPrintChecker`，iOS 14+、macOS 11+），或在 `Package.swift` 中：

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

`FPConfig` 还有 `baseURL`（默认 `https://api.fpchecker.com`）、`useAppAttest` 和 `useDeviceCheck`（默认均为 `true`）。并发的 `identify()` 调用会被串行化。在仓库根目录运行 `swift build && swift test` 即可在 macOS 上执行单元测试。`apple/Demo` 是同时面向两个平台的 SwiftUI 演示应用，见 [apple/Demo/README.md](apple/Demo/README.md)。

### App Attest 与 DeviceCheck

- **App Attest**（仅限真机；iOS 14+，以及受支持的 macOS 版本）：SDK 为每次安装创建一个密钥，在第一次请求时对其进行认证，之后发送断言。请为你的应用添加 App Attest capability。在你的 FingerPrint Checker 项目中配置应用的 Team ID 和 Bundle ID（以及环境，`development` 或 `production`），否则不会校验该证明，设备会被评为未认证。如果 App Attest 不可用或失败，identify 仍会成功，只是没有证明。只有在服务器确认了其认证之后，密钥才会被记住；如果服务器丢失了某个密钥，或 Apple 报告其无效（例如恢复备份之后），SDK 会在同一次 `identify()` 调用内重新认证一个新密钥（服务器丢失密钥时会多一次请求），因此调用方不会因此看到未认证的结果。
- **DeviceCheck**：SDK 会发送一个 DeviceCheck 令牌，使 FingerPrint Checker 能按设备记住是否已经领取过。为此，请在你的 Apple Developer 账号中创建一个 DeviceCheck 密钥，并上传到你的 FingerPrint Checker 项目；没有它，该令牌会被忽略。
- **已领取标记由你 Apple 团队下的所有应用共享。** Apple 对每个开发者团队的每台设备只保留两个 DeviceCheck 位，因此 FingerPrint Checker 用 bit 0 表示「这台设备已在该团队的某个应用中领取过免费试用（默认类型）」。代价是：在你的某个应用中领取过试用的设备，在同一团队的其他应用中也会被拒绝试用。请据此措辞拒绝提示（「此设备已使用过免费试用」），因为用户可能是在别处领取的。Bit 1 为保留位。要让两个应用互相独立，唯一的办法是把它们发布在不同的 Apple 开发者团队下。Android 的 Play Integrity Device Recall 同理：其位由同一个 Play 开发者账号下的所有应用共享。
- 模拟器两项功能都不支持，并会报告 `ios.simulator=true`。

## 设备完整性检测（SDK 0.7.0）

从 0.7.0 起，SDK 还会检查它所运行的设备的状态，每一项给出“是 / 否 / 未检查”之一。在支持的设备类型上，它能发现：
设备已 root 或越狱、存在 Hook 或插桩框架、模拟器、已附加调试器、开发者选项、拦截代理或不受信任的用户证书、正在使用的 VPN、
模拟（伪造）定位，以及你的应用被克隆或运行在平行空间里。macOS 应用只报告调试器和 Hook 两项。

- **开关。** Android 的 `FpCheckerConfig` 与 Swift 的 `FPConfig` 中的 `integrityProbes`（默认 `true`）。设为 `false` 时，SDK 不运行任何检测，所有项都报告为“未检查”。
- **结果去哪里。** 结果随 identify 请求一起发送，但**绝不会返回给应用**：identify 应答、`sealedResult` 和 `attestation` 都不含这些内容。
  它们只会通过事件 API（`signals.mobile`）和 webhook 到达**你的服务器**，并可用于项目规则。见[服务端 SDK](#封装结果服务端-sdk-与-web-包)。
- **三种状态。** `true` = 检测到，`false` = 已检查且未发现，`null` = 未检查（旧版 SDK、检测已关闭、该项在此设备或系统上无法运行）。检测尽力而为，两个方向都不是保证。
- **恢复出厂日期。** 字段 `factoryResetAt` 存在于服务端类型中，但属于保留字段：SDK 0.7.0 不检测恢复出厂，因此它始终为 `null`。
- **不增加权限。** SDK 不增加 `uses-permission`、不增加 `<queries>`，也不枚举设备上的应用。定位检查只使用你的应用已经持有的定位权限；在 Android 上，设备 VPN 检查只在你的应用已持有 `ACCESS_NETWORK_STATE` 时运行（SDK 不增加权限），否则 `vpn` 为 `null`。

在服务端，可按 `rooted`、`hooked`、`emulator`、`mitm`、`locationSpoofed`、`clonedApp`（`true` / `false`）过滤事件 API，并读取
`signals.mobile` 与 `signals.vpn.methods`（其中可能出现 `os_vpn`）。服务端 SDK 0.3.0 为这些字段提供了类型。

## 封装结果、服务端 SDK 与 Web 包

项目配置了封装密钥时，identify 的应答会带一个可选的 `sealedResult` 字符串（SDK 0.5.0）：Android 上是 `FpResult.Success.sealedResult` /
`FpIdentifyResult.Success.sealedResult`，iOS 和 macOS 上是 `FPSuccess.sealedResult` / `FPSuccessV2.sealedResult`。项目没有密钥，或服务端版本较旧时为
`null` / `nil`。把它转交给你自己的后端，由后端用项目密钥打开（不要在设备上打开）。

| 包 | 位置 | 安装 |
|---|---|---|
| Node.js 服务端 SDK，`@fingerprintchecker/node` | [`server/node`](server/node) | `npm install @fingerprintchecker/node` |
| Python 服务端 SDK，`fpchecker` | [`server/python`](server/python) | `pip install fingerprintchecker` |
| Go 服务端 SDK | [`server/go`](server/go) | `go get github.com/AndrewYukon/FingerPrintChecker/server/go` |
| Java 服务端 SDK，`com.fpchecker:fpchecker-server-java` | [`server/java`](server/java) | Maven Central：`com.fpchecker:fpchecker-server-java:0.1.0` |
| PHP 服务端 SDK，`fpchecker/fpchecker-php` | [`server/php`](server/php) | 从 GitHub release 的 zip 安装，见 [server/php/README.md](server/php/README.md) |
| .NET 服务端 SDK，`FingerPrintChecker.Server` | [`server/dotnet`](server/dotnet) | 从 GitHub release 的 .nupkg 安装，见 [server/dotnet/README.md](server/dotnet/README.md) |
| 浏览器 agent 加载器，`@fingerprintchecker/agent` | [`web/agent`](web/agent) | `npm install @fingerprintchecker/agent` |
| React 封装，`@fingerprintchecker/react` | [`web/react`](web/react) | `npm install @fingerprintchecker/react` |
| Vue 封装，`@fingerprintchecker/vue` | [`web/vue`](web/vue) | `npm install @fingerprintchecker/vue` |

这些包尚未发布到 npm 和 PyPI（PHP 和 .NET 在上架 Packagist / nuget.org 前，从 GitHub release 获取）。发布前请从 GitHub 安装：克隆本仓库后执行 `npm install ./web/agent`（或 `./server/node` 等）/
`pip install ./server/python`；Go 用 `go get github.com/AndrewYukon/FingerPrintChecker/server/go@main`。

Cloudflare Worker proxy (English): [integrations/cloudflare-worker](integrations/cloudflare-worker/README.md)

## 命令行工具

不需要库：CLI 可以用任何语言编写。[`cli/`](cli/README.md) 提供了无依赖的 Node、Python 和 Go 示例（每个不超过 100 行）。CLI 设备永远不会被认证；请为项目启用 PoW 人机验证。

## 在你自己的后端验证 attestation

seal key 随你的应用一起分发，因此任何在设备上计算出的内容都可能被有决心的攻击者伪造。成功结果中的 `attestation` 是你唯一应该信任的值：把它发送到你的后端，并在那里使用你的 secret key 通过 FingerPrint Checker API（例如 `/v1/eligibility`、`/v1/quota`）进行验证。不要依据客户端上报的 `trustScore` 或 `visitorId` 来控制权益。

0.35 及以上版本的服务器对 v1 `identify()` 返回密封的 `attestation`（`{ "token": "fpa1.…" }`），客户端无法读取；除非项目的 `scoreDetails` 策略为 `live` 或 `all`（默认 `none`），否则不会返回 `trustScore`、`identityConfidence`、`breakdown` 等分数字段，因此 SDK 0.3.0 起 v1 的 `trustScore` 和 `identityConfidence` 为可选值（`Int?` / `null`）。请原样把 attestation 转发给你的后端，并在后端从 `/v1/eligibility` 的响应中读取 `visitorId`、`isNew`、`trustScore` 和 `identityConfidence`。

## 隐私

应用商店披露问卷的填写参考（Google Play 数据安全、App Store 应用隐私）：[docs/PRIVACY.md](docs/PRIVACY.md)。

离开设备的数据（Android）：

- `ANDROID_ID`（作用域限于应用签名密钥，恢复出厂设置会重置）。
- Widevine `deviceUniqueId` 的 SHA-256。原始的 MediaDrm id 永远不会离开设备。
- SIM / 网络国家代码、时区、`Build.FINGERPRINT`、`Build.HARDWARE`、`Build.MODEL`、SDK 级别。
- 如果启用，还有一个 Play Integrity 令牌（Google 签发的内容针对应用和设备，而非用户）。

SDK 不会读取广告 id、账号、联系人、电话号码或 IMEI，也从不发送坐标（见下文的完整性检测段落）。作为集成方，你有责任在你的隐私政策和 Play 数据安全表单中披露这些内容。

离开设备的数据（iOS / macOS）：

- 存储在 Keychain 中的随机 UUID（仅限此设备，不同步，不会备份到其他设备）。
- iOS：`identifierForVendor`。macOS：硬件 `IOPlatformUUID`。
- 时区标识符、硬件型号（例如 `iPhone17,1`、`Mac15,3`）、操作系统版本、模拟器标志（iOS）。
- DeviceCheck 令牌的 SHA-256（令牌本身也会发送，以便服务器向 Apple 查询），以及在启用时的 App Attest 密钥 id 和认证/断言对象。

SDK 在 UserDefaults 中只存储一个时间戳（App Attest 退避）。不会读取广告 id、联系人或账号，也不发送坐标。该包附带 `PrivacyInfo.xcprivacy`，声明收集设备 ID（不关联用户、不用于跟踪），并且只使用一个需声明原因的 API（`UserDefaults`，原因 `CA92.1`，用于 App Attest 退避时间戳）。请在你的 App Privacy 详情中披露这些内容。

完整性检测新增的内容（SDK 0.7.0）：只有设备状态布尔值（检测到 / 未检测到 / 未检查）和一个检测版本号，用于安全与反欺诈，不用于跟踪。
SDK 不收集也不发送坐标、已安装应用列表、证书、代理地址或文件路径。Google Play **数据安全**表单仍沿用已有的“设备或其他 ID”答案
（用途：欺诈预防、安全和合规）；App Store **App 隐私**中没有新增的跟踪项，已有的设备 ID 条目（不用于跟踪）仍然适用。详见 [docs/PRIVACY.md](docs/PRIVACY.md)。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
