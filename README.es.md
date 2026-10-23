# FingerPrint Checker

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | **Español** | [Français](README.fr.md)

Identidad de dispositivo y protección contra el abuso de pruebas gratuitas para **aplicaciones web, aplicaciones iOS y aplicaciones Android** (además de aplicaciones macOS y herramientas de línea de comandos), de [FingerPrint Checker](https://fpchecker.com).

Tu cliente recopila un pequeño conjunto de señales del dispositivo, las sella con un HMAC, adjunta opcionalmente una atestación de la plataforma (Play Integrity en Android, App Attest y DeviceCheck en dispositivos Apple) y recibe un `visitorId` estable, una puntuación de confianza y un token `attestation`. Tu propio backend envía ese token a la API de FingerPrint Checker y obtiene `allow`, una verificación humana o `deny` para pruebas gratuitas, cupones, bonos de registro, recompensas por invitación y límites de uso anónimo.

Este repositorio contiene los SDK nativos de código abierto y el protocolo que utilizan.

## Plataformas compatibles

| Plataforma | Cómo integrarla | Estado |
|---|---|---|
| **Aplicaciones web** (cualquier navegador) | El agente de navegador de FingerPrint Checker `fp-agent.min.js`, servido desde tu propio dominio; consulta [Aplicaciones web](#aplicaciones-web) | Disponible |
| **Aplicaciones Android** (Kotlin / Java) | `com.fpchecker:fpchecker-android` en Maven Central, código fuente en [`android/`](android) | Disponible, 0.3.0 |
| **Aplicaciones iOS** (Swift Package) | `https://github.com/AndrewYukon/FingerPrintChecker`, código fuente en [`apple/`](apple) | Disponible, 0.3.0 |
| Aplicaciones macOS (Swift Package) | El mismo paquete que iOS | Disponible, 0.3.0 |
| Herramientas de línea de comandos | Protocolo + ejemplos en [`cli/`](cli/README.md) | Ejemplos |

Todas las plataformas terminan igual: el cliente obtiene un `attestation`, y solo tu backend, que posee tu clave secreta, solicita una decisión. El formato de transmisión de los SDK nativos se especifica en [PROTOCOL.md](PROTOCOL.md); los vectores de conformidad están en [`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json) y todos los SDK deben reproducirlos.

## Aplicaciones web

El agente de navegador no forma parte de este repositorio. Descarga `fp-agent.min.js` desde `https://fpchecker.com/static/fp-agent.min.js` y sírvelo desde **tu propio dominio** (los bloqueadores de anuncios suelen bloquear los scripts de huella digital de terceros, y el id de origen propio del agente solo funciona en tu origen). La página de tu proyecto en la consola de fpchecker.com muestra estos fragmentos con tus claves ya rellenadas:

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

Añade el origen de tu sitio a los orígenes permitidos del proyecto; de lo contrario, la llamada desde el navegador será rechazada.

## Inicio rápido en Android

```kotlin
// build.gradle.kts (Maven Central)
dependencies {
    implementation("com.fpchecker:fpchecker-android:0.3.0")
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

Los llamadores en Java usan `checker.identify(result -> { ... })` (callback en el hilo principal).

Requisitos: minSdk 23. La biblioteca declara el permiso `INTERNET`. Play Integrity usa `com.google.android.play:integrity` y solo se utiliza cuando pasas `cloudProjectNumber`; si no está disponible o es lento (5 s por defecto), la solicitud se envía igualmente sin prueba y se puntúa como no atestada.

### Aplicación de demostración

`android/demo` es una aplicación de una sola pantalla. Proporciona tus valores sin subirlos al repositorio, por ejemplo en `~/.gradle/gradle.properties`:

```
fpcheckerPk=pk_...
fpcheckerSealKey=...
fpcheckerBaseUrl=https://api.fpchecker.com
fpcheckerCloudProject=123456789012
```

Compilar y probar (JDK 17, Android SDK 35):

```
cd android
./gradlew :fpchecker:testDebugUnitTest :fpchecker:assembleRelease :demo:assembleDebug :demo:assembleRelease lint
```

El APK de release queda sin firmar a menos que `fpcheckerStoreFile`, `fpcheckerStorePassword`, `fpcheckerKeyAlias` y `fpcheckerKeyPassword` estén todos definidos.

## Inicio rápido en iOS / macOS

Swift Package Manager: añade `https://github.com/AndrewYukon/FingerPrintChecker` (producto `FingerPrintChecker`, iOS 14+, macOS 11+), o en `Package.swift`:

```swift
.package(url: "https://github.com/AndrewYukon/FingerPrintChecker", from: "0.3.0")
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

`FPConfig` también tiene `baseURL` (por defecto `https://api.fpchecker.com`), `useAppAttest` y `useDeviceCheck` (ambos `true` por defecto). Las llamadas concurrentes a `identify()` se serializan. `swift build && swift test` en la raíz del repositorio ejecutan las pruebas unitarias en macOS. `apple/Demo` es una demo en SwiftUI para ambas plataformas, consulta [apple/Demo/README.md](apple/Demo/README.md).

### App Attest y DeviceCheck

- **App Attest** (solo dispositivos reales; iOS 14+, versiones de macOS compatibles): el SDK crea una clave por instalación, la atesta en la primera solicitud y envía aserciones después. Añade la capability de App Attest a tu aplicación. En tu proyecto de FingerPrint Checker configura el Team ID y el Bundle ID de tu aplicación (y el entorno, `development` o `production`); de lo contrario la prueba no se comprueba y el dispositivo se puntúa como no atestado. Si App Attest no está disponible o falla, identify tiene éxito igualmente sin prueba. Una clave solo se recuerda después de que el servidor haya confirmado su atestación; si el servidor olvida una clave, o Apple la informa como inválida (por ejemplo, tras una restauración), el SDK atesta una nueva dentro de la misma llamada a `identify()` (una solicitud adicional cuando el servidor la olvidó), de modo que el llamador nunca ve por ello un resultado no atestado.
- **DeviceCheck**: el SDK envía un token de DeviceCheck para que FingerPrint Checker pueda recordar, por dispositivo, si ya se hizo un canje. Para ello, crea una clave de DeviceCheck en tu cuenta de Apple Developer y súbela a tu proyecto de FingerPrint Checker; sin ella, el token se ignora.
- **El bit de canje lo comparten todas las aplicaciones de tu equipo de Apple.** Apple solo conserva dos bits de DeviceCheck por dispositivo y por equipo de desarrollo, así que FingerPrint Checker usa el bit 0 para significar «este dispositivo ya canjeó una prueba gratuita (tipo por defecto) en una de las aplicaciones de este equipo». La contrapartida: un dispositivo que canjeó la prueba en una de tus aplicaciones tendrá la prueba rechazada en tus otras aplicaciones del mismo equipo. Redacta el rechazo en consecuencia («este dispositivo ya ha usado una prueba gratuita»), ya que el usuario puede haberla canjeado en otra aplicación. El bit 1 está reservado. La única forma de mantener dos aplicaciones independientes es publicarlas bajo equipos de desarrollador de Apple distintos. El Device Recall de Play Integrity en Android funciona igual: sus bits los comparten todas las aplicaciones de una misma cuenta de desarrollador de Play.
- Los simuladores no tienen ninguna de las dos funciones e informan `ios.simulator=true`.

## Herramientas de línea de comandos

Sin biblioteca: una CLI se puede escribir en cualquier lenguaje. [`cli/`](cli/README.md) incluye ejemplos sin dependencias para Node, Python y Go (menos de 100 líneas cada uno). Los dispositivos CLI nunca se atestan; activa la verificación humana PoW para el proyecto.

## Verifica el attestation en TU backend

La seal key viaja dentro de tu aplicación, así que cualquier cosa calculada en el dispositivo puede ser falsificada por un atacante decidido. El `attestation` de un resultado exitoso es el único valor en el que debes confiar: envíalo a tu backend y verifícalo allí con la API de FingerPrint Checker (por ejemplo `/v1/eligibility`, `/v1/quota`) usando tu secret key. No condiciones los derechos de acceso a `trustScore` ni a `visitorId` tal como se informan al cliente.

Los servidores desde la 0.35 responden al `identify()` v1 con un `attestation` sellado (`{ "token": "fpa1.…" }`) que el cliente no puede leer, y omiten `trustScore`, `identityConfidence`, `breakdown` y los demás campos de puntuación salvo que la política `scoreDetails` del proyecto sea `live` o `all` (por defecto `none`). Por eso, desde el SDK 0.3.0, `trustScore` e `identityConfidence` de v1 son opcionales (`Int?` / `null`). Reenvía el attestation a tu backend sin modificarlo y lee allí `visitorId`, `isNew`, `trustScore` e `identityConfidence` de la respuesta de `/v1/eligibility`.

## Privacidad

Respuestas para las declaraciones de las tiendas (Seguridad de los datos de Google Play, Privacidad de la app de App Store): [docs/PRIVACY.md](docs/PRIVACY.md).

Qué sale del dispositivo (Android):

- `ANDROID_ID` (con alcance limitado a la clave de firma de la aplicación, se restablece con un restablecimiento de fábrica).
- Un SHA-256 del `deviceUniqueId` de Widevine. El id bruto de MediaDrm nunca sale del dispositivo.
- Códigos de país de la SIM / de la red, zona horaria, `Build.FINGERPRINT`, `Build.HARDWARE`, `Build.MODEL`, nivel de SDK.
- Si está activado, un token de Play Integrity (que Google emite sobre la aplicación y el dispositivo, no sobre el usuario).

El SDK no lee el id de publicidad, las cuentas, los contactos, la ubicación, el número de teléfono ni el IMEI. Como integrador, eres responsable de divulgarlo en tu política de privacidad y en el formulario de Seguridad de los datos de Play.

Qué sale del dispositivo (iOS / macOS):

- Un UUID aleatorio almacenado en el Keychain (solo este dispositivo, no sincronizado, sin copia de seguridad en otros dispositivos).
- iOS: `identifierForVendor`. macOS: el `IOPlatformUUID` del hardware.
- Identificador de zona horaria, modelo de hardware (por ejemplo `iPhone17,1`, `Mac15,3`), versión del sistema operativo, indicador de simulador (iOS).
- Un SHA-256 del token de DeviceCheck (el token en sí se envía para que el servidor pueda consultar a Apple), y el id de clave y los objetos de atestación/aserción de App Attest, cuando están activados.

El SDK guarda una marca de tiempo en UserDefaults (espera de App Attest). No se lee ningún id de publicidad, ubicación, contactos ni cuentas. El paquete incluye un `PrivacyInfo.xcprivacy` que declara la recopilación de Device ID (sin vincular al usuario, no usado para seguimiento) y ninguna API que requiera declarar motivo. Divulga esto en los detalles de Privacidad de la app.

## Licencia

Apache-2.0, consulta [LICENSE](LICENSE).
