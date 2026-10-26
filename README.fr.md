# FingerPrint Checker

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [Español](README.es.md) | **Français**

Identité d'appareil et protection contre l'abus des essais gratuits pour les **applications web, les applications iOS et les applications Android** (ainsi que les applications macOS et les outils en ligne de commande), par [FingerPrint Checker](https://fpchecker.com).

Votre client collecte un petit ensemble de signaux de l'appareil, les scelle avec un HMAC, joint éventuellement une attestation de la plateforme (Play Integrity sur Android, App Attest et DeviceCheck sur les appareils Apple), et reçoit un `visitorId` stable, un score de confiance et un jeton `attestation`. Votre propre backend envoie ce jeton à l'API FingerPrint Checker et obtient `allow`, une vérification humaine ou `deny` pour les essais gratuits, les coupons, les bonus d'inscription, les récompenses de parrainage et les limites d'usage anonyme.

Ce dépôt contient les SDK natifs open source et le protocole qu'ils utilisent.

## Un foyer, un essai gratuit

Ceux qui abusent des essais gratuits ne s'arrêtent pas à un navigateur. Ils essaient un autre navigateur, puis
l'ordinateur portable, puis le téléphone, puis votre app. FingerPrint Checker les refuse tous dès que l'un d'eux a
réclamé. Chaque cas a été testé sur de vrais appareils (un Mac avec trois navigateurs, un iPhone, deux téléphones Android
et un même Wi-Fi domestique) :

- **Tous les navigateurs d'un ordinateur sont un seul appareil.** Des navigateurs différents sur le même ordinateur
  et le même réseau reçoivent le même `visitorId`.
- **Tous les appareils d'un Wi-Fi comptent comme un foyer.** Dès qu'un ordinateur, portable, tablette ou téléphone a
  réclamé sur le réseau de la maison, les autres appareils de ce réseau sont refusés, même après être passés en données
  mobiles, car chaque appareil se souvient des réseaux où il a été vu.
- **Votre site et vos apps partagent une limite.** Placez le projet web et les projets des apps iOS et Android dans un
  même *groupe de réclamations* dans la [console](https://fpchecker.com/console). Un foyer qui a réclamé sur le site
  est refusé dans l'app, et inversement.
- **Repéré après coup aussi.** Un téléphone qui a réclamé en données mobiles puis rejoint le même Wi-Fi domestique est
  signalé. Votre backend liste ces réclamations avec `GET /v1/claims/flags`. Rien n'est révoqué automatiquement.

## Plateformes prises en charge

| Plateforme | Comment l'intégrer | Statut |
|---|---|---|
| **Applications web** (tout navigateur) | L'agent navigateur FingerPrint Checker `fp-agent.min.js`, servi depuis votre propre domaine ; voir [Applications web](#applications-web) | Disponible |
| **Applications Android** (Kotlin / Java) | `com.fpchecker:fpchecker-android` sur Maven Central, sources dans [`android/`](android) | Disponible, 0.7.0 |
| **Applications iOS** (Swift Package) | `https://github.com/AndrewYukon/FingerPrintChecker`, sources dans [`apple/`](apple) | Disponible, 0.7.0 |
| Applications macOS (Swift Package) | Même paquet qu'iOS | Disponible, 0.7.0 |
| Outils en ligne de commande | Protocole + exemples dans [`cli/`](cli/README.md) | Exemples |

Toutes les plateformes se terminent de la même façon : le client obtient un `attestation`, et seul votre backend, qui détient votre clé secrète, demande une décision. Le format d'échange des SDK natifs est spécifié dans [PROTOCOL.md](PROTOCOL.md) ; les vecteurs de conformité se trouvent dans [`test-vectors/protocol-v1.json`](test-vectors/protocol-v1.json) et chaque SDK doit les reproduire.

## Applications web

L'agent navigateur ne fait pas partie de ce dépôt. Téléchargez `fp-agent.min.js` depuis `https://fpchecker.com/static/fp-agent.min.js` et servez-le depuis **votre propre domaine** (les bloqueurs de publicités bloquent souvent les scripts de fingerprinting tiers, et l'identifiant first-party de l'agent ne fonctionne que sur votre origine). La page de votre projet dans la console fpchecker.com affiche ces extraits avec vos clés déjà renseignées :

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

Ajoutez l'origine de votre site aux origines autorisées du projet, sinon l'appel depuis le navigateur est refusé.

## Démarrage rapide Android

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

Les appelants Java utilisent `checker.identify(result -> { ... })` (callback sur le thread principal).

Prérequis : minSdk 23. La bibliothèque déclare la permission `INTERNET`. Play Integrity utilise `com.google.android.play:integrity` et n'est utilisé que lorsque vous passez `cloudProjectNumber` ; s'il est indisponible ou lent (5 s par défaut), la requête est tout de même envoyée sans preuve et est notée comme non attestée.

### Application de démonstration

`android/demo` est une application d'un seul écran. Fournissez vos valeurs sans les committer, par exemple dans `~/.gradle/gradle.properties` :

```
fpcheckerPk=pk_...
fpcheckerSealKey=...
fpcheckerBaseUrl=https://api.fpchecker.com
fpcheckerCloudProject=123456789012
```

Compiler et tester (JDK 17, Android SDK 35) :

```
cd android
./gradlew :fpchecker:testDebugUnitTest :fpchecker:assembleRelease :demo:assembleDebug :demo:assembleRelease lint
```

L'APK de release n'est pas signé, sauf si `fpcheckerStoreFile`, `fpcheckerStorePassword`, `fpcheckerKeyAlias` et `fpcheckerKeyPassword` sont tous définis.

## Démarrage rapide iOS / macOS

Swift Package Manager : ajoutez `https://github.com/AndrewYukon/FingerPrintChecker` (produit `FingerPrintChecker`, iOS 14+, macOS 11+), ou dans `Package.swift` :

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

`FPConfig` possède aussi `baseURL` (par défaut `https://api.fpchecker.com`), `useAppAttest` et `useDeviceCheck` (tous deux à `true` par défaut). Les appels concurrents à `identify()` sont sérialisés. `swift build && swift test` à la racine du dépôt exécutent les tests unitaires sur macOS. `apple/Demo` est une démo SwiftUI pour les deux plateformes, voir [apple/Demo/README.md](apple/Demo/README.md).

### App Attest et DeviceCheck

- **App Attest** (appareils réels uniquement ; iOS 14+, versions de macOS prises en charge) : le SDK crée une clé par installation, l'atteste à la première requête, puis envoie des assertions ensuite. Ajoutez la capability App Attest à votre application. Dans votre projet FingerPrint Checker, configurez le Team ID et le Bundle ID de votre application (et l'environnement, `development` ou `production`), sinon la preuve n'est pas vérifiée et l'appareil est noté comme non attesté. Si App Attest est indisponible ou échoue, identify réussit quand même sans preuve. Une clé n'est mémorisée qu'après que le serveur a confirmé son attestation ; si le serveur oublie une clé, ou si Apple la signale comme invalide (par exemple après une restauration), le SDK en atteste une nouvelle au sein du même appel à `identify()` (une requête supplémentaire lorsque le serveur l'a oubliée), de sorte que l'appelant ne voit jamais de résultat non attesté à ce titre.
- **DeviceCheck** : le SDK envoie un jeton DeviceCheck afin que FingerPrint Checker puisse mémoriser, par appareil, si une réclamation a déjà été faite. Pour cela, créez une clé DeviceCheck dans votre compte Apple Developer et téléversez-la dans votre projet FingerPrint Checker ; sans elle, le jeton est ignoré.
- **Le bit de réclamation est partagé par toutes les applications de votre équipe Apple.** Apple ne conserve que deux bits DeviceCheck par appareil et par équipe de développement, donc FingerPrint Checker utilise le bit 0 pour signifier « cet appareil a déjà réclamé un essai gratuit (type par défaut) dans l'une des applications de cette équipe ». Le compromis : un appareil qui a réclamé l'essai dans l'une de vos applications se voit refuser l'essai dans vos autres applications de la même équipe. Formulez le refus en conséquence (« cet appareil a déjà utilisé un essai gratuit »), car l'utilisateur peut l'avoir réclamé ailleurs. Le bit 1 est réservé. Le seul moyen de garder deux applications indépendantes est de les publier sous des équipes de développeur Apple distinctes. Le Device Recall de Play Integrity sur Android fonctionne de la même façon : ses bits sont partagés par toutes les applications d'un même compte développeur Play.
- Les simulateurs n'ont aucune de ces deux fonctionnalités et signalent `ios.simulator=true`.

## Sondes d'intégrité de l'appareil (SDK 0.7.0)

Depuis la 0.7.0, le SDK vérifie aussi l'état de l'appareil sur lequel il s'exécute et rapporte une réponse oui / non / non vérifié par élément.
Sur les types d'appareils compatibles, il détecte : un appareil rooté ou jailbreaké, des frameworks de hooking ou d'instrumentation,
un émulateur ou simulateur, un débogueur attaché, les options pour les développeurs, un proxy d'interception ou des certificats utilisateur non fiables,
un VPN actif, des positions simulées (falsifiées) et une copie clonée ou en espace parallèle de votre app. Une app macOS ne rapporte que le débogueur et le hooking.

- **Interrupteur.** `integrityProbes` (par défaut `true`) dans `FpCheckerConfig` côté Android et `FPConfig` côté Swift. Avec `false`, le SDK n'exécute aucune sonde et rapporte tous les éléments comme « non vérifié ».
- **Où vont les résultats.** Ils sont envoyés avec la requête identify mais **ne sont jamais renvoyés à l'app** : la réponse identify, le `sealedResult` et l'`attestation` ne les contiennent pas.
  Ils n'arrivent sur **votre serveur** que par l'API d'événements (`signals.mobile`) et les webhooks, et peuvent alimenter les règles du projet. Voir [SDK serveur](#résultats-scellés-sdk-serveur-et-paquets-web).
- **Trois états.** `true` = détecté, `false` = vérifié et rien trouvé, `null` = non vérifié (ancien SDK, sondes désactivées, élément qui ne peut pas s'exécuter sur cet appareil ou ce système). La détection est faite au mieux et n'est une garantie dans aucun sens.
- **Date de réinitialisation.** Le champ `factoryResetAt` existe dans les types serveur mais il est réservé : le SDK 0.7.0 ne détecte pas les réinitialisations d'usine, il vaut donc toujours `null`.
- **Aucune nouvelle permission.** Le SDK n'ajoute ni `uses-permission` ni `<queries>` et n'énumère pas les apps de l'appareil. La vérification de position n'utilise qu'une permission de localisation que votre app détient déjà, et sur Android la vérification VPN de l'appareil ne s'exécute que si votre app détient déjà `ACCESS_NETWORK_STATE` (le SDK n'ajoute aucune permission) ; sinon `vpn` vaut `null`.

Côté serveur, filtrez l'API d'événements par `rooted`, `hooked`, `emulator`, `mitm`, `locationSpoofed` et `clonedApp` (`true` / `false`) et lisez
`signals.mobile` et `signals.vpn.methods` (qui peut contenir `os_vpn`). Les SDK serveur 0.3.0 typent ces champs.

## Résultats scellés, SDK serveur et paquets web

Quand votre projet a une clé de scellement, les réponses d'identify portent une chaîne facultative `sealedResult` (SDK 0.5.0) :
`FpResult.Success.sealedResult` / `FpIdentifyResult.Success.sealedResult` sur Android, `FPSuccess.sealedResult` / `FPSuccessV2.sealedResult`
sur iOS et macOS. Elle vaut `null` / `nil` si le projet n'a pas de clé ou si le serveur est plus ancien. Transmettez-la à VOTRE backend, qui
l'ouvre avec la clé du projet (jamais sur l'appareil).

| Paquet | Où | Installation |
|---|---|---|
| SDK serveur Node.js, `@fingerprintchecker/node` | [`server/node`](server/node) | `npm install @fingerprintchecker/node` |
| SDK serveur Python, `fpchecker` | [`server/python`](server/python) | `pip install fingerprintchecker` |
| SDK serveur Go | [`server/go`](server/go) | `go get github.com/AndrewYukon/FingerPrintChecker/server/go` |
| Chargeur de l'agent navigateur, `@fingerprintchecker/agent` | [`web/agent`](web/agent) | `npm install @fingerprintchecker/agent` |
| Wrapper React, `@fingerprintchecker/react` | [`web/react`](web/react) | `npm install @fingerprintchecker/react` |
| Wrapper Vue, `@fingerprintchecker/vue` | [`web/vue`](web/vue) | `npm install @fingerprintchecker/vue` |

Ces paquets ne sont pas encore publiés sur npm ni PyPI. D'ici là, installez-les depuis GitHub : clonez ce dépôt puis lancez
`npm install ./web/agent` (ou `./server/node`, ...) / `pip install ./server/python` ; pour Go, `go get github.com/AndrewYukon/FingerPrintChecker/server/go@main`.

Cloudflare Worker proxy (English): [integrations/cloudflare-worker](integrations/cloudflare-worker/README.md)

## Outils en ligne de commande

Pas de bibliothèque : une CLI peut être écrite dans n'importe quel langage. [`cli/`](cli/README.md) contient des exemples sans dépendance pour Node, Python et Go (moins de 100 lignes chacun). Les appareils CLI ne sont jamais attestés ; activez la vérification humaine PoW pour le projet.

## Vérifiez l'attestation sur VOTRE backend

La seal key est embarquée dans votre application, donc tout ce qui est calculé sur l'appareil peut être falsifié par un attaquant déterminé. L'`attestation` d'un résultat réussi est la seule valeur à laquelle vous devez faire confiance : envoyez-la à votre backend et vérifiez-la là-bas avec l'API FingerPrint Checker (par exemple `/v1/eligibility`, `/v1/quota`) en utilisant votre secret key. Ne conditionnez pas les droits d'accès à `trustScore` ou `visitorId` tels que rapportés au client.

Les serveurs à partir de la 0.35 répondent à `identify()` v1 par un `attestation` scellé (`{ "token": "fpa1.…" }`) que le client ne peut pas lire, et omettent `trustScore`, `identityConfidence`, `breakdown` et les autres champs de score, sauf si la politique `scoreDetails` du projet vaut `live` ou `all` (`none` par défaut). C'est pourquoi, depuis le SDK 0.3.0, `trustScore` et `identityConfidence` de v1 sont optionnels (`Int?` / `null`). Transmettez l'attestation telle quelle à votre backend et lisez-y `visitorId`, `isNew`, `trustScore` et `identityConfidence` dans la réponse de `/v1/eligibility`.

## Confidentialité

Réponses pour les déclarations des stores (Sécurité des données de Google Play, Confidentialité des apps de l'App Store) : [docs/PRIVACY.md](docs/PRIVACY.md).

Ce qui quitte l'appareil (Android) :

- `ANDROID_ID` (limité à la clé de signature de l'application, réinitialisable par une réinitialisation d'usine).
- Un SHA-256 du `deviceUniqueId` Widevine. L'identifiant MediaDrm brut ne quitte jamais l'appareil.
- Codes pays de la SIM / du réseau, fuseau horaire, `Build.FINGERPRINT`, `Build.HARDWARE`, `Build.MODEL`, niveau de SDK.
- Si activé, un jeton Play Integrity (que Google émet à propos de l'application et de l'appareil, pas de l'utilisateur).

Le SDK ne lit ni l'identifiant publicitaire, ni les comptes, ni les contacts, ni le numéro de téléphone, ni l'IMEI, et n'envoie jamais de coordonnées (voir le paragraphe sur l'intégrité plus bas). En tant qu'intégrateur, vous êtes responsable de le déclarer dans votre politique de confidentialité et dans le formulaire Sécurité des données de Play.

Ce qui quitte l'appareil (iOS / macOS) :

- Un UUID aléatoire stocké dans le Keychain (cet appareil uniquement, non synchronisé, non sauvegardé vers d'autres appareils).
- iOS : `identifierForVendor`. macOS : l'`IOPlatformUUID` matériel.
- Identifiant du fuseau horaire, modèle matériel (par exemple `iPhone17,1`, `Mac15,3`), version de l'OS, indicateur de simulateur (iOS).
- Un SHA-256 du jeton DeviceCheck (le jeton lui-même est envoyé afin que le serveur puisse interroger Apple), ainsi que l'identifiant de clé et les objets d'attestation/assertion App Attest, lorsqu'ils sont activés.

Le SDK stocke un horodatage dans UserDefaults (temporisation App Attest). Aucun identifiant publicitaire, contact ou compte n'est lu, et aucune coordonnée n'est envoyée. Le paquet inclut un `PrivacyInfo.xcprivacy` déclarant la collecte du Device ID (non lié à l'utilisateur, non utilisé pour le suivi) et son unique usage d'une API à raison obligatoire (`UserDefaults`, raison `CA92.1`, pour l'horodatage de temporisation App Attest). Déclarez-le dans vos détails de Confidentialité des apps.

Ce qu'ajoutent les sondes d'intégrité (SDK 0.7.0) : uniquement des booléens d'état de l'appareil (détecté / non détecté / non vérifié) et un numéro de version des sondes, utilisés pour la sécurité et la prévention de la fraude, pas pour le suivi.
Le SDK ne collecte ni n'envoie de coordonnées, la liste des apps installées, de certificats, d'adresses de proxy ni de chemins de fichiers. Pour la **Sécurité des données** de Google Play, la réponse existante « Identifiants d'appareil ou autres » reste valable
(finalité : prévention de la fraude, sécurité et conformité) ; pour la **Confidentialité des apps** d'App Store, rien de nouveau n'est utilisé pour le suivi et l'entrée Device ID existante (non utilisée pour le suivi) décrit toujours le SDK. Détails : [docs/PRIVACY.md](docs/PRIVACY.md).

## Licence

Apache-2.0, voir [LICENSE](LICENSE).
