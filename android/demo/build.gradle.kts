plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

fun prop(name: String): String = (project.findProperty(name) as String?).orEmpty()

fun buildConfigString(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

kotlin { jvmToolchain(17) }

android {
    namespace = "com.fpchecker.demo"
    // 36 for the demo only: Play requires targetSdk 36 for new releases. The library stays on 35.
    compileSdk = 36

    defaultConfig {
        applicationId = "com.fpchecker.demo"
        // 24, not the library's 23: Play automatic protection refuses bundles below 24.
        minSdk = 24
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.0"

        // Populated from gradle properties (-P or ~/.gradle/gradle.properties). Never commit real values.
        buildConfigField("String", "FP_PK", buildConfigString(prop("fpcheckerPk")))
        buildConfigField("String", "FP_SEAL_KEY", buildConfigString(prop("fpcheckerSealKey")))
        buildConfigField("String", "FP_BASE_URL", buildConfigString(prop("fpcheckerBaseUrl")))
        buildConfigField("String", "FP_CLOUD_PROJECT", buildConfigString(prop("fpcheckerCloudProject")))
        // Optional, enables "Identify v2": backend endpoint answering POST {} with {"intentToken": "..."}.
        buildConfigField("String", "FP_INTENT_URL", buildConfigString(prop("fpcheckerIntentUrl")))
    }

    buildFeatures { buildConfig = true }

    // Release is signed only when all four properties are provided; otherwise it stays unsigned.
    val storeFile = prop("fpcheckerStoreFile")
    val hasSigning = storeFile.isNotEmpty() && prop("fpcheckerStorePassword").isNotEmpty() &&
        prop("fpcheckerKeyAlias").isNotEmpty() && prop("fpcheckerKeyPassword").isNotEmpty()

    signingConfigs {
        if (hasSigning) {
            create("release") {
                this.storeFile = file(storeFile)
                storePassword = prop("fpcheckerStorePassword")
                keyAlias = prop("fpcheckerKeyAlias")
                keyPassword = prop("fpcheckerKeyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (hasSigning) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint { abortOnError = true }
}

dependencies {
    implementation(project(":fpchecker"))
}
