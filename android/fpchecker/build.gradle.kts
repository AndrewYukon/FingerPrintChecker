plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("com.vanniktech.maven.publish")
}

val sdkVersion = "0.3.0"

kotlin {
    jvmToolchain(17)
    explicitApi()
}

android {
    namespace = "com.fpchecker"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
        buildConfigField("String", "SDK_VERSION", "\"$sdkVersion\"")
    }

    buildFeatures { buildConfig = true }

    buildTypes {
        release { isMinifyEnabled = false }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
    }

    testOptions {
        unitTests {
            // org.json is a stub in android.jar; the real implementation is a test dependency.
            isReturnDefaultValues = false
        }
    }
}

tasks.withType<Test>().configureEach {
    systemProperty("fpchecker.vectors", rootProject.projectDir.resolve("../test-vectors/protocol-v1.json").canonicalPath)
    systemProperty("fpchecker.vectors.v2", rootProject.projectDir.resolve("../test-vectors/protocol-v2.json").canonicalPath)
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.android.play:integrity:1.6.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}

mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
    if (project.hasProperty("signingInMemoryKey") || project.hasProperty("signing.keyId")) {
        signAllPublications()
    }

    coordinates("com.fpchecker", "fpchecker-android", sdkVersion)

    pom {
        name.set("FpChecker Android SDK")
        description.set("Android client SDK for the fpchecker native device identification protocol.")
        inceptionYear.set("2026")
        url.set("https://github.com/AndrewYukon/FingerPrintChecker")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("fpchecker")
                name.set("fpchecker")
                url.set("https://fpchecker.com")
            }
        }
        scm {
            url.set("https://github.com/AndrewYukon/FingerPrintChecker")
            connection.set("scm:git:git://github.com/AndrewYukon/FingerPrintChecker.git")
            developerConnection.set("scm:git:ssh://git@github.com/AndrewYukon/FingerPrintChecker.git")
        }
    }
}
