plugins {
    `java-library`
    id("com.vanniktech.maven.publish") version "0.30.0"
}

group = "com.fpchecker"
version = "0.1.0"

repositories {
    mavenCentral()
}

// The publish plugin attaches the sources and javadoc jars Maven Central requires.
tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:all,-missing", "-quiet")
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 11
    options.encoding = "UTF-8"
}

dependencies {
    api("com.fasterxml.jackson.core:jackson-databind:2.17.2")

    testImplementation(platform("org.junit:junit-bom:5.10.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
    if (project.hasProperty("signingInMemoryKey") || project.hasProperty("signing.keyId")) {
        signAllPublications()
    }

    coordinates("com.fpchecker", "fpchecker-server-java", version.toString())

    pom {
        name.set("FpChecker Server SDK for Java")
        description.set("Server SDK for FingerPrintChecker: API client, sealed results, webhook verification and bot check.")
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
