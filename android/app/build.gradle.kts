plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.remiband"
    compileSdk = 34

    // ------------------------------------------------------------------
    // A STABLE signing key, so a new build replaces the installed app.
    //
    // Gradle otherwise generates a fresh debug keystore on every machine it
    // builds on, and GitHub runners are disposable -- so every CI run produced
    // a different certificate and Android refused the install ("app not
    // installed"), forcing an uninstall that wipes settings. One committed key
    // fixes that permanently.
    //
    // Trade-off, stated plainly: anyone who can write to this repo can sign a
    // build that this app will accept as an update. That is acceptable for a
    // personal sideloaded app and unacceptable for anything distributed; for
    // distribution, move the keystore to a repository secret instead.
    // ------------------------------------------------------------------
    val stableKeystore = rootProject.file("keystore/sleepplayer.jks")
    if (stableKeystore.exists()) {
        signingConfigs {
            create("stable") {
                storeFile = stableKeystore
                storePassword = "sleepplayer"
                keyAlias = "sleepplayer"
                keyPassword = "sleepplayer"
            }
        }
    }

    defaultConfig {
        applicationId = "dev.remiband.sleepguard"
        minSdk = 26   // androidx.health.connect requires 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        getByName("debug") {
            if (stableKeystore.exists()) {
                signingConfig = signingConfigs.getByName("stable")
            }
        }
        getByName("release") {
            isMinifyEnabled = false
            if (stableKeystore.exists()) {
                signingConfig = signingConfigs.getByName("stable")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

// No dependencies on purpose.
//
// Everything here is plain `android.*` -- no AndroidX, no Compose, no
// coroutines. That is a deliberate trade: the UI is built programmatically and
// is uglier than Compose would be, but the project has nothing to resolve from
// the network and nothing that can drift out of version compatibility.
//
// If you later want modern UI, adding AndroidX + Compose is a normal
// migration; nothing in the BLE or protocol layers needs to change.
dependencies {
    // Health Connect: the phone's health store, which Mi Fitness may already be
    // writing heart rate into. Reading it needs no BLE connection and no
    // protocol work -- the trade is latency, since records land in batches.
    // Version pinned deliberately: 1.1.0 stable (and rc/alphas after alpha07)
    // demand compileSdk 36 and AGP 8.9.1+, while this project builds with AGP
    // 8.5.2 / compileSdk 34. alpha07 is the newest release whose AAR metadata
    // only requires compileSdk 34:
    //   unzip -p <aar> META-INF/com/android/build/gradle/aar-metadata.properties
    implementation("androidx.health.connect:connect-client:1.1.0-alpha07")

    // The Health Connect API is suspend-based, and coroutines are not exposed
    // as an `api` dependency, so compiling against it needs these explicitly.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Pure-JVM unit tests for the sleep detector. No Android, no device:
    //   ./gradlew :app:testDebugUnitTest
    testImplementation("junit:junit:4.13.2")
}
