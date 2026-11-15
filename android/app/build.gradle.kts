plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.remiband"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.remiband.sleepguard"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
    // Pure-JVM unit tests for the sleep detector. No Android, no device:
    //   ./gradlew :app:testDebugUnitTest
    testImplementation("junit:junit:4.13.2")
}
