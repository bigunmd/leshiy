import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Single source of truth for the version: the workspace Cargo.toml. Keeps the APK in lockstep
// with the CLI/desktop/server release instead of drifting.
val leshiyVersion: String = run {
    val toml = File(rootProject.projectDir, "../../Cargo.toml").readText()
    val block = toml.substringAfter("[workspace.package]")
    Regex("""version\s*=\s*"([^"]+)"""").find(block)?.groupValues?.get(1) ?: "0.0.0"
}

fun versionToCode(v: String): Int {
    val p = v.split(".").map { it.trim().toIntOrNull() ?: 0 }
    return p.getOrElse(0) { 0 } * 10000 + p.getOrElse(1) { 0 } * 100 + p.getOrElse(2) { 0 }
}

android {
    namespace = "dev.leshiy"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.leshiy"
        minSdk = 26
        targetSdk = 35
        versionCode = versionToCode(leshiyVersion)
        versionName = leshiyVersion
    }

    // Release signing is driven by environment variables so CI can inject the keystore from
    // secrets (see .github/workflows/android-release.yml). Absent (local/dev/forks) → unsigned.
    signingConfigs {
        create("release") {
            System.getenv("ANDROID_KEYSTORE_PATH")?.let { path ->
                storeFile = file(path)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Sign only when a keystore is provided (CI release); otherwise leave it unsigned
            // (still installable for testing, just not updatable).
            if (System.getenv("ANDROID_KEYSTORE_PATH") != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    // Built-in Kotlin takes its JVM target from targetCompatibility.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true // BuildConfig.VERSION_NAME / DEBUG for the in-app updater
    }
    // The Rust bridge .so files are staged by scripts/build-android-jni.sh into src/main/jniLibs,
    // AGP's default location — no source-set override needed.
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.navigation:navigation-compose:2.10.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.biometric:biometric:1.1.0")
    // QR import: CameraX preview + ML Kit barcode scanning (offline).
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    // QR export: encode issued credential URIs to a bitmap (offline, pure-Java).
    implementation("com.google.zxing:core:3.5.4")
    // UniFFI-generated Kotlin needs the JNA runtime.
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    testImplementation("junit:junit:4.13.2")
    // android.jar's org.json classes are stubs in JVM unit tests; this real implementation
    // shadows them so the release-JSON parsing is testable off-device.
    testImplementation("org.json:json:20260814")
}
