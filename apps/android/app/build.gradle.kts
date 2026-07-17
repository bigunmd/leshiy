import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
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
    compileSdk = 35

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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    // The Rust bridge .so files are staged here by scripts/build-android-jni.sh.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    // QR import: CameraX preview + ML Kit barcode scanning (offline).
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    // QR export: encode issued credential URIs to a bitmap (offline, pure-Java).
    implementation("com.google.zxing:core:3.5.3")
    // UniFFI-generated Kotlin needs the JNA runtime.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    testImplementation("junit:junit:4.13.2")
    // android.jar's org.json classes are stubs in JVM unit tests; this real implementation
    // shadows them so the release-JSON parsing is testable off-device.
    testImplementation("org.json:json:20240303")
}
