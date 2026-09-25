plugins {
    // AGP 9 compiles Kotlin itself (built-in Kotlin); the compose compiler plugin's version is
    // the Kotlin version the build uses.
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}
