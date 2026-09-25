# Leshiy — Native Android app

Native Kotlin + Jetpack Compose client. The UI drives the existing leshiy Rust datapath
(REALITY/mux/tun) through the `leshiy-mobile` UniFFI bridge — no protocol logic lives in Kotlin.

**Status:** Phase 1 (bridge spike). See
`docs/superpowers/plans/2026-07-05-android-native-phase1-bridge.md`.

## Prerequisites

- Android SDK (`ANDROID_HOME` set) + Platform 35, Build-Tools.
- Android NDK: already installed at `~/Android/ndk/28.2.13676358` — just
  `export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358` (else
  `sdkmanager "ndk;28.2.13676358"`).
- Rust Android targets (already installed): `aarch64/armv7/x86_64-linux-android`.
- `cargo install cargo-ndk`.
- JDK 17 (Gradle/AGP requirement).

## Build

The system default JDK is 25; Gradle/AGP needs JDK 17. Point `JAVA_HOME` at it for the build
only (don't change the global default):

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=~/Android
export ANDROID_NDK_HOME=~/Android/ndk/28.2.13676358

# 1. Build the Rust bridge (.so per ABI) + generate Kotlin bindings.
../../scripts/build-android-jni.sh

# 2. Build the APKs (the Gradle wrapper is committed; pinned to Gradle 9.8.0, AGP 9.4).
./gradlew assembleDebug
# -> app/build/outputs/apk/debug/app-{arm64-v8a,armeabi-v7a,x86_64,universal}-debug.apk
```

Builds split per ABI: each `app-<abi>-*.apk` carries only that ABI's `libleshiy_mobile.so`, and
`app-universal-*.apk` carries all three. Release builds are shrunk with R8 (keep rules for JNA,
the UniFFI bindings and ML Kit in `app/proguard-rules.pro`). The `./gradlew` wrapper is
self-contained.

The bridge outputs (`app/src/main/jniLibs/`, `app/src/main/java/uniffi/`) are generated and
git-ignored — regenerate them with the script, don't hand-edit.

## Layout

- `app/src/main/java/dev/leshiy/` — `MainActivity` (spike UI), `LeshiyVpnService`
  (establishes the TUN, hands the fd to the bridge), `AppState` (temporary status holder).
- `app/src/main/java/dev/leshiy/ui/theme/` — Deep Bog palette + Bricolage/IBM Plex Mono fonts,
  mirroring `apps/gui/src/index.css`.
- `app/src/main/res/font/` — vendored OFL fonts (Bricolage Grotesque, IBM Plex Mono).

## Verifying

Per repo notes, exercise the tunnel from the device/phone (or check-host.net), **not** the WSL2
CLI — the Windows VPN intercepts WSL2 outbound.
