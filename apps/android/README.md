# Leshiy — Native Android app

Native Kotlin + Jetpack Compose client. The UI drives the existing leshiy Rust datapath
(REALITY/mux/tun) through the `leshiy-mobile` UniFFI bridge — no protocol logic lives in Kotlin.

**Status:** Phase 1 (bridge spike). See
`docs/superpowers/plans/2026-07-05-android-native-phase1-bridge.md`.

## Prerequisites

- Android SDK (`ANDROID_HOME` set) + Platform 35, Build-Tools.
- Android NDK: `sdkmanager "ndk;27.0.12077973"` then
  `export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.0.12077973`.
- Rust Android targets (already installed): `aarch64/armv7/x86_64-linux-android`.
- `cargo install cargo-ndk`.
- JDK 17 (Gradle/AGP requirement).

## Build

```bash
# 1. Build the Rust bridge (.so per ABI) + generate Kotlin bindings.
../../scripts/build-android-jni.sh

# 2. Build the APK. (Generate the Gradle wrapper once if missing: `gradle wrapper`.)
./gradlew assembleDebug
```

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
