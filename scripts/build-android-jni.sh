#!/usr/bin/env bash
# Build the leshiy-mobile bridge for Android ABIs and generate the Kotlin bindings.
#
# Prerequisites:
#   - Android Rust targets (already installed): aarch64/armv7/i686/x86_64-linux-android
#   - cargo-ndk:            cargo install cargo-ndk
#   - Android NDK:          sdkmanager "ndk;27.0.12077973"
#                           export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.0.12077973
set -euo pipefail
cd "$(dirname "$0")/.."

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an installed NDK (see header)}"

APP="apps/android/app"
JNILIBS="$APP/src/main/jniLibs"
KOTLIN_OUT="$APP/src/main/java"

echo ">> cargo-ndk build (release) for arm64-v8a, armeabi-v7a, x86_64"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o "$JNILIBS" \
  build -p leshiy-mobile --release

echo ">> generate Kotlin bindings from the built cdylib"
cargo run -q -p leshiy-mobile --bin uniffi-bindgen -- generate \
  --library target/aarch64-linux-android/release/libleshiy_mobile.so \
  --language kotlin --out-dir "$KOTLIN_OUT"

echo ">> done: jniLibs in $JNILIBS, bindings in $KOTLIN_OUT/uniffi/leshiy_mobile/"
