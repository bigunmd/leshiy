# R8 rules for the release build.

# JNA (the runtime under the UniFFI bindings) finds classes, fields and callback methods by
# reflection and from native code; nothing it touches may be renamed or removed.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-dontwarn java.awt.**

# UniFFI-generated bindings: JNA structures, callback interfaces (StatusListener,
# ProvisionListener, ...) and the library interface are all reached from native code.
-keep class uniffi.** { *; }

# ML Kit (QR import) discovers its components the Firebase way: registrar classes named in
# manifest meta-data are created by reflection through their no-arg constructor, which R8's full
# mode strips unless kept — QR scanning then fails in release builds only.
-keep class * implements com.google.firebase.components.ComponentRegistrar { public <init>(); }
