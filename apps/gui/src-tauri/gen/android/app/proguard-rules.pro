# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Leshiy VPN: the plugin is loaded reflectively by Tauri (register_android_plugin) and the
# @InvokeArg arg classes are deserialized reflectively — R8 must not strip/rename them. The
# VpnService is kept automatically (declared in the manifest).
-keep class app.leshiy.gui.VpnPlugin { *; }
-keep class app.leshiy.gui.EstablishArgs { *; }
-keep class app.leshiy.gui.RouteArg { *; }