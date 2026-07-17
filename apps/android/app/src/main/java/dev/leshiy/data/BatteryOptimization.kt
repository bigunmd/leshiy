package dev.leshiy.data

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

/**
 * Battery-optimization exemption — the single gate on whether the sleep-keepalive alarm (ADR-0031)
 * can actually wake the CPU under Doze. One source of truth, reused by Settings, the keepalive
 * toggle, and onboarding.
 */
object BatteryOptimization {
    fun isUnrestricted(context: Context): Boolean =
        context.getSystemService(PowerManager::class.java)
            ?.isIgnoringBatteryOptimizations(context.packageName) ?: false

    /**
     * Fire the one-tap "Allow background activity?" system dialog. Requires the
     * REQUEST_IGNORE_BATTERY_OPTIMIZATIONS permission (declared in the manifest). runCatching: some
     * OEM ROMs restrict or don't resolve the action.
     *
     * BatteryLife lint flags this as a Play Store policy violation; the app ships as a GitHub APK
     * (not on Play), and an always-connected VPN is a documented acceptable use case, so suppressed.
     */
    @SuppressLint("BatteryLife")
    fun request(context: Context) {
        runCatching {
            context.startActivity(
                Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:${context.packageName}"),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }
}

/**
 * Prompt for the battery exemption only when the user just enabled keepalive and the app is still
 * restricted — the moment the exemption starts to matter. Pure, kept testable like [tileAction].
 */
fun shouldPromptBattery(enablingKeepalive: Boolean, unrestricted: Boolean): Boolean =
    enablingKeepalive && !unrestricted
