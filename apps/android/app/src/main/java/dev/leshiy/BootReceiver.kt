package dev.leshiy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.Profiles
import dev.leshiy.data.TunnelRepository

/**
 * Re-establishes the tunnel after the device reboots or the app self-updates.
 *
 * Triggered by `BOOT_COMPLETED` (post-unlock — our profiles/prefs/vault live in credential-
 * encrypted storage, so Direct Boot's `LOCKED_BOOT_COMPLETED` is too early) and by
 * `MY_PACKAGE_REPLACED`, since the in-app updater reinstalls the APK, killing the process and
 * dropping the tunnel.
 *
 * It only *triggers* the service's existing no-URI start path, which resolves the persisted active
 * profile — see [LeshiyVpnService.onStartCommand]. The decision of whether to start at all is the
 * pure [shouldAutoStart]. `specialUse` is not on Android 15's list of foreground-service types
 * barred from a boot receiver, so the start is permitted; the `runCatching` is belt-and-braces
 * (and a boot receiver must never crash the boot flow).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> Unit
            else -> return
        }
        runCatching {
            val app = context.applicationContext
            val start = shouldAutoStart(
                toggleOn = AppPrefs.reconnectOnBoot(app),
                hasConsent = VpnService.prepare(app) == null,
                hasProfile = Profiles.manager(app).activeUri() != null,
                alreadyRunning = TunnelRepository.running.value,
            )
            if (start) {
                app.startForegroundService(Intent(app, LeshiyVpnService::class.java))
            }
        }.onFailure { Log.w(TAG, "boot auto-start skipped: $it") }
    }

    private companion object {
        const val TAG = "BootReceiver"
    }
}
