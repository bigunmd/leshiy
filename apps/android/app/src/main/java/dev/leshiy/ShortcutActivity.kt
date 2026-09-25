package dev.leshiy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import dev.leshiy.data.Profiles
import dev.leshiy.data.TunnelRepository

/**
 * Invisible target of the launcher's Connect / Disconnect shortcuts. Not exported: the launcher
 * starts static shortcuts with our own identity, while other apps cannot reach it — as the exported
 * MainActivity, any app could fire the disconnect action and drop the tunnel.
 *
 * Connect starts the tunnel directly when it can (consent + active profile, the tile's rule);
 * otherwise it opens the app, where the user finishes setup. No UI is revealed on the direct paths,
 * so the shortcuts keep working behind the app lock.
 */
class ShortcutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        when (intent?.action) {
            ACTION_CONNECT -> if (!TunnelRepository.running.value) connect()
            ACTION_DISCONNECT ->
                startService(Intent(this, LeshiyVpnService::class.java).setAction(LeshiyVpnService.ACTION_STOP))
        }
        finish()
    }

    private fun connect() {
        val verb = tileAction(
            running = false,
            hasConsent = VpnService.prepare(this) == null,
            hasProfile = runCatching { Profiles.manager(this).activeUri() }.getOrNull() != null,
        )
        if (verb == TileVerb.START) {
            startForegroundService(Intent(this, LeshiyVpnService::class.java))
        } else {
            startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    private companion object {
        const val ACTION_CONNECT = "dev.leshiy.SHORTCUT_CONNECT"
        const val ACTION_DISCONNECT = "dev.leshiy.SHORTCUT_DISCONNECT"
    }
}
