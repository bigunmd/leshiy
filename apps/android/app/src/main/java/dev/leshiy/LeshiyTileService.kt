package dev.leshiy

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.leshiy.data.Profiles
import dev.leshiy.data.TunnelRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Shade toggle for the tunnel. Mirrors [TunnelRepository.running] (same process) and
 * reuses the service's existing paths: no-URI start resolves the active profile, and
 * [LeshiyVpnService.ACTION_STOP] tears down. Taps that cannot succeed directly
 * (no VPN consent yet, no active profile) open the app instead — see [tileAction].
 */
class LeshiyTileService : TileService() {

    private var listenJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onStartListening() {
        listenJob?.cancel()
        listenJob = scope.launch {
            TunnelRepository.running.collect { render(it) }
        }
    }

    override fun onStopListening() {
        listenJob?.cancel()
        listenJob = null
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun render(running: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "Leshiy"
        tile.icon = Icon.createWithResource(this, R.drawable.ic_qs_leshiy)
        tile.updateTile()
    }

    override fun onClick() {
        val verb = tileAction(
            running = TunnelRepository.running.value,
            hasConsent = VpnService.prepare(this) == null,
            hasProfile = runCatching { Profiles.manager(applicationContext).activeUri() }.getOrNull() != null,
        )
        when (verb) {
            TileVerb.STOP ->
                // The app has a live foreground service, so plain startService is allowed.
                startService(
                    Intent(this, LeshiyVpnService::class.java).setAction(LeshiyVpnService.ACTION_STOP),
                )
            TileVerb.START ->
                // From the shade the app is background — must go through startForegroundService;
                // the service calls startForeground first thing in onStartCommand.
                startForegroundService(Intent(this, LeshiyVpnService::class.java))
            TileVerb.OPEN_APP -> openApp()
        }
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(
                    PendingIntent.getActivity(
                        this,
                        2,
                        intent,
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                    ),
                )
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        }
    }

    companion object {
        /** Ask the system to refresh the tile now (e.g. right after connect/disconnect). */
        fun requestUpdate(context: Context) {
            runCatching {
                requestListeningState(context, ComponentName(context, LeshiyTileService::class.java))
            }
        }
    }
}
