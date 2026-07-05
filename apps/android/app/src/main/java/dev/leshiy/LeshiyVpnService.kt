package dev.leshiy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import uniffi.leshiy_mobile.LeshiyBridge
import uniffi.leshiy_mobile.Status
import uniffi.leshiy_mobile.StatusListener

/**
 * Establishes the Android TUN interface and hands its fd to the Rust bridge, which runs the
 * REALITY tunnel. Routing/DNS are owned by [VpnService.Builder]; the Rust side only pumps
 * packets between the fd and the tunnel.
 */
class LeshiyVpnService : VpnService() {

    private val bridge = LeshiyBridge()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
        }

        val uri = intent?.getStringExtra(EXTRA_URI) ?: return START_NOT_STICKY

        val tun = Builder()
            .setSession("leshiy")
            .addAddress("10.71.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setMtu(1400)
            .establish() ?: return START_NOT_STICKY

        startForeground(NOTIFICATION_ID, buildNotification())

        // detachFd() transfers ownership of the fd to native code, which closes it on stop.
        bridge.start(tun.detachFd(), uri, object : StatusListener {
            override fun onStatus(status: Status) {
                AppState.status.value = status
            }
        })
        AppState.running.value = true
        return START_STICKY
    }

    private fun stopTunnel() {
        bridge.stop()
        AppState.running.value = false
        AppState.status.value = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        bridge.stop()
        AppState.running.value = false
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Leshiy VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Leshiy")
            .setContentText("Tunnel active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val EXTRA_URI = "uri"
        const val ACTION_STOP = "dev.leshiy.STOP"
        private const val CHANNEL_ID = "leshiy_vpn"
        private const val NOTIFICATION_ID = 1
    }
}
