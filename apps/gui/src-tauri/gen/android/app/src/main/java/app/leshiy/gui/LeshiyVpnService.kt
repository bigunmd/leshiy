package app.leshiy.gui

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.net.InetAddress

/** One CIDR (address + prefix length) for a VpnService route. */
data class VpnRoute(val address: String, val prefix: Int)

/** Everything the service needs to build the tunnel interface, handed over by [VpnPlugin]. */
data class VpnConfig(
    val address: String,
    val prefix: Int,
    val mtu: Int,
    val dns: List<String>,
    val routes: List<VpnRoute>,
    val excludeRoutes: List<VpnRoute>,
    /** Per-app routing: "off" | "include" | "exclude". */
    val perAppMode: String,
    val perAppPackages: List<String>,
)

/**
 * The tunnel interface owner. [VpnPlugin] sets [pendingConfig] + the [onEstablished]/[onError]
 * callbacks, then starts this foreground service; we build the `VpnService.Builder`, `establish()`,
 * and report the resulting fd back. The Rust engine (loaded in this same process) reads/writes the
 * fd via `TunEngine`. The fd is **detached** so native owns + closes it on engine teardown.
 *
 * Loop avoidance: `addDisallowedApplication(packageName)` excludes our own app from the VPN, so the
 * outbound tunnel socket bypasses it (no per-socket protect needed).
 */
class LeshiyVpnService : VpnService() {
    companion object {
        const val CHANNEL_ID = "leshiy_vpn"
        const val NOTIFICATION_ID = 1

        @Volatile
        var instance: LeshiyVpnService? = null

        @Volatile
        var pendingConfig: VpnConfig? = null

        @Volatile
        var onEstablished: ((Int) -> Unit)? = null

        @Volatile
        var onError: ((String) -> Unit)? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        instance = this
        startForegroundCompat()

        val cfg = pendingConfig
        pendingConfig = null
        if (cfg == null) {
            reportError("no VPN config provided")
            stopVpn()
            return START_NOT_STICKY
        }

        try {
            val builder = Builder()
                .setSession("Leshiy")
                .setMtu(cfg.mtu)
                .addAddress(cfg.address, cfg.prefix)
            for (dns in cfg.dns) builder.addDnsServer(dns)
            for (r in cfg.routes) builder.addRoute(r.address, r.prefix)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                for (r in cfg.excludeRoutes) {
                    builder.excludeRoute(IpPrefix(InetAddress.getByName(r.address), r.prefix))
                }
            }
            // Per-app routing + loop avoidance. addAllowed/addDisallowed are mutually exclusive.
            //  - include: ONLY the listed apps tunnel; our own app isn't listed, so it bypasses
            //             the VPN (no loop). Empty list ⇒ degenerate, fall back to off.
            //  - exclude: everything tunnels except the listed apps + our own app.
            //  - off:     everything tunnels except our own app (loop avoidance).
            val includeApps = cfg.perAppMode == "include" && cfg.perAppPackages.isNotEmpty()
            if (includeApps) {
                for (pkg in cfg.perAppPackages) {
                    try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
                }
            } else {
                try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
                if (cfg.perAppMode == "exclude") {
                    for (pkg in cfg.perAppPackages) {
                        if (pkg != packageName) {
                            try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
                        }
                    }
                }
            }

            android.util.Log.i(
                "leshiy",
                "VpnService establish: mtu=${cfg.mtu} dns=${cfg.dns.size} routes=${cfg.routes.size} excludeRoutes=${cfg.excludeRoutes.size}",
            )
            val pfd = builder.establish()
                ?: throw IllegalStateException("VpnService.establish() returned null")
            vpnInterface = pfd
            // Transfer fd ownership to native; Rust closes it when the engine tears down.
            val fd = pfd.detachFd()
            reportEstablished(fd)
        } catch (e: Exception) {
            reportError(e.message ?: "failed to establish the VPN interface")
            stopVpn()
        }
        return START_STICKY
    }

    /** Stop the tunnel + foreground service. The fd itself is owned + closed by native. */
    fun stopVpn() {
        vpnInterface = null
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
        instance = null
    }

    override fun onRevoke() {
        // The system revoked the VPN (e.g. another VPN started). The engine's read on the now-dead
        // fd will error and tear down; just clean up the service here.
        stopVpn()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Background VPN: when the user swipes the app from recents we deliberately KEEP the tunnel
        // running (like other VPN apps). The foreground service holds the process + engine alive;
        // do not stop here. Disconnect is only via the explicit UI action / onRevoke.
        android.util.Log.i("leshiy", "VpnService onTaskRemoved — keeping VPN alive in background")
    }

    override fun onDestroy() {
        android.util.Log.i("leshiy", "VpnService onDestroy")
        instance = null
        super.onDestroy()
    }

    private fun startForegroundCompat() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Leshiy VPN",
                NotificationManager.IMPORTANCE_LOW,
            )
            nm.createNotificationChannel(channel)
        }
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Leshiy")
            .setContentText("VPN active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        // If this throws (e.g. FGS-type/notification policy), the service won't be promoted to
        // foreground and the OS will kill the process when the app is swiped → VPN stops. Log it
        // loudly so `adb logcat -s leshiy` shows the reason.
        try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
            android.util.Log.i("leshiy", "VpnService is now foreground (type=$type)")
        } catch (e: Exception) {
            android.util.Log.e("leshiy", "startForeground failed: ${e.message}", e)
        }
    }

    private fun reportEstablished(fd: Int) {
        val cb = onEstablished
        onEstablished = null
        onError = null
        cb?.invoke(fd)
    }

    private fun reportError(message: String) {
        val cb = onError
        onEstablished = null
        onError = null
        cb?.invoke(message)
    }
}
