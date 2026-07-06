package dev.leshiy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.content.Context
import android.net.InetAddresses
import android.net.IpPrefix
import android.os.Build
import dev.leshiy.data.PerAppMode
import dev.leshiy.data.PerAppStore
import dev.leshiy.data.SplitKind
import dev.leshiy.data.SplitStore
import dev.leshiy.data.TunnelRepository
import dev.leshiy.data.cidrParts
import dev.leshiy.data.perAppPlan
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
        }

        // Explicit URI from the UI, or (always-on / boot) the persisted active profile.
        val uri = intent?.getStringExtra(EXTRA_URI)
            ?: dev.leshiy.data.Profiles.manager(applicationContext).activeUri()
            ?: return START_NOT_STICKY

        // Foreground promptly; domain resolution + establish run async so DNS never blocks the UI.
        startForeground(NOTIFICATION_ID, buildNotification())
        scope.launch { buildAndStart(uri) }
        return START_STICKY
    }

    private suspend fun buildAndStart(uri: String) {
        // Network-mode domain rules → resolved IPs (off the main thread; bounded).
        val domainRoutes = withContext(Dispatchers.IO) { resolveDomainRoutes(applicationContext) }

        val builder = Builder()
            .setSession("leshiy")
            .addAddress("10.71.0.2", 32)
            .addDnsServer("1.1.1.1")
            .setMtu(1400)
        configureSplit(builder, applicationContext, domainRoutes)
        val tun = builder.establish() ?: run { stopTunnel(); return }

        // detachFd() transfers ownership of the fd to native code, which closes it on stop.
        bridge.start(tun.detachFd(), uri, object : StatusListener {
            override fun onStatus(status: Status) {
                TunnelRepository.onStatus(status)
            }
        })
        TunnelRepository.setRunning(true)
    }

    /** Resolve network-mode domain rules to `(ip, prefix)` routes. Best-effort, bounded. */
    private fun resolveDomainRoutes(ctx: Context): List<Pair<String, Int>> {
        val split = SplitStore(ctx)
        if (split.kind() != SplitKind.NETWORK || split.netMode() == PerAppMode.OFF) return emptyList()
        return split.domains().flatMap { domain ->
            val host = domain.removePrefix("*.")
            runCatching {
                java.net.InetAddress.getAllByName(host).take(8).map { addr ->
                    val prefix = if (addr is java.net.Inet6Address) 128 else 32
                    addr.hostAddress!! to prefix
                }
            }.getOrDefault(emptyList())
        }
    }

    private fun stopTunnel() {
        bridge.stop()
        TunnelRepository.setRunning(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Apply the active split-tunnel scheme to the Builder. App-based uses allow/disallow apps;
     * network-based uses routes (include = route only these CIDRs; exclude = full tunnel minus
     * these, Android 13+). Our own app is always kept off the tunnel to avoid a routing loop.
     */
    private fun configureSplit(b: Builder, ctx: Context, domainRoutes: List<Pair<String, Int>>) {
        when (SplitStore(ctx).kind()) {
            SplitKind.NETWORK -> {
                val split = SplitStore(ctx)
                val cidrs = split.cidrs().mapNotNull { cidrParts(it) } + domainRoutes
                when {
                    split.netMode() == PerAppMode.INCLUDE && cidrs.isNotEmpty() ->
                        cidrs.forEach { (a, p) -> runCatching { b.addRoute(a, p) } }
                    split.netMode() == PerAppMode.EXCLUDE -> {
                        b.addRoute("0.0.0.0", 0)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            cidrs.forEach { (a, p) ->
                                runCatching { b.excludeRoute(IpPrefix(InetAddresses.parseNumericAddress(a), p)) }
                            }
                        }
                    }
                    else -> b.addRoute("0.0.0.0", 0)
                }
                // Loop avoidance: our own dial must bypass the tunnel.
                runCatching { b.addDisallowedApplication(ctx.packageName) }
            }
            SplitKind.APP -> {
                b.addRoute("0.0.0.0", 0)
                val store = PerAppStore(ctx)
                val plan = perAppPlan(store.mode(), store.packages(), ctx.packageName)
                // runCatching guards NameNotFoundException for a since-uninstalled package.
                plan.allowed.forEach { runCatching { b.addAllowedApplication(it) } }
                plan.disallowed.forEach { runCatching { b.addDisallowedApplication(it) } }
            }
        }
    }

    override fun onRevoke() {
        // The system or another VPN app revoked our permission — tear down cleanly.
        stopTunnel()
    }

    override fun onDestroy() {
        bridge.stop()
        TunnelRepository.setRunning(false)
        scope.cancel()
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
