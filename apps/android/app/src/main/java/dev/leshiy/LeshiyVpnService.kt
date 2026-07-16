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
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.PerAppMode
import dev.leshiy.data.PerAppStore
import dev.leshiy.data.SplitKind
import dev.leshiy.data.SplitStore
import dev.leshiy.data.TunnelRepository
import dev.leshiy.data.cidrParts
import dev.leshiy.data.mergeDomainRoutes
import dev.leshiy.data.perAppPlan
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
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

    /**
     * Resolved domain-rule routes currently baked into the interface. Only ever grows — see
     * [refreshDomainRoutes]. Confined to [scope]'s main dispatcher, so no synchronisation.
     */
    private var domainRoutes: Set<Pair<String, Int>> = emptySet()
    private var refreshJob: Job? = null

    private suspend fun buildAndStart(uri: String) {
        // Network-mode domain rules → resolved IPs (off the main thread; bounded).
        domainRoutes = withContext(Dispatchers.IO) { resolveDomainRoutes(applicationContext) }
        val tun = establish(domainRoutes) ?: run { stopTunnel(); return }

        // detachFd() transfers ownership of the fd to native code, which closes it on stop.
        bridge.start(tun.detachFd(), uri, object : StatusListener {
            override fun onStatus(status: Status) {
                TunnelRepository.onStatus(status)
            }
        })
        TunnelRepository.setRunning(true)
        startDomainRefresh()
    }

    /** Build + establish the interface with `routes` as the resolved domain-rule routes. */
    private fun establish(routes: Set<Pair<String, Int>>): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("leshiy")
            .addAddress("10.71.0.2", 32)
            .addDnsServer("1.1.1.1")
            .setMtu(1400)
        configureSplit(builder, applicationContext, routes)
        return builder.establish()
    }

    /**
     * Re-resolve domain rules periodically and re-establish when new IPs appear.
     *
     * Android's VPN routes are immutable once established, so a domain rule can only be honoured
     * by baking its resolved IPs into the interface — and the resolution [buildAndStart] did is
     * stale the moment a DNS TTL expires. Without this, traffic to a domain's newer IPs silently
     * leaves the tunnel for the rest of the session, which on a censored path means the site
     * simply stops loading.
     *
     * **Accumulate, never replace.** The desktop resolver diffs and removes stale IPs, because
     * mutating a route there is cheap. Here every change costs an interface re-establish, which
     * drops the netstack's per-flow state and breaks in-flight connections — so a CDN rotating
     * through its pool would otherwise churn the tunnel every refresh, forever. Taking the union
     * converges instead: re-establishes get rarer as the pool is discovered, and the cost of
     * keeping an IP a domain no longer uses is over-inclusion (something unrelated gets tunneled)
     * rather than under-inclusion (the site is blocked). For a circumvention tool that is the
     * safe direction to err in.
     */
    private fun startDomainRefresh() {
        refreshJob?.cancel()
        if (!hasDomainRules(applicationContext)) return
        refreshJob = scope.launch {
            while (true) {
                delay(DOMAIN_REFRESH_MS)
                refreshDomainRoutes()
            }
        }
    }

    /** One refresh pass. Visible for the service's own loop; no-ops unless the union grew. */
    private suspend fun refreshDomainRoutes() {
        val fresh = withContext(Dispatchers.IO) { resolveDomainRoutes(applicationContext) }
        val union = mergeDomainRoutes(domainRoutes, fresh)
        if (union == domainRoutes) return // nothing new — never churn the interface for free
        // establish() supersedes the live interface, keeping the old fd valid until we drop it;
        // if it fails, the platform leaves the existing interface untouched, so we keep running
        // on the routes we have and simply try again next pass.
        val tun = establish(union) ?: run {
            Log.w(TAG, "re-establish for refreshed domain routes failed; keeping current routes")
            return
        }
        // Past this point the old interface is superseded and packets are already being routed to
        // `tun`, so the fd MUST reach the engine. If handing it over fails there is nothing left
        // reading the live interface — every packet would blackhole — so reclaim the fd (detachFd
        // took it out of ParcelFileDescriptor's ownership) and tear down rather than wedge.
        val fd = tun.detachFd()
        runCatching { bridge.reattachTun(fd) }
            .onSuccess { domainRoutes = union }
            .onFailure { e ->
                Log.w(TAG, "reattach after domain refresh failed; stopping: $e")
                runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                stopTunnel()
            }
    }

    /** Resolve network-mode domain rules to `(ip, prefix)` routes. Best-effort, bounded. */
    private fun resolveDomainRoutes(ctx: Context): Set<Pair<String, Int>> {
        if (!hasDomainRules(ctx)) return emptySet()
        return SplitStore(ctx).domains().flatMapTo(mutableSetOf()) { domain ->
            val host = domain.removePrefix("*.")
            runCatching {
                java.net.InetAddress.getAllByName(host).take(MAX_IPS_PER_DOMAIN).map { addr ->
                    val prefix = if (addr is java.net.Inet6Address) 128 else 32
                    addr.hostAddress!! to prefix
                }
            }.getOrDefault(emptyList())
        }
    }

    /** True when network-mode domain rules are active and worth resolving. */
    private fun hasDomainRules(ctx: Context): Boolean {
        val split = SplitStore(ctx)
        return split.kind() == SplitKind.NETWORK &&
            split.netMode() != PerAppMode.OFF &&
            split.domains().isNotEmpty()
    }

    private fun stopTunnel() {
        refreshJob?.cancel()
        refreshJob = null
        bridge.stop()
        TunnelRepository.setRunning(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Apply the active split-tunnel scheme to the Builder. App-based uses allow/disallow apps;
     * network-based uses routes (include = route only these CIDRs; exclude = full tunnel minus
     * these, Android 13+). Our own app is always kept off the tunnel to avoid a routing loop.
     *
     * IPv6: OFF by default IPv6 is left to the physical interface (goes direct). Android can't
     * carry v6 through the tunnel yet, so capturing it would black-hole every v6 site (e.g.
     * YouTube). Users who want strict no-leak can enable [AppPrefs.blockIpv6], which routes ::/0
     * into the tunnel in full-tunnel modes. Explicit v6 ranges in network-include are always routed.
     */
    private fun configureSplit(b: Builder, ctx: Context, domainRoutes: Set<Pair<String, Int>>) {
        val blockV6 = AppPrefs.blockIpv6(ctx)
        when (SplitStore(ctx).kind()) {
            SplitKind.NETWORK -> {
                val split = SplitStore(ctx)
                val cidrs = split.cidrs().mapNotNull { cidrParts(it) } + domainRoutes
                when {
                    split.netMode() == PerAppMode.INCLUDE && cidrs.isNotEmpty() -> {
                        // Only the listed ranges are tunneled. Add the v6 TUN address only if a v6
                        // range is present, so v6 routes are accepted.
                        if (cidrs.any { it.first.contains(':') }) enableV6Routing(b)
                        cidrs.forEach { (a, p) -> runCatching { b.addRoute(a, p) } }
                    }
                    split.netMode() == PerAppMode.EXCLUDE -> {
                        b.addRoute("0.0.0.0", 0)
                        if (blockV6) {
                            killV6(b)
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                cidrs.forEach { (a, p) ->
                                    runCatching { b.excludeRoute(IpPrefix(InetAddresses.parseNumericAddress(a), p)) }
                                }
                            }
                        }
                    }
                    else -> {
                        b.addRoute("0.0.0.0", 0)
                        if (blockV6) killV6(b)
                    }
                }
                // Loop avoidance: our own dial must bypass the tunnel.
                runCatching { b.addDisallowedApplication(ctx.packageName) }
            }
            SplitKind.APP -> {
                b.addRoute("0.0.0.0", 0)
                if (blockV6) killV6(b)
                val store = PerAppStore(ctx)
                val plan = perAppPlan(store.mode(), store.packages(), ctx.packageName)
                // runCatching guards NameNotFoundException for a since-uninstalled package.
                plan.allowed.forEach { runCatching { b.addAllowedApplication(it) } }
                plan.disallowed.forEach { runCatching { b.addDisallowedApplication(it) } }
            }
        }
    }

    /** Add a ULA v6 address so IPv6 routes on the TUN are accepted. */
    private fun enableV6Routing(b: Builder) {
        runCatching { b.addAddress("fd00:71::2", 128) }
    }

    /** Route all IPv6 into the tunnel (no-leak mode) so it can't escape the physical interface. */
    private fun killV6(b: Builder) {
        enableV6Routing(b)
        runCatching { b.addRoute("::", 0) }
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
        private const val TAG = "LeshiyVpnService"

        /**
         * How often domain rules are re-resolved. Well above a typical DNS TTL (60–300s) on
         * purpose: chasing every rotation would re-establish the interface constantly, and each
         * re-establish breaks in-flight connections. Since the resolved set accumulates rather
         * than churns, a slow cadence still converges — it just takes longer to discover a large
         * CDN pool. Matches the desktop resolver's REFRESH.
         */
        private const val DOMAIN_REFRESH_MS = 30 * 60 * 1000L

        /** Addresses taken per domain per resolution — a guard against a huge RRset. */
        private const val MAX_IPS_PER_DOMAIN = 8
    }
}
