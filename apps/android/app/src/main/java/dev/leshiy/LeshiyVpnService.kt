package dev.leshiy

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.content.Context
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.IpPrefix
import android.net.Network
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.graphics.drawable.Icon
import android.os.SystemClock
import android.util.Log
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.PerAppMode
import dev.leshiy.data.PerAppStore
import dev.leshiy.data.SplitKind
import dev.leshiy.data.SplitStore
import dev.leshiy.data.TunnelRepository
import dev.leshiy.data.UiEvents
import dev.leshiy.data.VPN_DNS
import dev.leshiy.data.UiMessage
import dev.leshiy.data.UiMessageKind
import dev.leshiy.data.cidrParts
import dev.leshiy.data.mergeDomainRoutes
import dev.leshiy.data.netRoutePlan
import dev.leshiy.data.perAppPlan
import dev.leshiy.ui.i18n.LangState
import dev.leshiy.ui.i18n.stringsFor
import java.util.concurrent.Executors
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import dev.leshiy.ui.formatBytes
import dev.leshiy.ui.formatDuration
import uniffi.leshiy_mobile.ConnState
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
            ACTION_RECONFIGURE -> {
                if (!sessionActive) {
                    stopSelf(startId)
                    return START_NOT_STICKY
                }
                scheduleReconfigure()
                return START_STICKY
            }
        }

        // Foreground promptly — required within 5s when launched via
        // startForegroundService (QS tile), and before any potentially slow work.
        LangState.init(applicationContext)
        profileName = activeProfileName()
        startForeground(NOTIFICATION_ID, buildNotification())

        // Explicit URI from the UI, or (always-on / boot / tile) the persisted active profile.
        val uri = intent?.getStringExtra(EXTRA_URI)
            ?: dev.leshiy.data.Profiles.manager(applicationContext).activeUri()
            ?: run { stopTunnel(); return START_NOT_STICKY }

        // A session is already up or coming up (double tap, tile + widget, always-on + boot):
        // starting another would establish a second interface over the live one and trip the
        // bridge's AlreadyRunning. Only a FAILED session is replaced — that is what Retry means.
        val failed = TunnelRepository.status.value?.state == ConnState.FAILED
        if (sessionActive && !failed) return START_STICKY
        if (sessionActive) teardownSession()
        sessionActive = true
        startJob = scope.launch { buildAndStart(uri) }
        return START_STICKY
    }

    /** True from a start request until [stopTunnel]. Main-confined. */
    private var sessionActive = false
    private var startJob: Job? = null
    private var reconfigJob: Job? = null

    /** The domain rules [domainRoutes] was resolved from; a change invalidates the routes. */
    private var domainRoutesFor: List<String> = emptyList()

    /**
     * Apply edited split-tunnel rules (or the IPv6 switch) to the live session: re-establish the
     * interface and hand the engine the new fd — no re-dial. Debounced, because every re-establish
     * breaks in-flight flows and a user ticking through an app list would otherwise pay it per tap.
     */
    private fun scheduleReconfigure() {
        reconfigJob?.cancel()
        reconfigJob = scope.launch {
            delay(RECONFIGURE_DEBOUNCE_MS)
            // Still starting: the start path's establish() reads the rules itself.
            if (!TunnelRepository.running.value) return@launch
            // Routes accumulated for rules that changed (or were removed) must not linger.
            if (SplitStore(applicationContext).domains() != domainRoutesFor) domainRoutes = emptySet()
            if (reestablish(domainRoutes)) startDomainRefresh()
        }
    }

    /**
     * Resolved domain-rule routes currently baked into the interface. Only ever grows — see
     * [refreshDomainRoutes]. Confined to [scope]'s main dispatcher, so no synchronisation.
     */
    private var domainRoutes: Set<Pair<String, Int>> = emptySet()
    private var refreshJob: Job? = null

    /** `elapsedRealtime` of the first CONNECTED this session (0 = not yet). Drives the notification's
     *  live duration. Written from the bridge's status thread, read on main. */
    @Volatile
    private var connectedSince = 0L

    /** Ticks the ongoing notification's live up/down + duration while connected. */
    private var notifJob: Job? = null

    /** Registered default-network watch; see [startNetworkWatch]. Main-confined. */
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /** The default network the tunnel was last dialed on. Confined to the callback thread. */
    private var lastNetwork: Network? = null

    private suspend fun buildAndStart(uri: String) {
        try {
            // Domain rules resolve through the tunnel, so there is nothing to resolve them with
            // yet: start without them and let [startDomainRefresh] bake them in once connected.
            domainRoutes = emptySet()
            // Null means consent was revoked in the meantime; the Builder can also throw
            // (IllegalState / Security) when another app holds always-on VPN.
            val tun = establish(domainRoutes) ?: error("VPN permission not granted")
            startBridge(tun, uri)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "could not start the tunnel: $e")
            UiEvents.emit(UiMessage(stringsFor(LangState.lang.value).connFailed, UiMessageKind.CONNECTION_FAILURE))
            stopTunnel()
            return
        }
        TunnelRepository.setRunning(true)
        LeshiyTileService.requestUpdate(applicationContext)
        LeshiyWidgetProvider.requestUpdate(applicationContext)
        startDomainRefresh()
        startNetworkWatch()
        startNotificationUpdates()
        scheduleKeepaliveAlarm(applicationContext)
    }

    /**
     * Hand the interface to the bridge on [bridgeDispatcher], so it is ordered after any stop still
     * winding down. Ownership of the fd passes to native code, which closes it on stop; if the
     * hand-off never happens or `start` rejects it, the fd is closed here instead.
     */
    private suspend fun startBridge(tun: ParcelFileDescriptor, uri: String) {
        var handedOff = false
        try {
            withContext(bridgeDispatcher) {
                val fd = tun.detachFd()
                handedOff = true
                try {
                    bridge.start(fd, uri, statusListener)
                } catch (e: Exception) {
                    runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                    throw e
                }
            }
        } finally {
            if (!handedOff) runCatching { tun.close() }
        }
    }

    private val statusListener = object : StatusListener {
        override fun onStatus(status: Status) {
            // Stamp the session start on the first CONNECTED; kept across reconnects.
            if (status.state == ConnState.CONNECTED && connectedSince == 0L) {
                connectedSince = SystemClock.elapsedRealtime()
            }
            TunnelRepository.onStatus(status)
        }
    }

    /**
     * Refresh the ongoing notification every second while connected, so it shows live up/down and
     * session duration. IMPORTANCE_LOW, so these silent updates never buzz or interrupt. Built and
     * posted off the main thread (it shares a process with the UI), and skipped while the screen
     * is off, where nobody can see it.
     */
    private fun startNotificationUpdates() {
        notifJob?.cancel()
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val power = getSystemService(PowerManager::class.java)
        notifJob = scope.launch(Dispatchers.Default) {
            while (true) {
                delay(NOTIF_UPDATE_MS)
                if (power?.isInteractive == false) continue
                val st = TunnelRepository.status.value ?: continue
                if (st.state != ConnState.CONNECTED) continue
                val seconds = if (connectedSince > 0L) (SystemClock.elapsedRealtime() - connectedSince) / 1000 else 0L
                runCatching { nm.notify(NOTIFICATION_ID, buildNotification(st.upBytes, st.downBytes, seconds)) }
            }
        }
    }

    /** Build + establish the interface with `routes` as the resolved domain-rule routes. */
    private fun establish(routes: Set<Pair<String, Int>>): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("leshiy")
            .addAddress("10.71.0.2", 32)
            .addDnsServer(VPN_DNS)
            .setMtu(1400)
        configureSplit(builder, applicationContext, routes)
        return builder.establish()
    }

    /**
     * Resolve domain rules as soon as the tunnel connects, then periodically, re-establishing
     * when new IPs appear.
     *
     * Resolution goes through the tunnel ([LeshiyBridge.resolveViaTunnel]), never the system
     * resolver: this app is excluded from its own VPN, so a local lookup would hand the censor
     * the rule list in plaintext and take back its poisoned answers for exactly those domains.
     * Until the first pass lands the interface carries no domain routes (Include with only domain
     * rules is briefly a full tunnel — over-inclusion, the safe direction).
     *
     * Android's VPN routes are immutable once established, so a domain rule can only be honoured
     * by baking its resolved IPs into the interface — and any resolution is stale the moment a
     * DNS TTL expires. Without this, traffic to a domain's newer IPs silently
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
            TunnelRepository.status.first { it?.state == ConnState.CONNECTED }
            while (true) {
                refreshDomainRoutes()
                // Nothing resolved yet (tunnel still settling) → retry soon, not in half an hour.
                delay(if (domainRoutes.isEmpty()) DOMAIN_RETRY_MS else DOMAIN_REFRESH_MS)
            }
        }
    }

    /** One refresh pass. Visible for the service's own loop; no-ops unless the union grew. */
    private suspend fun refreshDomainRoutes() {
        val rules = SplitStore(applicationContext).domains()
        val fresh = withContext(Dispatchers.IO) { resolveDomainRoutes(applicationContext) }
        val union = mergeDomainRoutes(domainRoutes, fresh)
        if (union == domainRoutes) return // nothing new — never churn the interface for free
        if (reestablish(union)) {
            domainRoutes = union
            domainRoutesFor = rules
        }
    }

    /**
     * Establish a fresh interface for the current rules plus [routes] and move the engine onto it.
     * Returns false if the interface could not be replaced (the session keeps its current one, or
     * — if the hand-over itself failed — has been torn down).
     */
    private fun reestablish(routes: Set<Pair<String, Int>>): Boolean {
        // establish() supersedes the live interface, keeping the old fd valid until we drop it;
        // if it fails, the platform leaves the existing interface untouched, so we keep running
        // on the routes we have and simply try again next pass.
        val tun = runCatching { establish(routes) }.getOrNull() ?: run {
            Log.w(TAG, "re-establish failed; keeping current routes")
            return false
        }
        // Past this point the old interface is superseded and packets are already being routed to
        // `tun`, so the fd MUST reach the engine. If handing it over fails there is nothing left
        // reading the live interface — every packet would blackhole — so reclaim the fd (detachFd
        // took it out of ParcelFileDescriptor's ownership) and tear down rather than wedge.
        val fd = tun.detachFd()
        return runCatching { bridge.reattachTun(fd) }
            .onFailure { e ->
                Log.w(TAG, "reattach after re-establish failed; stopping: $e")
                runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                stopTunnel()
            }
            .isSuccess
    }

    /**
     * Schedule the sleep-keepalive alarm, if the user opted in (ADR-0031).
     *
     * The CPU suspends seconds after screen-off and every tokio timer freezes with it, so nothing
     * pings and the server eventually gives up on us. `setExactAndAllowWhileIdle` is the only way
     * to wake from Doze, and it is capped at once per ~9 minutes per app — which is precisely why
     * the server's tolerance had to be negotiated up to 10 minutes first. At 45s no alarm could
     * ever have arrived in time.
     *
     * The receiver does not need to *do* anything: waking the CPU is the whole job. The mux's
     * keepalive is driven by the wall clock, so it notices on its first poll that a ping is
     * overdue and sends one. It just has to stay awake long enough for that poll — hence the brief
     * hold in [KeepalivePingReceiver].
     *
     * Deliberately not exact-alarm-permission territory: `SCHEDULE_EXACT_ALARM` is for
     * user-visible scheduled events (alarms, reminders) and Google rejects it for keepalives.
     * `setAndAllowWhileIdle` is inexact, needs no permission, and a keepalive does not care about
     * a few minutes of jitter — the tolerance has 90 seconds of headroom over the interval.
     */
    /**
     * Watch the default network, so a Wi-Fi↔cellular switch re-dials at once.
     *
     * Two jobs, of unequal weight. [setUnderlyingNetworks] tells the platform what the VPN rides
     * on so its capabilities (metered, validated, …) track the real upstream; the default of
     * `null` already means "whatever the system default is", which is where our own sockets go
     * anyway since the app is disallowed from its own tunnel — so that part is belt-and-braces.
     *
     * The re-dial is the real point. When the default network changes, the tunnel's socket is
     * already dead — its source address no longer exists — but nothing on the wire says so, so
     * the mux would spend its whole idle timeout finding out while every flow hangs. The OS knows
     * immediately; this passes that on.
     *
     * Callbacks arrive serialised on a ConnectivityThread, so [lastNetwork] is confined to it.
     */
    private fun startNetworkWatch() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                runCatching { setUnderlyingNetworks(arrayOf(network)) }
                val previous = lastNetwork
                lastNetwork = network
                // The first callback after registering only reports where we already are — the
                // tunnel was dialed on it. Only a *change* means the socket's source is gone, and
                // a re-dial costs a handshake and every in-flight flow, so never spend one for
                // a mere capability update.
                if (previous != null && previous != network) {
                    Log.i(TAG, "default network changed; forcing reconnect")
                    runCatching { bridge.networkChanged() }
                        .onFailure { Log.w(TAG, "networkChanged failed: $it") }
                }
            }

            override fun onLost(network: Network) {
                if (network == lastNetwork) lastNetwork = null
            }
        }
        runCatching { cm.registerDefaultNetworkCallback(cb) }
            .onSuccess { networkCallback = cb }
            .onFailure { Log.w(TAG, "could not watch the default network: $it") }
    }

    private fun stopNetworkWatch() {
        val cb = networkCallback ?: return
        networkCallback = null
        lastNetwork = null
        runCatching {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        }
    }

    /**
     * Resolve network-mode domain rules to `(ip, prefix)` routes through the tunnel. Blocking and
     * bounded (see [LeshiyBridge.resolveViaTunnel]); empty until the tunnel is up.
     */
    private fun resolveDomainRoutes(ctx: Context): Set<Pair<String, Int>> {
        if (!hasDomainRules(ctx)) return emptySet()
        val hosts = SplitStore(ctx).domains().map { it.removePrefix("*.") }.distinct()
        return runCatching { bridge.resolveViaTunnel(hosts, MAX_IPS_PER_DOMAIN.toUInt()) }
            .getOrDefault(emptyList())
            .mapTo(mutableSetOf()) { ip -> ip to if (':' in ip) 128 else 32 }
    }

    /** True when network-mode domain rules are active and worth resolving. */
    private fun hasDomainRules(ctx: Context): Boolean {
        val split = SplitStore(ctx)
        return split.kind() == SplitKind.NETWORK &&
            split.netMode() != PerAppMode.OFF &&
            split.domains().isNotEmpty()
    }

    /**
     * End the current session's engine and background work, leaving the service (and its
     * foreground notification) up. `bridge.stop()` can take up to its grace period, so it runs on
     * [bridgeDispatcher] — never on main, where it used to freeze the UI.
     */
    private fun teardownSession() {
        startJob?.cancel()
        startJob = null
        reconfigJob?.cancel()
        reconfigJob = null
        refreshJob?.cancel()
        refreshJob = null
        domainRoutesFor = emptyList()
        notifJob?.cancel()
        notifJob = null
        connectedSince = 0L
        stopNetworkWatch()
        cancelKeepaliveAlarm(applicationContext)
        stopBridge(bridge)
    }

    private fun stopTunnel() {
        sessionActive = false
        teardownSession()
        TunnelRepository.setRunning(false)
        LeshiyTileService.requestUpdate(applicationContext)
        LeshiyWidgetProvider.requestUpdate(applicationContext)
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
                val plan = netRoutePlan(
                    mode = split.netMode(),
                    cidrs = split.cidrs().mapNotNull { cidrParts(it) } + domainRoutes,
                    blockV6 = blockV6,
                    canExclude = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU,
                )
                if (plan.v6Address) enableV6Routing(b)
                plan.routes.forEach { (a, p) -> runCatching { b.addRoute(a, p) } }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    plan.excludes.forEach { (a, p) ->
                        runCatching { b.excludeRoute(IpPrefix(InetAddresses.parseNumericAddress(a), p)) }
                    }
                }
                // Loop avoidance: our own dial must bypass the tunnel.
                runCatching { b.addDisallowedApplication(ctx.packageName) }
            }
            SplitKind.APP -> {
                b.addRoute("0.0.0.0", 0)
                if (blockV6) killV6(b)
                val store = PerAppStore(ctx)
                val plan = perAppPlan(store.mode(), store.packages(), ctx.packageName) { pkg ->
                    runCatching { ctx.packageManager.getApplicationInfo(pkg, 0) }.isSuccess
                }
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
        stopNetworkWatch()
        cancelKeepaliveAlarm(applicationContext)
        stopBridge(bridge)
        TunnelRepository.setRunning(false)
        LeshiyTileService.requestUpdate(applicationContext)
        LeshiyWidgetProvider.requestUpdate(applicationContext)
        scope.cancel()
        super.onDestroy()
    }

    /** Display name of the active profile, or null when unnamed/absent. */
    private fun activeProfileName(): String? =
        runCatching {
            dev.leshiy.data.Profiles.manager(applicationContext)
                .list().firstOrNull { it.isActive }?.name
        }.getOrNull()?.takeIf { it.isNotBlank() }

    /**
     * The session's profile name, read once per start rather than on every notification tick —
     * and it is the profile the tunnel actually dialed, even if another is activated meanwhile.
     */
    @Volatile
    private var profileName: String? = null

    private val openAppIntent by lazy {
        PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private val stopIntent by lazy {
        PendingIntent.getService(
            this,
            1,
            Intent(this, LeshiyVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Leshiy VPN", NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun buildNotification(
        up: ULong = 0u,
        down: ULong = 0u,
        seconds: Long = -1L,
    ): Notification {
        val profileName = profileName
        val s = stringsFor(LangState.lang.value)
        // With live stats (seconds >= 0): profile name in the title, throughput + duration in the
        // text. Without (the initial foreground notification): the plain connected line.
        val title = if (seconds >= 0L) (profileName ?: "Leshiy") else "Leshiy"
        val text = if (seconds >= 0L) {
            "↓ ${formatBytes(down)}   ↑ ${formatBytes(up)}   ·   ${formatDuration(seconds)}"
        } else {
            profileName?.let { String.format(s.notifConnected, it) } ?: s.notifConnectedPlain
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_qs_leshiy)
            .setContentIntent(openAppIntent)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, R.drawable.ic_qs_leshiy),
                    s.notifDisconnect,
                    stopIntent,
                ).build(),
            )
            .setOngoing(true)
            .build()
    }

    companion object {
        const val EXTRA_URI = "uri"
        const val ACTION_STOP = "dev.leshiy.STOP"
        private const val ACTION_RECONFIGURE = "dev.leshiy.RECONFIGURE"
        private const val RECONFIGURE_DEBOUNCE_MS = 1500L

        /**
         * Push edited split-tunnel rules / IPv6 blocking into the running tunnel. No-op when the
         * tunnel is down — the next connect reads the rules anyway.
         */
        fun reconfigure(context: Context) {
            if (!TunnelRepository.running.value) return
            runCatching {
                context.startService(Intent(context, LeshiyVpnService::class.java).setAction(ACTION_RECONFIGURE))
            }.onFailure { Log.w(TAG, "could not apply the new rules live: $it") }
        }
        private const val CHANNEL_ID = "leshiy_vpn"
        private const val NOTIFICATION_ID = 1
        private const val TAG = "LeshiyVpnService"

        /** How often the ongoing notification's live up/down + duration refresh while connected. */
        private const val NOTIF_UPDATE_MS = 1000L

        /**
         * How often domain rules are re-resolved. Well above a typical DNS TTL (60–300s) on
         * purpose: chasing every rotation would re-establish the interface constantly, and each
         * re-establish breaks in-flight connections. Since the resolved set accumulates rather
         * than churns, a slow cadence still converges — it just takes longer to discover a large
         * CDN pool. Matches the desktop resolver's REFRESH.
         */
        private const val DOMAIN_REFRESH_MS = 30 * 60 * 1000L

        /** Retry gap while no domain rule has resolved yet (tunnel still settling, resolver slow). */
        private const val DOMAIN_RETRY_MS = 60 * 1000L

        /** Addresses taken per domain per resolution — a guard against a huge RRset. */
        private const val MAX_IPS_PER_DOMAIN = 8

        /**
         * Gap between sleep-keepalive wakes. Doze floors allow-while-idle alarms at ~9 minutes per
         * app, so this is the fastest that is actually achievable — which is why the server's
         * tolerance had to be negotiated to 10 minutes (ADR-0031) before the alarm could work at
         * all. The 90s of headroom absorbs the jitter of an inexact alarm.
         */
        private const val KEEPALIVE_ALARM_MS = 9 * 60 * 1000L

        /**
         * Serialises every bridge start/stop, process-wide. Stop must stay off the main thread,
         * and a connect issued right after a disconnect must not overtake the stop — including
         * across service instances, since the native TUN-fd slot is process-global.
         */
        private val bridgeExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "leshiy-bridge") }
        private val bridgeDispatcher = bridgeExecutor.asCoroutineDispatcher()

        /** Not on the service scope: that is cancelled in onDestroy, and the stop must still run. */
        private fun stopBridge(bridge: LeshiyBridge) {
            bridgeExecutor.execute { bridge.stop() }
        }

        /**
         * Schedule the next sleep-keepalive wake, if the user opted in (ADR-0031).
         *
         * The receiver sends nothing: waking the CPU is the whole job, because the mux's keepalive
         * is driven by the wall clock and fires on its first poll after any wake.
         *
         * `setAndAllowWhileIdle`, not the exact variant: `SCHEDULE_EXACT_ALARM` is meant for
         * user-visible scheduled events and Google rejects it for keepalives. Inexact needs no
         * permission, and a keepalive does not care about a few minutes of jitter.
         *
         * Static so [KeepalivePingReceiver] can re-arm — allow-while-idle alarms are one-shot, and
         * a missed re-arm would silently end the keepalive.
         */
        fun scheduleKeepaliveAlarm(context: Context) {
            if (!AppPrefs.sleepKeepalive(context)) return
            val am = context.getSystemService(AlarmManager::class.java) ?: return
            runCatching {
                am.setAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    SystemClock.elapsedRealtime() + KEEPALIVE_ALARM_MS,
                    keepalivePendingIntent(context),
                )
            }.onFailure { Log.w(TAG, "could not schedule the keepalive alarm: $it") }
        }

        fun cancelKeepaliveAlarm(context: Context) {
            runCatching {
                context
                    .getSystemService(AlarmManager::class.java)
                    ?.cancel(keepalivePendingIntent(context))
            }
        }

        private fun keepalivePendingIntent(context: Context): PendingIntent =
            PendingIntent.getBroadcast(
                context,
                0,
                Intent(context, KeepalivePingReceiver::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
    }
}
