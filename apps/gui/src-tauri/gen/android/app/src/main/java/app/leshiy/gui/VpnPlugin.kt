package app.leshiy.gui

import android.app.Activity
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class RouteArg {
    var address: String = ""
    var prefix: Int = 0
}

@InvokeArg
class EstablishArgs {
    var address: String = "10.71.0.2"
    var prefix: Int = 32
    var mtu: Int = 1400
    var dns: List<String> = emptyList()
    var routes: List<RouteArg> = emptyList()
    var excludeRoutes: List<RouteArg> = emptyList()
    var perAppMode: String = "off"
    var perAppPackages: List<String> = emptyList()
}

/**
 * The Rust↔Kotlin bridge for the in-process VPN, invoked from `mobile.rs` via `run_mobile_plugin`:
 *   - `prepare`   → request the one-time VPN consent (system dialog)
 *   - `establish` → start [LeshiyVpnService] (foreground) and return the established TUN fd
 *   - `stop`      → stop the service
 */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /**
     * Register a ConnectivityManager callback so the app learns about network
     * online/offline transitions authoritatively (more reliable than the webview's
     * `navigator.onLine`). Each change is forwarded to JS via the `connectivity`
     * event; the frontend calls the `set_online` command so the supervisor parks
     * its reconnect backoff while offline instead of spinning failing dials (battery).
     */
    override fun load(webView: android.webkit.WebView) {
        super.load(webView)
        val cm = activity.getSystemService(android.content.Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager ?: return
        connectivityManager = cm
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = emitConnectivity(true)
            override fun onLost(network: Network) = emitConnectivity(false)
            override fun onUnavailable() = emitConnectivity(false)
        }
        networkCallback = cb
        try {
            cm.registerDefaultNetworkCallback(cb)
        } catch (_: Exception) {
            // Best-effort: if registration fails, the webview navigator.onLine path
            // still drives connectivity.
        }
    }

    private fun emitConnectivity(online: Boolean) {
        val o = JSObject()
        o.put("online", online)
        trigger("connectivity", o)
    }

    /** Ask for VPN consent. Resolves `{ granted: Boolean }`. */
    @Command
    fun prepare(invoke: Invoke) {
        val intent = VpnService.prepare(activity)
        if (intent == null) {
            val ret = JSObject()
            ret.put("granted", true)
            invoke.resolve(ret)
        } else {
            startActivityForResult(invoke, intent, "prepareResult")
        }
    }

    @ActivityCallback
    fun prepareResult(invoke: Invoke, result: ActivityResult) {
        val ret = JSObject()
        ret.put("granted", result.resultCode == Activity.RESULT_OK)
        invoke.resolve(ret)
    }

    /** Build + bring up the tunnel interface; resolves `{ fd: Int }` (the detached TUN fd). */
    @Command
    fun establish(invoke: Invoke) {
        val args = invoke.parseArgs(EstablishArgs::class.java)
        LeshiyVpnService.pendingConfig = VpnConfig(
            address = args.address,
            prefix = args.prefix,
            mtu = args.mtu,
            dns = args.dns,
            routes = args.routes.map { VpnRoute(it.address, it.prefix) },
            excludeRoutes = args.excludeRoutes.map { VpnRoute(it.address, it.prefix) },
            perAppMode = args.perAppMode,
            perAppPackages = args.perAppPackages,
        )
        LeshiyVpnService.onEstablished = { fd ->
            val ret = JSObject()
            ret.put("fd", fd)
            invoke.resolve(ret)
        }
        LeshiyVpnService.onError = { msg -> invoke.reject(msg) }
        val intent = Intent(activity, LeshiyVpnService::class.java)
        ContextCompat.startForegroundService(activity, intent)
    }

    /** Stop the VPN service. */
    @Command
    fun stop(invoke: Invoke) {
        LeshiyVpnService.instance?.stopVpn()
        invoke.resolve(JSObject())
    }

    /** List launchable installed apps for the per-app split-tunnel picker. Resolves
     *  `{ apps: [{ package, label }] }` (excluding ourselves). */
    @Command
    fun listApps(invoke: Invoke) {
        val pm = activity.packageManager
        val main = Intent(Intent.ACTION_MAIN, null).apply { addCategory(Intent.CATEGORY_LAUNCHER) }
        val arr = app.tauri.plugin.JSArray()
        val seen = HashSet<String>()
        for (ri in pm.queryIntentActivities(main, 0)) {
            val pkg = ri.activityInfo.packageName
            if (pkg == activity.packageName || !seen.add(pkg)) continue
            val o = JSObject()
            o.put("package", pkg)
            o.put("label", ri.loadLabel(pm).toString())
            arr.put(o)
        }
        val ret = JSObject()
        ret.put("apps", arr)
        invoke.resolve(ret)
    }

    /** Read the system clipboard as text. Resolves `{ text: String }` ("" if empty). The Tauri
     *  clipboard plugin proved unreliable in the Android webview, so read it natively here. */
    @Command
    fun readClipboard(invoke: Invoke) {
        val cm = activity.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
            as? android.content.ClipboardManager
        val clip = cm?.primaryClip
        val text = if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0).coerceToText(activity).toString()
        } else {
            ""
        }
        val ret = JSObject()
        ret.put("text", text)
        invoke.resolve(ret)
    }
}
