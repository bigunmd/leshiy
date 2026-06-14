package app.leshiy.desktop

import android.app.Activity
import android.content.Intent
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
}

/**
 * The Rust↔Kotlin bridge for the in-process VPN, invoked from `mobile.rs` via `run_mobile_plugin`:
 *   - `prepare`   → request the one-time VPN consent (system dialog)
 *   - `establish` → start [LeshiyVpnService] (foreground) and return the established TUN fd
 *   - `stop`      → stop the service
 */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {

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
}
