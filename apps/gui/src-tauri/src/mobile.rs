//! Android in-process VPN bridge.
//!
//! On Android there is no privileged helper: the app's own `VpnService` (Kotlin, in `gen/android`)
//! builds the tunnel interface and hands its TUN fd to the engine, which runs in-process here via
//! `TunEngine::run`. The Rust↔Kotlin calls go through Tauri's mobile-plugin channel
//! (`run_mobile_plugin`) — see `VpnPlugin.kt`:
//!   - `prepare`   → `VpnService.prepare` + consent activity → `{ granted }`
//!   - `establish` → start the foreground service, build the tunnel, return `{ fd }`
//!   - `stop`      → stop the foreground service
//!
//! Loop avoidance: the service calls `addDisallowedApplication(ourPackage)`, so our own outbound
//! socket (the tunnel dial) bypasses the VPN — no per-socket `protect()` needed.
use crate::{build_split_plan, AppState};
use leshiy_client::{
    ByteCounters, PerAppMode, RealTransport, Settings, SplitMode, SplitPlan, State, Throughput,
    Transport, TransportPref, Tunnel,
};
use leshiy_tun::{TunConfig, TunEngine};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::{Emitter, Wry};
use tokio::sync::Notify;

/// Handle to the Kotlin `VpnPlugin`, set once during plugin setup.
static VPN_PLUGIN: OnceLock<tauri::plugin::PluginHandle<Wry>> = OnceLock::new();

/// Dedicated multi-thread runtime for the dial + engine. Created once and **never dropped**, so it
/// (and the tunnel/engine tasks on it) survive the Tauri Activity/app being destroyed when the user
/// closes the app — the foreground `VpnService` keeps the process alive, and the VPN keeps running.
static ENGINE_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn engine_runtime() -> &'static tokio::runtime::Runtime {
    ENGINE_RT.get_or_init(|| {
        // Phase 1b: cap the engine runtime to a single worker thread on the phone.
        // The data plane is I/O-bound and bursty, not CPU-parallel, so the default
        // (one worker per core) only adds idle wakeups and context switches that
        // cost battery. `worker_threads(1)` keeps the spawn-and-forget model (a
        // current_thread runtime would only drive tasks during block_on).
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("failed to build the engine runtime")
    })
}

/// A running in-process VPN session: the cooperative-cancel signal for the engine (same graceful
/// teardown contract as desktop — never abort) plus its task handle (on [`engine_runtime`]).
pub struct VpnSession {
    /// User-stop signal; the reconnect loop distinguishes this from a transient drop.
    pub stop: tokio::sync::watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<()>,
}

/// Register the Tauri mobile plugin that fronts the Kotlin `VpnPlugin`. Called from `run()`.
pub fn init() -> tauri::plugin::TauriPlugin<Wry> {
    tauri::plugin::Builder::new("leshiy-vpn")
        .setup(|_app, api| {
            let handle = api.register_android_plugin("app.leshiy.gui", "VpnPlugin")?;
            let _ = VPN_PLUGIN.set(handle);
            Ok(())
        })
        .build()
}

#[derive(Serialize)]
struct RouteArg {
    address: String,
    prefix: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EstablishArgs {
    address: String,
    prefix: u8,
    mtu: u16,
    dns: Vec<String>,
    routes: Vec<RouteArg>,
    exclude_routes: Vec<RouteArg>,
    /// Per-app routing: "off" | "include" | "exclude", with the package list.
    per_app_mode: String,
    per_app_packages: Vec<String>,
}

#[derive(Deserialize)]
struct PrepareResp {
    granted: bool,
}

#[derive(Deserialize)]
struct EstablishResp {
    fd: i32,
}

#[derive(Deserialize)]
struct ClipboardResp {
    text: String,
}

#[derive(Deserialize)]
struct AppsResp {
    apps: Vec<crate::AppInfo>,
}

/// List launchable installed apps via the native Kotlin plugin (for the per-app picker).
pub fn list_apps() -> Result<Vec<crate::AppInfo>, String> {
    let plugin = VPN_PLUGIN
        .get()
        .ok_or_else(|| "VPN plugin not registered".to_string())?;
    let resp: AppsResp = plugin
        .run_mobile_plugin("listApps", ())
        .map_err(|e| e.to_string())?;
    Ok(resp.apps)
}

/// Read the system clipboard via the native Kotlin plugin (the Tauri clipboard plugin returns
/// empty in the Android webview).
pub fn read_clipboard() -> Result<String, String> {
    let plugin = VPN_PLUGIN
        .get()
        .ok_or_else(|| "VPN plugin not registered".to_string())?;
    let resp: ClipboardResp = plugin
        .run_mobile_plugin("readClipboard", ())
        .map_err(|e| e.to_string())?;
    Ok(resp.text)
}

/// Map the merged split plan to VpnService routes. Exclude base = full tunnel (`0.0.0.0/0`) plus
/// per-CIDR `excludeRoute` (API 33+, applied best-effort by the service); Include base = only the
/// listed CIDRs. IPv4-only this phase (IPv6 isn't tunnelled). Domain rules aren't represented here
/// (resolved at runtime; a no-op on Android's `NullController`) — a documented limitation.
fn routes_for_builder(split: &SplitPlan) -> (Vec<RouteArg>, Vec<RouteArg>) {
    let (inc, exc) = split.effective();
    let v4 = |c: &leshiy_client::SplitCidr| c.addr.is_ipv4();
    let to_arg = |c: &leshiy_client::SplitCidr| RouteArg {
        address: c.addr.to_string(),
        prefix: c.prefix,
    };
    match split.base_mode {
        SplitMode::Exclude => (
            vec![RouteArg {
                address: "0.0.0.0".into(),
                prefix: 0,
            }],
            exc.cidrs.iter().filter(|c| v4(c)).map(to_arg).collect(),
        ),
        SplitMode::Include => (
            inc.cidrs.iter().filter(|c| v4(c)).map(to_arg).collect(),
            Vec::new(),
        ),
    }
}

/// Publish per-second throughput to the webview (~1 Hz) until aborted, mirroring the desktop
/// helper's sampler so the GUI shows live speed/totals in VPN mode.
async fn sample_throughput(app: tauri::AppHandle, counters: Arc<ByteCounters>) {
    let mut tput = Throughput::new();
    let mut last = std::time::Instant::now();
    let mut fg = crate::foreground_rx();
    // Park (no 1 Hz wakeups) whenever the app is backgrounded — the webview reports
    // visibility via `set_foreground`. This is the main idle-battery win on Android.
    while leshiy_client::await_next_sample(&mut fg, Duration::from_secs(1)).await {
        if !*fg.borrow() {
            // Resumed-to-background race or an early foreground change: don't emit;
            // reset the baseline so the next real sample isn't a giant delta.
            last = std::time::Instant::now();
            continue;
        }
        let (up, down) = counters.totals();
        let now = std::time::Instant::now();
        let rates = tput.sample(up, down, now.duration_since(last));
        last = now;
        let _ = app.emit("tunnel:stats", rates);
    }
}

/// Start the Android VPN: consent → establish the tunnel interface → dial → run the engine.
pub async fn connect(state: &AppState, uri: String, settings: Settings) -> Result<(), String> {
    let app = state
        .app_handle
        .get()
        .cloned()
        .ok_or_else(|| "app not ready".to_string())?;
    let plugin = VPN_PLUGIN
        .get()
        .ok_or_else(|| "VPN plugin not registered".to_string())?;

    let _ = app.emit("tunnel:state", "Connecting");
    tracing::info!("android connect: requesting consent + establishing tunnel");

    // 1. VPN consent (one-time system dialog).
    let prep: PrepareResp = plugin
        .run_mobile_plugin("prepare", ())
        .map_err(|e| e.to_string())?;
    if !prep.granted {
        let _ = app.emit("tunnel:state", "Error");
        return Err("VPN permission was denied".into());
    }

    // 2. Make sure enabled subscriptions (routing presets) are fetched — otherwise their CIDRs
    //    aren't in the cache yet and the preset wouldn't route. Fetch any enabled-but-uncached
    //    ones now (conditional GET; cached ones are skipped). Failures are logged, not fatal.
    let missing: Vec<String> = {
        let s = state.settings.lock().unwrap();
        let c = state.sub_cache.lock().unwrap();
        s.rule_subscriptions
            .iter()
            .filter(|x| x.enabled && c.get(&x.id).is_none())
            .map(|x| x.id.clone())
            .collect()
    };
    if !missing.is_empty() {
        tracing::info!(
            count = missing.len(),
            "fetching uncached enabled subscriptions"
        );
        for id in &missing {
            if let Err(e) = crate::refresh_subs(state, Some(id)).await {
                tracing::warn!(sub = %id, "subscription refresh failed: {e}");
            }
        }
    }

    // 3. Build the tunnel interface (foreground service does establish()).
    let cache = state.sub_cache.lock().unwrap().clone();
    let split = build_split_plan(&settings, &cache);
    let (routes, exclude_routes) = routes_for_builder(&split);
    tracing::info!(
        base = ?split.base_mode,
        routes = routes.len(),
        exclude_routes = exclude_routes.len(),
        subs_enabled = settings.rule_subscriptions.iter().filter(|s| s.enabled).count(),
        cached_subs = cache.entries.len(),
        "android split routes for VpnService.Builder"
    );
    let (per_app_mode, per_app_packages) = match settings.per_app.mode {
        PerAppMode::Off => ("off", Vec::new()),
        PerAppMode::Include => ("include", settings.per_app.packages.clone()),
        PerAppMode::Exclude => ("exclude", settings.per_app.packages.clone()),
    };
    let establish_args = EstablishArgs {
        address: "10.71.0.2".into(),
        prefix: 32,
        mtu: settings.vpn_mtu,
        dns: vec![settings.vpn_dns.clone()],
        routes,
        exclude_routes,
        per_app_mode: per_app_mode.into(),
        per_app_packages,
    };
    let est: EstablishResp = plugin
        .run_mobile_plugin("establish", &establish_args)
        .map_err(|e| {
            let _ = app.emit("tunnel:state", "Error");
            e.to_string()
        })?;

    // 4. Build config + run the dial AND engine on the dedicated ENGINE runtime, NOT Tauri's.
    //    Tauri's runtime/app is torn down when the Activity is destroyed (app closed/swiped), which
    //    would kill the tunnel's mux tasks + the engine even though the foreground service keeps
    //    the process alive — so the VPN would stop on close. The static engine runtime outlives the
    //    Activity, so the tunnel keeps pumping in the background as long as the process lives.
    //    (server_ip/orig_gateway are unused on Android — AndroidOps ignores the plan.)
    let cfg = TunConfig {
        tun_name: "leshiy0".into(),
        mtu: settings.vpn_mtu,
        dns: vec![settings
            .vpn_dns
            .parse()
            .unwrap_or_else(|_| "1.1.1.1".parse().unwrap())],
        split,
        ..TunConfig::default()
    };
    // Stop signal: `disconnect` flips it to `true`. The reconnect loop uses it to tell a
    // user-requested stop apart from a transient tunnel drop (network change).
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let app_task = app.clone();
    let first_fd = est.fd;
    let task = engine_runtime().spawn(async move {
        run_session_with_reconnect(app_task, uri, cfg, establish_args, first_fd, stop_rx).await;
    });

    *state.android_vpn.lock().unwrap() = Some(VpnSession {
        stop: stop_tx,
        task,
    });
    Ok(())
}

/// Run the in-process VPN with automatic reconnection across tunnel drops (the common
/// case being an Android network change, Wi-Fi ⇄ LTE, which kills the server socket but
/// leaves the TUN interface valid). On a drop we re-establish the TUN interface (the
/// engine closed the old fd on teardown) and re-dial, gated on connectivity + backoff,
/// so the user never has to manually disconnect/reconnect. Exits only on an explicit
/// user stop (`stop_rx == true`).
async fn run_session_with_reconnect(
    app: tauri::AppHandle,
    uri: String,
    cfg: TunConfig,
    establish_args: EstablishArgs,
    first_fd: i32,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    const BACKOFF_BASE: Duration = Duration::from_millis(500);
    const BACKOFF_MAX: Duration = Duration::from_secs(30);

    let mut online = crate::online_rx();
    let counters = Arc::new(ByteCounters::new());
    let sampler = tokio::spawn(sample_throughput(app.clone(), counters.clone()));
    let mut fd = first_fd; // first interface already established by `connect`
    let mut need_establish = false; // re-establish only after a drop
    let mut backoff = BACKOFF_BASE;

    loop {
        if *stop_rx.borrow() {
            break;
        }
        // Don't burn cycles dialing while the device is offline; park until connectivity returns.
        if !*online.borrow_and_update() {
            let _ = app.emit("tunnel:state", "Reconnecting");
            tokio::select! {
                _ = online.wait_for(|v| *v) => {}
                _ = stop_rx.wait_for(|v| *v) => break,
            }
        }
        // After a drop the engine closed the old TUN fd, so re-establish to get a fresh interface.
        if need_establish {
            match establish_tun(&establish_args) {
                Ok(new_fd) => fd = new_fd,
                Err(e) => {
                    tracing::warn!("android re-establish failed: {e}");
                    let _ = app.emit("tunnel:state", "Reconnecting");
                    if backoff_or_stop(backoff, &mut stop_rx).await {
                        break;
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            }
        }

        let tunnel: Arc<dyn Tunnel> = match RealTransport.dial(&uri, TransportPref::Tcp).await {
            Ok(t) => Arc::from(t),
            Err(e) => {
                tracing::warn!("android dial failed: {e}");
                let _ = app.emit("tunnel:state", "Reconnecting");
                // The fd from the (re-)establish above is still valid (engine never ran), so just
                // back off and retry the dial without re-establishing.
                if backoff_or_stop(backoff, &mut stop_rx).await {
                    break;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        backoff = BACKOFF_BASE;
        leshiy_tun::sys::set_tun_fd(fd);
        let _ = app.emit("tunnel:state", State::Connected);

        // Run the engine until the tunnel dies OR the user stops. The bridge task fans either
        // signal into the engine's cooperative-cancel `Notify`.
        let eng_stop = Arc::new(Notify::new());
        let bridge = {
            let es = eng_stop.clone();
            let t = tunnel.clone();
            let mut stop_b = stop_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = t.closed() => {}
                    _ = stop_b.wait_for(|v| *v) => {}
                }
                es.notify_one();
            })
        };
        if let Err(e) = TunEngine::run(tunnel, cfg.clone(), counters.clone(), eng_stop).await {
            tracing::warn!("android tun engine exited: {e}");
        }
        bridge.abort();

        if *stop_rx.borrow() {
            break; // user-requested disconnect
        }
        // Tunnel dropped (or engine errored) without a user stop → reconnect.
        tracing::info!("android tunnel dropped; reconnecting");
        let _ = app.emit("tunnel:state", "Reconnecting");
        need_establish = true;
    }

    sampler.abort();
    let _ = app.emit("tunnel:state", State::Disconnected);
}

/// Sleep for `d`, but return `true` early if a user stop is requested meanwhile.
async fn backoff_or_stop(d: Duration, stop_rx: &mut tokio::sync::watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = stop_rx.wait_for(|v| *v) => true,
    }
}

/// (Re-)establish the VpnService TUN interface via the Kotlin plugin, returning the new fd.
/// Safe to call repeatedly on the running service — `establish()` atomically replaces the
/// interface and no consent re-prompt is needed.
fn establish_tun(args: &EstablishArgs) -> Result<i32, String> {
    let plugin = VPN_PLUGIN
        .get()
        .ok_or_else(|| "VPN plugin not registered".to_string())?;
    let est: EstablishResp = plugin
        .run_mobile_plugin("establish", args)
        .map_err(|e| e.to_string())?;
    Ok(est.fd)
}

/// Stop the Android VPN: signal the engine to tear down gracefully, then stop the service.
pub async fn disconnect(state: &AppState) -> Result<(), String> {
    let app = state.app_handle.get().cloned();
    if let Some(app) = &app {
        let _ = app.emit("tunnel:state", "Disconnecting");
    }
    let session = state.android_vpn.lock().unwrap().take();
    if let Some(session) = session {
        let _ = session.stop.send(true);
        let _ = session.task.await;
    }
    if let Some(plugin) = VPN_PLUGIN.get() {
        let _: Result<serde_json::Value, _> = plugin.run_mobile_plugin("stop", ());
    }
    if let Some(app) = &app {
        let _ = app.emit("tunnel:state", State::Disconnected);
    }
    Ok(())
}
