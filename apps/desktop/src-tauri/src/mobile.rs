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
    pub cancel: Arc<Notify>,
    pub task: tokio::task::JoinHandle<()>,
}

/// Register the Tauri mobile plugin that fronts the Kotlin `VpnPlugin`. Called from `run()`.
pub fn init() -> tauri::plugin::TauriPlugin<Wry> {
    tauri::plugin::Builder::new("leshiy-vpn")
        .setup(|_app, api| {
            let handle = api.register_android_plugin("app.leshiy.desktop", "VpnPlugin")?;
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
    let est: EstablishResp = plugin
        .run_mobile_plugin(
            "establish",
            EstablishArgs {
                address: "10.71.0.2".into(),
                prefix: 32,
                mtu: settings.vpn_mtu,
                dns: vec![settings.vpn_dns.clone()],
                routes,
                exclude_routes,
                per_app_mode: per_app_mode.into(),
                per_app_packages,
            },
        )
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
    let fd = est.fd;
    let cancel = Arc::new(Notify::new());
    let engine_cancel = cancel.clone();
    let app_task = app.clone();
    let task = engine_runtime().spawn(async move {
        // Dial here (on the surviving runtime) so the tunnel's mux tasks live past app close.
        let tunnel: Arc<dyn Tunnel> = match RealTransport.dial(&uri, TransportPref::Tcp).await {
            Ok(t) => Arc::from(t),
            Err(e) => {
                tracing::warn!("android dial failed: {e}");
                let _ = app_task.emit("tunnel:state", "Error");
                return;
            }
        };
        leshiy_tun::sys::set_tun_fd(fd);
        let counters = Arc::new(ByteCounters::new());
        let sampler = tokio::spawn(sample_throughput(app_task.clone(), counters.clone()));
        let _ = app_task.emit("tunnel:state", State::Connected);
        if let Err(e) = TunEngine::run(tunnel, cfg, counters, engine_cancel).await {
            tracing::warn!("android tun engine exited: {e}");
        }
        sampler.abort();
        let _ = app_task.emit("tunnel:state", State::Disconnected);
    });

    *state.android_vpn.lock().unwrap() = Some(VpnSession { cancel, task });
    Ok(())
}

/// Stop the Android VPN: signal the engine to tear down gracefully, then stop the service.
pub async fn disconnect(state: &AppState) -> Result<(), String> {
    let app = state.app_handle.get().cloned();
    if let Some(app) = &app {
        let _ = app.emit("tunnel:state", "Disconnecting");
    }
    let session = state.android_vpn.lock().unwrap().take();
    if let Some(session) = session {
        session.cancel.notify_one();
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
