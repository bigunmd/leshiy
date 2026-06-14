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
    ByteCounters, RealTransport, Settings, SplitMode, SplitPlan, State, Throughput, Transport,
    TransportPref, Tunnel,
};
use leshiy_tun::{TunConfig, TunEngine};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::{Emitter, Wry};
use tokio::sync::Notify;

/// Handle to the Kotlin `VpnPlugin`, set once during plugin setup.
static VPN_PLUGIN: OnceLock<tauri::plugin::PluginHandle<Wry>> = OnceLock::new();

/// A running in-process VPN session: the cooperative-cancel signal for the engine (same graceful
/// teardown contract as desktop — never abort) plus its task handle.
pub struct VpnSession {
    pub cancel: Arc<Notify>,
    pub task: tauri::async_runtime::JoinHandle<()>,
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
}

#[derive(Deserialize)]
struct PrepareResp {
    granted: bool,
}

#[derive(Deserialize)]
struct EstablishResp {
    fd: i32,
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
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
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

    // 1. VPN consent (one-time system dialog).
    let prep: PrepareResp = plugin
        .run_mobile_plugin("prepare", ())
        .map_err(|e| e.to_string())?;
    if !prep.granted {
        let _ = app.emit("tunnel:state", "Error");
        return Err("VPN permission was denied".into());
    }

    // 2. Build the tunnel interface (foreground service does establish()).
    let cache = state.sub_cache.lock().unwrap().clone();
    let split = build_split_plan(&settings, &cache);
    let (routes, exclude_routes) = routes_for_builder(&split);
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
            },
        )
        .map_err(|e| {
            let _ = app.emit("tunnel:state", "Error");
            e.to_string()
        })?;

    // 3. Dial the tunnel (our app is excluded from the VPN, so this egresses directly).
    let tunnel: Arc<dyn Tunnel> = Arc::from(
        RealTransport
            .dial(&uri, TransportPref::Tcp)
            .await
            .map_err(|e| {
                let _ = app.emit("tunnel:state", "Error");
                format!("dial failed: {e}")
            })?,
    );

    // 4. Run the engine in-process over the VpnService fd (server_ip/orig_gateway are unused on
    //    Android — AndroidOps ignores the route plan; VpnService owns routing).
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
    leshiy_tun::sys::set_tun_fd(est.fd);

    let cancel = Arc::new(Notify::new());
    let counters = Arc::new(ByteCounters::new());
    let app_task = app.clone();
    let engine_cancel = cancel.clone();
    let task = tauri::async_runtime::spawn(async move {
        let sampler =
            tauri::async_runtime::spawn(sample_throughput(app_task.clone(), counters.clone()));
        if let Err(e) = TunEngine::run(tunnel, cfg, counters, engine_cancel).await {
            eprintln!("android tun engine exited: {e}");
        }
        sampler.abort();
        let _ = app_task.emit("tunnel:state", State::Disconnected);
    });

    *state.android_vpn.lock().unwrap() = Some(VpnSession { cancel, task });
    let _ = app.emit("tunnel:state", State::Connected);
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
