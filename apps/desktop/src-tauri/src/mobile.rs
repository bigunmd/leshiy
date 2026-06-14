//! Android in-process VPN bridge.
//!
//! On Android there is no privileged helper: the app's own `VpnService` (Kotlin, in
//! `gen/android`) builds the tunnel interface and hands its TUN fd to the engine, which runs
//! in-process here via `TunEngine::run`. This module is the Rust side of that bridge.
//!
//! Phase B (current): scaffolding only — `connect` returns a clear "not wired yet" error so the
//! app builds and the UI runs in an emulator. Phase C implements:
//!   - starting/binding the `LeshiyVpnService` (foreground) + VPN-consent flow,
//!   - registering the `leshiy_core::protect` callback (→ `VpnService.protect`),
//!   - `start_engine(fd, params)`: dial via `RealTransport`, `set_tun_fd(fd)`, run `TunEngine`,
//!   - relaying state/stats to the `tunnel:state` / `tunnel:stats` webview events.
#![allow(dead_code)] // Phase C populates the engine task; the cancel handle is wired then.

use crate::AppState;
use leshiy_client::Settings;
use std::sync::Arc;
use tokio::sync::Notify;

/// A running in-process VPN session: the cooperative-cancel signal for the engine (same graceful
/// teardown contract as desktop — never abort) plus its task handle.
pub struct VpnSession {
    pub cancel: Arc<Notify>,
    pub task: tokio::task::JoinHandle<()>,
}

/// Start the Android VPN. Phase C: trigger the VpnService (consent + establish), then drive the
/// engine in-process with the returned fd.
pub async fn connect(_state: &AppState, _uri: String, _settings: Settings) -> Result<(), String> {
    Err("Android VPN is not wired yet (Phase C: VpnService + engine bridge)".into())
}

/// Stop the Android VPN: signal the engine to tear down gracefully (the device fd closes, routes
/// are owned by the service which stops itself). Safe to call when nothing is running.
pub async fn disconnect(state: &AppState) -> Result<(), String> {
    let session = state.android_vpn.lock().unwrap().take();
    if let Some(session) = session {
        session.cancel.notify_one();
        let _ = session.task.await;
    }
    Ok(())
}
