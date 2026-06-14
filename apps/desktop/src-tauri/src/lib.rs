//! Tauri shell: bridges the webview to the `leshiy-client` supervisor (proxy mode) and to
//! the privileged `leshiy-helper` daemon (VPN mode).
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use leshiy_client::adapter::RealTransport;
use leshiy_client::{
    spawn_supervisor, system_proxy, Profile, ProfileStore, Settings, SupervisorConfig,
    SupervisorHandle,
};
// Desktop VPN goes through the privileged `leshiy-helper` (elevation). On Android the VPN runs
// in-process via `VpnService` (see `mobile`), so the helper isn't compiled there.
#[cfg(not(target_os = "android"))]
use leshiy_helper::{is_installed, HelperClient, StartParams};
use tauri::{Emitter, Manager, State};

#[cfg(target_os = "android")]
mod mobile;

/// Application state managed by Tauri.
struct AppState {
    supervisor: SupervisorHandle,
    profiles: Mutex<ProfileStore>,
    settings: Mutex<Settings>,
    profiles_path: PathBuf,
    settings_path: PathBuf,
    /// Lazily-connected privileged-helper client; `None` until VPN mode connects. Desktop-only.
    #[cfg(not(target_os = "android"))]
    helper: Mutex<Option<HelperClient>>,
    /// Android in-process VPN session handle (cancel signal + engine task). `None` until connect.
    #[cfg(target_os = "android")]
    android_vpn: Mutex<Option<mobile::VpnSession>>,
    /// Cached rules fetched from rule subscriptions (separate from settings so a settings write
    /// never drops fetched data).
    sub_cache: Mutex<leshiy_client::SubscriptionCache>,
    sub_cache_path: PathBuf,
    /// App handle for emitting webview events from commands (set in `setup`).
    app_handle: OnceLock<tauri::AppHandle>,
    /// Owns the tokio runtime the supervisor's tasks run on; kept alive for the app's lifetime.
    _runtime: tokio::runtime::Runtime,
}

impl AppState {
    fn save_profiles(&self) -> Result<(), String> {
        self.profiles
            .lock()
            .unwrap()
            .save(&self.profiles_path)
            .map_err(|e| e.to_string())
    }
    fn save_settings(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&*self.settings.lock().unwrap())
            .map_err(|e| e.to_string())?;
        std::fs::write(&self.settings_path, bytes).map_err(|e| e.to_string())
    }
    fn save_sub_cache(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&*self.sub_cache.lock().unwrap())
            .map_err(|e| e.to_string())?;
        std::fs::write(&self.sub_cache_path, bytes).map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn list_profiles(state: State<AppState>) -> Vec<Profile> {
    state.profiles.lock().unwrap().list().to_vec()
}

#[tauri::command]
fn active_profile(state: State<AppState>) -> Option<Profile> {
    state.profiles.lock().unwrap().active().cloned()
}

#[tauri::command]
fn import_profile(state: State<AppState>, uri: String, name: String) -> Result<String, String> {
    let id = state
        .profiles
        .lock()
        .unwrap()
        .import(&uri, &name)
        .map_err(|e| e.to_string())?;
    state.save_profiles()?;
    Ok(id)
}

#[tauri::command]
fn remove_profile(state: State<AppState>, id: String) -> Result<(), String> {
    state.profiles.lock().unwrap().remove(&id);
    state.save_profiles()
}

#[tauri::command]
fn rename_profile(state: State<AppState>, id: String, name: String) -> Result<(), String> {
    state.profiles.lock().unwrap().rename(&id, &name);
    state.save_profiles()
}

#[tauri::command]
fn set_active(state: State<AppState>, id: String) -> Result<(), String> {
    state.profiles.lock().unwrap().set_active(&id);
    state.save_profiles()
}

/// Whether the given mode routes connect/disconnect through the privileged helper
/// (VPN) rather than the in-process SOCKS supervisor (Proxy).
fn mode_uses_helper(mode: leshiy_client::Mode) -> bool {
    matches!(mode, leshiy_client::Mode::Vpn)
}

/// True while VPN mode is active — used to silence the always-on proxy-supervisor stats relay
/// so it doesn't race the VPN helper forwarder on the `tunnel:stats`/`tunnel:state` events
/// (the supervisor idles in VPN mode and would otherwise emit zeros, flickering the GUI).
fn vpn_active(handle: &tauri::AppHandle) -> bool {
    mode_uses_helper(handle.state::<AppState>().settings.lock().unwrap().mode)
}

/// Merge the manual split-tunnel rules with each enabled subscription's cached rules into the
/// two-directional `SplitPlan`. Cross-platform (used by the desktop `StartParams` builder and the
/// Android in-process engine alike).
// Android calls this from `mobile::connect` in Phase C; until then it's unused on that target.
#[cfg_attr(target_os = "android", allow(dead_code))]
fn build_split_plan(
    settings: &Settings,
    cache: &leshiy_client::SubscriptionCache,
) -> leshiy_client::SplitPlan {
    let mut split = leshiy_client::SplitPlan::from_manual(&settings.split_tunnel);
    for sub in &settings.rule_subscriptions {
        if sub.enabled {
            if let Some(entry) = cache.get(&sub.id) {
                split.merge(sub.mode, &entry.rules);
            }
        }
    }
    split
}

/// Build the VPN `StartParams` (the helper's wire type) from the active profile URI + settings +
/// subscription cache. Desktop-only — the Android engine is driven in-process (see `mobile`).
#[cfg(not(target_os = "android"))]
fn build_start_params(
    uri: String,
    settings: &Settings,
    cache: &leshiy_client::SubscriptionCache,
) -> StartParams {
    StartParams {
        uri,
        transport: settings.transport,
        mtu: settings.vpn_mtu,
        tun_name: "leshiy0".into(),
        dns: settings.vpn_dns.clone(),
        split_tunnel: build_split_plan(settings, cache),
    }
}

#[tauri::command]
async fn connect(state: State<'_, AppState>) -> Result<(), String> {
    let (uri, settings) = {
        let prof = state.profiles.lock().unwrap();
        let uri = prof
            .active()
            .map(|p| p.uri.clone())
            .ok_or_else(|| "no active profile".to_string())?;
        let settings = state.settings.lock().unwrap().clone();
        (uri, settings)
    };

    if mode_uses_helper(settings.mode) {
        #[cfg(not(target_os = "android"))]
        {
            let endpoint = leshiy_helper::default_endpoint();

            // On-demand model on all desktop platforms: if no helper is answering, launch an
            // elevated ephemeral one (pkexec / osascript / UAC) and wait for the endpoint.
            let bin = helper_sidecar_path()?;
            leshiy_helper::elevate::ensure_running(&bin)
                .await
                .map_err(|e| e.to_string())?;

            let client = HelperClient::connect(endpoint);
            *state.helper.lock().unwrap() = Some(client.clone());

            // Relay the helper's state/stats onto the SAME webview events the proxy path uses, so
            // `useTunnel` is reused unchanged. SUBSCRIBE FIRST (before start_vpn) so the orb
            // reflects helper state immediately — Connecting → Connected, or → Disconnected if the
            // dial fails — regardless of how long start_vpn takes or whether it errors. The
            // forwarder ends when the helper closes the subscribe stream.
            let app = state
                .app_handle
                .get()
                .cloned()
                .ok_or_else(|| "app not ready".to_string())?;
            let mut rx = client.subscribe().await.map_err(|e| e.to_string())?;
            tauri::async_runtime::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    if let Some(s) = ev.state {
                        let _ = app.emit("tunnel:state", s);
                    }
                    if let Some(r) = ev.rates {
                        let _ = app.emit("tunnel:stats", r);
                    }
                }
            });

            let cache = state.sub_cache.lock().unwrap().clone();
            let params = build_start_params(uri, &settings, &cache);
            // Single start. We deliberately do NOT retry with an in-process stop+start: on Windows
            // that creates a second Wintun session on the same adapter before the first is released
            // (0x4DF "rings already registered"). Disconnect exits the ephemeral helper promptly
            // (fast in-process route teardown), so every connect gets a fresh process.
            client.start_vpn(params).await.map_err(|e| e.to_string())?;
        }
        #[cfg(target_os = "android")]
        {
            // In-process VpnService path: start the foreground service (which prompts for VPN
            // consent), hand its TUN fd to the engine, and dial.
            mobile::connect(state.inner(), uri, settings).await?;
        }
    } else {
        // Proxy mode: unchanged from today (no system proxy on Android, so effectively a no-op).
        state.supervisor.connect(uri);
    }
    Ok(())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mode = state.settings.lock().unwrap().mode;
    if mode_uses_helper(mode) {
        #[cfg(not(target_os = "android"))]
        {
            // Take the handle out (the helper is about to exit, so don't keep a stale client
            // around), then drop the lock before `shutdown().await`. We use `shutdown` (not
            // `stop`) so the on-demand helper TEARS DOWN and EXITS on disconnect: the next connect
            // spawns a fresh, clean helper. Reusing a long-lived helper across reconnects left
            // stale in-process state that wedged the second dial (UI stuck on "Connecting").
            let client = { state.helper.lock().unwrap().take() };
            if let Some(c) = client {
                // Route/DNS teardown takes a moment, so tell the UI we're tearing down — the orb
                // shows a "Disconnecting…" busy state instead of looking frozen. "Disconnecting"
                // is a UI-only transient (not in the Rust State enum), emitted as a plain string.
                if let Some(app) = state.app_handle.get() {
                    let _ = app.emit("tunnel:state", "Disconnecting");
                }
                // Best-effort: tear down + exit the helper. We deliberately DON'T propagate an
                // error — a wedged helper / broken pipe must not block the UI reset below.
                let _ = c.shutdown().await;
            }
            // The helper is exiting, so its dropped `Subscribe` stream won't deliver a final state.
            // Tell the UI we're disconnected directly so the orb always returns to idle.
            if let Some(app) = state.app_handle.get() {
                let _ = app.emit("tunnel:state", leshiy_client::State::Disconnected);
            }
        }
        #[cfg(target_os = "android")]
        {
            mobile::disconnect(state.inner()).await?;
        }
    } else {
        state.supervisor.disconnect();
    }
    Ok(())
}

/// True if the privileged VPN helper is already installed on this system (privilege-free).
#[cfg(not(target_os = "android"))]
#[tauri::command]
fn helper_installed() -> bool {
    is_installed()
}

/// Android has no privileged helper (the VPN runs in-process via VpnService).
#[cfg(target_os = "android")]
#[tauri::command]
fn helper_installed() -> bool {
    false
}

/// Host OS, so the GUI adapts the VPN flow: Linux uses an installed daemon (+ install dialog);
/// macOS/Windows use on-demand elevation during connect (no install step, no remove row).
#[tauri::command]
fn platform() -> String {
    std::env::consts::OS.to_string()
}

/// Install the privileged VPN helper. Runs OS elevation to invoke the helper's own
/// `install` subcommand — it does NOT call any install method on `HelperClient`. Idempotent.
/// The actual elevation is integration/manual-tested (it pops a system auth prompt).
#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn install_helper() -> Result<(), String> {
    run_helper_subcommand("install")
}

/// Android has no privileged helper to install.
#[cfg(target_os = "android")]
#[tauri::command]
async fn install_helper() -> Result<(), String> {
    Err("the privileged helper is not used on Android".into())
}

/// Locate the bundled `leshiy-helper` binary (Tauri sidecar) and run `<bin> <sub>` with OS
/// elevation. Returns Err on a non-zero exit. Per-OS elevation; manual/integration-tested.
#[cfg(not(target_os = "android"))]
fn run_helper_subcommand(sub: &str) -> Result<(), String> {
    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("leshiy-helper")))
        .ok_or_else(|| "cannot locate bundled leshiy-helper binary".to_string())?;
    let bin = bin.to_string_lossy().to_string();

    #[cfg(target_os = "linux")]
    let status = std::process::Command::new("pkexec")
        .arg(&bin)
        .arg(sub)
        // AppImage leaks LD_LIBRARY_PATH to its bundled libs; pkexec must use system libs
        // (else libpolkit/glib fail with an undefined symbol). See elevate::linux.
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .status();

    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "do shell script \"{} {}\" with administrator privileges",
            bin, sub
        ))
        .status();

    #[cfg(target_os = "windows")]
    let status = {
        // Elevate via PowerShell Start-Process -Verb RunAs (UAC), waiting for exit.
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
                    bin, sub
                ),
            ])
            .status()
    };

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("leshiy-helper {sub} exited with {s}")),
        Err(e) => Err(format!("failed to elevate leshiy-helper {sub}: {e}")),
    }
}

/// Locate the bundled `leshiy-helper` sidecar next to the app executable (on-demand model).
/// Tauri places `externalBin` next to the main binary at runtime.
#[cfg(not(target_os = "android"))]
fn helper_sidecar_path() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe
        .parent()
        .ok_or_else(|| "cannot resolve the app directory".to_string())?;
    #[cfg(target_os = "windows")]
    let name = "leshiy-helper.exe";
    #[cfg(not(target_os = "windows"))]
    let name = "leshiy-helper";
    Ok(dir.join(name))
}

/// Extract the `host:port` from a `leshiy://…@host:port?…` URI (mirrors the JS `defaultConfigName`).
fn server_addr_from_uri(uri: &str) -> Option<String> {
    let after = uri.split_once('@')?.1;
    let host = after.split(['?', '#']).next()?.trim();
    (!host.is_empty()).then(|| host.to_string())
}

/// Measure round-trip latency to the active profile's server (a timed TCP connect to host:port).
/// On Android our app is excluded from the VPN, so this reflects the real path to the server.
#[tauri::command]
async fn measure_latency(state: State<'_, AppState>) -> Result<u32, String> {
    let uri = {
        state
            .profiles
            .lock()
            .unwrap()
            .active()
            .map(|p| p.uri.clone())
    }
    .ok_or_else(|| "no active profile".to_string())?;
    let addr = server_addr_from_uri(&uri).ok_or_else(|| "no server in uri".to_string())?;
    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| "timed out".to_string())?
    .map_err(|e| e.to_string())?;
    Ok(start.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// Read the system clipboard as text. On Android this uses a native Kotlin read (the JS/plugin
/// clipboard read returns empty in the webview); on desktop it uses the clipboard-manager plugin.
#[cfg_attr(target_os = "android", allow(unused_variables))]
#[tauri::command]
fn read_clipboard(app: tauri::AppHandle) -> Result<String, String> {
    #[cfg(target_os = "android")]
    {
        mobile::read_clipboard()
    }
    #[cfg(not(target_os = "android"))]
    {
        use tauri_plugin_clipboard_manager::ClipboardExt;
        app.clipboard().read_text().map_err(|e| e.to_string())
    }
}

/// Remove the privileged VPN helper (stops it if running, then uninstalls). Like install,
/// the removal runs the helper's own `uninstall` subcommand under OS elevation — NOT a
/// `HelperClient` method. The actual elevation is integration/manual-tested.
#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn remove_helper(state: State<'_, AppState>) -> Result<(), String> {
    // Stop any running session first, dropping our cached client handle.
    {
        let client = state.helper.lock().unwrap().take();
        if let Some(c) = client {
            let _ = c.stop().await;
        }
    }
    run_helper_subcommand("uninstall")
}

/// Android has no privileged helper to remove.
#[cfg(target_os = "android")]
#[tauri::command]
async fn remove_helper(_state: State<'_, AppState>) -> Result<(), String> {
    Err("the privileged helper is not used on Android".into())
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
fn set_settings(state: State<AppState>, settings: Settings) -> Result<(), String> {
    *state.settings.lock().unwrap() = settings;
    state.save_settings()
}

/// Stop any running VPN session, then quit. Stopping first makes the ephemeral helper tear
/// down (routes/DNS restored) and exit on its own — relying on the helper noticing the dropped
/// pipe after the app is gone is unreliable on Windows, so it would otherwise linger.
#[cfg(not(target_os = "android"))]
async fn shutdown_and_exit(app: tauri::AppHandle) {
    let client = { app.state::<AppState>().helper.lock().unwrap().take() };
    if let Some(c) = client {
        let _ = c.shutdown().await; // stop the session AND exit the ephemeral helper
    }
    app.exit(0);
}

/// Fully quit the application. Used by the close-window dialog ("Quit") and mirrors the tray
/// "Quit" item. The frontend owns the close decision (see App.tsx), so this is the single
/// explicit exit path.
#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn quit_app(app: tauri::AppHandle) {
    shutdown_and_exit(app).await;
}

/// Android apps don't programmatically exit (the OS manages lifecycle) — make this a no-op so the
/// shared frontend can call it unconditionally.
#[cfg(target_os = "android")]
#[tauri::command]
async fn quit_app(_app: tauri::AppHandle) {}

/// Hide the main window to the system tray. Done from Rust (like the old close handler) so it
/// doesn't require the `core:window:allow-hide` capability that a JS `window.hide()` would.
#[cfg(not(target_os = "android"))]
#[tauri::command]
fn hide_window(app: tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
}

/// No system tray / window-hide on Android (no tray, OS-managed lifecycle) — no-op.
#[cfg(target_os = "android")]
#[tauri::command]
fn hide_window(_app: tauri::AppHandle) {}

/// Parse split-tunnel rule text in the given `format` ("lines" = native, "hosts" = hosts-file)
/// and `mode`. Reuses the `leshiy-client` parser; the error string is shown in the editor.
fn parse_split_text(
    mode: leshiy_client::SplitMode,
    format: &str,
    text: &str,
) -> Result<leshiy_client::SplitTunnel, String> {
    let r = match format {
        "hosts" => leshiy_client::SplitTunnel::parse_hosts(mode, text),
        _ => leshiy_client::SplitTunnel::parse_lines(mode, text),
    };
    r.map_err(|e| e.to_string())
}

#[tauri::command]
fn validate_split_rules(
    mode: leshiy_client::SplitMode,
    format: String,
    text: String,
) -> Result<leshiy_client::SplitTunnel, String> {
    parse_split_text(mode, &format, &text)
}

// ---- Rule subscriptions: fetch + cache ----

/// Refuse to ingest absurdly large lists (some RKN domain dumps are tens of MB).
const MAX_FETCH_BYTES: usize = 32 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Background re-fetch cadence for enabled subscriptions.
const SUB_REFRESH: Duration = Duration::from_secs(24 * 3600);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn header_str(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Fetch one subscription with a conditional GET (ETag / Last-Modified). `Ok(None)` means the
/// server replied 304 Not Modified — keep the existing cache entry.
async fn fetch_one(
    client: &reqwest::Client,
    sub: &leshiy_client::Subscription,
    prev: Option<&leshiy_client::SubscriptionCacheEntry>,
) -> Result<Option<leshiy_client::SubscriptionCacheEntry>, String> {
    let mut req = client.get(&sub.url);
    if let Some(p) = prev {
        if let Some(etag) = &p.etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(lm) = &p.last_modified {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, lm);
        }
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_FETCH_BYTES {
            return Err(format!("list too large ({len} bytes)"));
        }
    }
    let etag = header_str(&resp, reqwest::header::ETAG);
    let last_modified = header_str(&resp, reqwest::header::LAST_MODIFIED);
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if body.len() > MAX_FETCH_BYTES {
        return Err("list too large".into());
    }
    let rules = leshiy_client::parse_subscription(sub.format, &body).map_err(|e| e.to_string())?;
    Ok(Some(leshiy_client::SubscriptionCacheEntry {
        rules,
        etag,
        last_modified,
        fetched_at: now_secs(),
    }))
}

/// Re-fetch enabled subscriptions (all, or only `only_id`) and persist the cache. Per-source
/// errors are logged and skipped (the old cache entry is kept) so one dead URL can't fail the lot.
async fn refresh_subs(state: &AppState, only_id: Option<&str>) -> Result<(), String> {
    let (subs, mut cache) = {
        let s = state.settings.lock().unwrap();
        let c = state.sub_cache.lock().unwrap().clone();
        (s.rule_subscriptions.clone(), c)
    };
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    for sub in subs.iter().filter(|s| s.enabled) {
        if let Some(id) = only_id {
            if id != sub.id {
                continue;
            }
        }
        let prev = cache.get(&sub.id).cloned();
        match fetch_one(&client, sub, prev.as_ref()).await {
            Ok(Some(entry)) => {
                tracing::info!(
                    sub = %sub.id,
                    cidrs = entry.rules.cidrs.len(),
                    domains = entry.rules.domains.len(),
                    "subscription fetched"
                );
                cache.insert(sub.id.clone(), entry);
            }
            Ok(None) => tracing::info!(sub = %sub.id, "subscription not modified (304)"),
            Err(e) => tracing::warn!(sub = %sub.id, "subscription fetch failed: {e}"),
        }
    }
    *state.sub_cache.lock().unwrap() = cache;
    state.save_sub_cache()
}

#[tauri::command]
fn subscription_cache(state: State<AppState>) -> leshiy_client::SubscriptionCache {
    state.sub_cache.lock().unwrap().clone()
}

#[tauri::command]
async fn refresh_subscriptions(
    state: State<'_, AppState>,
) -> Result<leshiy_client::SubscriptionCache, String> {
    refresh_subs(&state, None).await?;
    Ok(state.sub_cache.lock().unwrap().clone())
}

#[tauri::command]
async fn refresh_subscription(
    state: State<'_, AppState>,
    id: String,
) -> Result<leshiy_client::SubscriptionCache, String> {
    refresh_subs(&state, Some(&id)).await?;
    Ok(state.sub_cache.lock().unwrap().clone())
}

#[cfg(not(target_os = "android"))]
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{MenuBuilder, MenuItemBuilder};
    use tauri::tray::TrayIconBuilder;

    let connect_i = MenuItemBuilder::with_id("connect", "Connect").build(app)?;
    let disconnect_i = MenuItemBuilder::with_id("disconnect", "Disconnect").build(app)?;
    let show_i = MenuItemBuilder::with_id("show", "Show").build(app)?;
    let quit_i = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&connect_i, &disconnect_i, &show_i, &quit_i])
        .build()?;

    let icon = app.default_window_icon().unwrap().clone();
    let _tray = TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "connect" => {
                // Tray quick-connect uses the proxy supervisor path; VPN connect is
                // initiated from the window so the lazy install dialog can appear.
                let st = app.state::<AppState>();
                let uri = st.profiles.lock().unwrap().active().map(|p| p.uri.clone());
                if let Some(uri) = uri {
                    st.supervisor.connect(uri);
                }
            }
            "disconnect" => {
                app.state::<AppState>().supervisor.disconnect();
            }
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "quit" => {
                // Stop the VPN session (so the ephemeral helper exits) before quitting.
                let app2 = app.clone();
                tauri::async_runtime::spawn(async move { shutdown_and_exit(app2).await });
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// Resolve the config directory. Desktop keeps its historical `directories` path so existing
/// users don't lose settings; Android uses Tauri's app-private `app_config_dir`.
#[cfg(not(target_os = "android"))]
fn config_dir(_app: &tauri::App) -> PathBuf {
    directories::ProjectDirs::from("app", "leshiy", "Leshiy")
        .expect("could not resolve a config directory")
        .config_dir()
        .to_path_buf()
}

#[cfg(target_os = "android")]
fn config_dir(app: &tauri::App) -> PathBuf {
    app.path()
        .app_config_dir()
        .expect("could not resolve the app config directory")
}

/// Build the managed application state: load persisted profiles/settings/subscription cache from
/// `cfg_dir`, and spawn the proxy supervisor on a fresh tokio runtime. Called from `setup` (where
/// the Tauri path API is available).
fn build_app_state(cfg_dir: PathBuf) -> AppState {
    std::fs::create_dir_all(&cfg_dir).ok();
    let profiles_path = cfg_dir.join("profiles.json");
    let settings_path = cfg_dir.join("settings.json");
    let sub_cache_path = cfg_dir.join("subscriptions_cache.json");

    let settings: Settings = std::fs::read(&settings_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let profiles = ProfileStore::load(&profiles_path).unwrap_or_default();
    let sub_cache: leshiy_client::SubscriptionCache = std::fs::read(&sub_cache_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let supervisor = {
        let _guard = runtime.enter();
        let sup_cfg = SupervisorConfig {
            socks_addr: format!("127.0.0.1:{}", settings.socks_port)
                .parse()
                .expect("valid socks addr"),
            pref: settings.transport,
            kill_switch: settings.kill_switch,
            ..SupervisorConfig::default()
        };
        spawn_supervisor(RealTransport, system_proxy(), sup_cfg)
    };

    AppState {
        supervisor,
        profiles: Mutex::new(profiles),
        settings: Mutex::new(settings),
        profiles_path,
        settings_path,
        #[cfg(not(target_os = "android"))]
        helper: Mutex::new(None),
        #[cfg(target_os = "android")]
        android_vpn: Mutex::new(None),
        sub_cache: Mutex::new(sub_cache),
        sub_cache_path,
        app_handle: OnceLock::new(),
        _runtime: runtime,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Android: forward the crates' `tracing` logs to logcat so connect/dial failures are
    // diagnosable via `adb logcat -s leshiy`. `try_init` is a no-op if a subscriber already exists.
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::prelude::*;
        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(paranoid_android::AndroidLogMakeWriter::new(
                        "leshiy".to_owned(),
                    )),
            )
            .try_init();
    }

    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init());
    // Android: register the VpnService bridge plugin + the camera barcode scanner (mobile-only).
    #[cfg(target_os = "android")]
    {
        builder = builder
            .plugin(mobile::init())
            .plugin(tauri_plugin_barcode_scanner::init());
    }
    builder
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            active_profile,
            import_profile,
            remove_profile,
            rename_profile,
            set_active,
            connect,
            disconnect,
            get_settings,
            set_settings,
            read_clipboard,
            measure_latency,
            validate_split_rules,
            subscription_cache,
            refresh_subscriptions,
            refresh_subscription,
            helper_installed,
            install_helper,
            remove_helper,
            platform,
            quit_app,
            hide_window
        ])
        .setup(|app| {
            // Build + manage state here (not before the builder) so the Tauri path API is
            // available for the Android config dir.
            let cfg_dir = config_dir(app);
            app.manage(build_app_state(cfg_dir));

            let handle = app.handle().clone();
            // Store the app handle so commands (the VPN helper relay) can emit webview events.
            let _ = app.state::<AppState>().app_handle.set(handle.clone());
            let (mut state_rx, mut stats_rx) = {
                let st = app.state::<AppState>();
                (
                    st.supervisor.subscribe_state(),
                    st.supervisor.subscribe_stats(),
                )
            };
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::select! {
                        r = state_rx.changed() => {
                            if r.is_err() { break; }
                            let s = *state_rx.borrow();
                            // Quiet in VPN mode: the helper forwarder owns these events there.
                            if !vpn_active(&handle) { let _ = handle.emit("tunnel:state", s); }
                        }
                        r = stats_rx.changed() => {
                            if r.is_err() { break; }
                            let s = *stats_rx.borrow();
                            if !vpn_active(&handle) { let _ = handle.emit("tunnel:stats", s); }
                        }
                    }
                }
            });
            // Refresh rule subscriptions on launch and once a day. Conditional GETs (ETag /
            // Last-Modified) keep repeated refreshes cheap (304 Not Modified).
            let sub_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let _ = refresh_subs(sub_handle.state::<AppState>().inner(), None).await;
                    tokio::time::sleep(SUB_REFRESH).await;
                }
            });
            #[cfg(not(target_os = "android"))]
            build_tray(app)?;
            Ok(())
        })
        // The frontend owns the window-close decision (ask / quit / hide-to-tray):
        // it intercepts CloseRequested via getCurrentWindow().onCloseRequested() and
        // either hides the window or calls the `quit_app` command. See App.tsx.
        .run(tauri::generate_context!())
        .expect("error while running leshiy desktop");
}

#[cfg(test)]
mod tests {
    #[test]
    fn vpn_mode_branch_selects_helper() {
        use leshiy_client::Mode;
        // VPN routes to the helper, Proxy to the in-process SOCKS supervisor.
        assert!(super::mode_uses_helper(Mode::Vpn));
        assert!(!super::mode_uses_helper(Mode::Proxy));
    }

    #[test]
    fn parse_split_text_handles_lines_and_hosts_and_errors() {
        use leshiy_client::SplitMode;
        let lines =
            super::parse_split_text(SplitMode::Exclude, "lines", "10.0.0.0/8\nexample.com\n")
                .unwrap();
        assert_eq!(lines.cidrs.len(), 1);
        assert_eq!(lines.domains, vec!["example.com"]);
        let hosts =
            super::parse_split_text(SplitMode::Exclude, "hosts", "0.0.0.0 ads.example.com\n")
                .unwrap();
        assert_eq!(hosts.domains, vec!["ads.example.com"]);
        assert!(super::parse_split_text(SplitMode::Exclude, "lines", "10.0.0.0/40").is_err());
    }

    #[test]
    fn start_params_carries_split_tunnel_and_vpn_settings() {
        use leshiy_client::{Settings, SplitMode, SplitPlan, SplitTunnel};
        let s = Settings {
            vpn_mtu: 1390,
            split_tunnel: SplitTunnel::parse_lines(SplitMode::Include, "10.0.0.0/8\n").unwrap(),
            ..Settings::default()
        };
        let cache = leshiy_client::SubscriptionCache::default();
        let params = super::build_start_params("leshiy://x".into(), &s, &cache);
        // Manual Include rules map to the include direction of the two-directional plan.
        assert_eq!(params.split_tunnel, SplitPlan::from_manual(&s.split_tunnel));
        assert_eq!(params.split_tunnel.base_mode, SplitMode::Include);
        assert_eq!(params.split_tunnel.include.cidrs.len(), 1);
        assert_eq!(params.mtu, 1390);
        assert_eq!(params.dns, s.vpn_dns);
    }

    #[test]
    fn build_start_params_merges_enabled_subscriptions() {
        use leshiy_client::{
            RuleSet, Settings, SplitCidr, SplitMode, SubFormat, Subscription, SubscriptionCache,
            SubscriptionCacheEntry,
        };
        let sub = Subscription {
            id: "refilter".into(),
            name: "Re:filter".into(),
            url: "https://x/ipsum.lst".into(),
            format: SubFormat::Lines,
            mode: SplitMode::Include,
            enabled: true,
        };
        let s = Settings {
            rule_subscriptions: vec![sub],
            ..Settings::default()
        };
        let mut cache = SubscriptionCache::default();
        cache.insert(
            "refilter".into(),
            SubscriptionCacheEntry {
                rules: RuleSet {
                    cidrs: vec![SplitCidr {
                        addr: "1.2.3.0".parse().unwrap(),
                        prefix: 24,
                    }],
                    domains: vec!["blocked.example".into()],
                },
                ..Default::default()
            },
        );
        let params = super::build_start_params("leshiy://x".into(), &s, &cache);
        // The Include subscription's rules landed in the include direction.
        assert_eq!(params.split_tunnel.include.cidrs.len(), 1);
        assert_eq!(params.split_tunnel.include.domains, vec!["blocked.example"]);
    }
}
