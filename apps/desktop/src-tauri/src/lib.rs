//! Tauri shell: bridges the webview to the `leshiy-client` supervisor (proxy mode) and to
//! the privileged `leshiy-helper` daemon (VPN mode).
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use leshiy_client::adapter::RealTransport;
use leshiy_client::{
    spawn_supervisor, system_proxy, Profile, ProfileStore, Settings, SupervisorConfig,
    SupervisorHandle,
};
// Free functions for the install probe (NOT HelperClient methods); HelperClient drives VPN mode.
use leshiy_helper::{is_installed, HelperClient, StartParams};
use tauri::{Emitter, Manager, State};

/// Application state managed by Tauri.
struct AppState {
    supervisor: SupervisorHandle,
    profiles: Mutex<ProfileStore>,
    settings: Mutex<Settings>,
    profiles_path: PathBuf,
    settings_path: PathBuf,
    /// Lazily-connected privileged-helper client; `None` until VPN mode connects.
    helper: Mutex<Option<HelperClient>>,
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
        let endpoint = leshiy_helper::default_endpoint();

        // On-demand model on macOS/Windows: if no helper is answering, launch an elevated
        // ephemeral one (UAC / osascript admin) and wait for the endpoint. Linux uses the
        // installed daemon (systemd/setcap) — no spawn here.
        #[cfg(not(target_os = "linux"))]
        {
            let bin = helper_sidecar_path()?;
            leshiy_helper::elevate::ensure_running(&bin)
                .await
                .map_err(|e| e.to_string())?;
        }

        let client = HelperClient::connect(endpoint);
        *state.helper.lock().unwrap() = Some(client.clone());
        let params = StartParams {
            uri, // active profile URI
            transport: settings.transport,
            mtu: settings.vpn_mtu,
            tun_name: "leshiy0".into(),
            dns: settings.vpn_dns.clone(),
        };
        client.start_vpn(params).await.map_err(|e| e.to_string())?;

        // Relay the helper's state/stats onto the SAME webview events the proxy path uses,
        // so `useTunnel` is reused unchanged. The forwarder ends when the helper closes the
        // subscribe stream (final Disconnected event returns the orb to idle).
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
    } else {
        // Proxy mode: unchanged from today.
        state.supervisor.connect(uri);
    }
    Ok(())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mode = state.settings.lock().unwrap().mode;
    if mode_uses_helper(mode) {
        // Clone the cheap handle out of the guard, then drop the lock before `stop().await`.
        let client = { state.helper.lock().unwrap().clone() };
        if let Some(c) = client {
            c.stop().await.map_err(|e| e.to_string())?;
        }
    } else {
        state.supervisor.disconnect();
    }
    Ok(())
}

/// True if the privileged VPN helper is already installed on this system (privilege-free).
#[tauri::command]
fn helper_installed() -> bool {
    is_installed()
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
#[tauri::command]
async fn install_helper() -> Result<(), String> {
    run_helper_subcommand("install")
}

/// Locate the bundled `leshiy-helper` binary (Tauri sidecar) and run `<bin> <sub>` with OS
/// elevation. Returns Err on a non-zero exit. Per-OS elevation; manual/integration-tested.
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

/// Locate the bundled `leshiy-helper` sidecar next to the app executable (macOS/Windows
/// on-demand model). Tauri places `externalBin` next to the main binary at runtime.
#[cfg(not(target_os = "linux"))]
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

/// Remove the privileged VPN helper (stops it if running, then uninstalls). Like install,
/// the removal runs the helper's own `uninstall` subcommand under OS elevation — NOT a
/// `HelperClient` method. The actual elevation is integration/manual-tested.
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

#[tauri::command]
fn get_settings(state: State<AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
fn set_settings(state: State<AppState>, settings: Settings) -> Result<(), String> {
    *state.settings.lock().unwrap() = settings;
    state.save_settings()
}

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
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let dirs = directories::ProjectDirs::from("app", "leshiy", "Leshiy")
        .expect("could not resolve a config directory");
    let cfg_dir = dirs.config_dir().to_path_buf();
    std::fs::create_dir_all(&cfg_dir).ok();
    let profiles_path = cfg_dir.join("profiles.json");
    let settings_path = cfg_dir.join("settings.json");

    let settings: Settings = std::fs::read(&settings_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let profiles = ProfileStore::load(&profiles_path).unwrap_or_default();

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

    let app_state = AppState {
        supervisor,
        profiles: Mutex::new(profiles),
        settings: Mutex::new(settings),
        profiles_path,
        settings_path,
        helper: Mutex::new(None),
        app_handle: OnceLock::new(),
        _runtime: runtime,
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
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
            helper_installed,
            install_helper,
            remove_helper,
            platform
        ])
        .setup(|app| {
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
                            let _ = handle.emit("tunnel:state", s);
                        }
                        r = stats_rx.changed() => {
                            if r.is_err() { break; }
                            let s = *stats_rx.borrow();
                            let _ = handle.emit("tunnel:stats", s);
                        }
                    }
                }
            });
            build_tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
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
}
