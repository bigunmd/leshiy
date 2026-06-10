//! Tauri shell: bridges the webview to the `leshiy-client` supervisor.
use std::path::PathBuf;
use std::sync::Mutex;

use leshiy_client::adapter::RealTransport;
use leshiy_client::{
    spawn_supervisor, system_proxy, Profile, ProfileStore, Settings, SupervisorConfig,
    SupervisorHandle,
};
use tauri::{Emitter, Manager, State};

/// Application state managed by Tauri.
struct AppState {
    supervisor: SupervisorHandle,
    profiles: Mutex<ProfileStore>,
    settings: Mutex<Settings>,
    profiles_path: PathBuf,
    settings_path: PathBuf,
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

#[tauri::command]
fn connect(state: State<AppState>) -> Result<(), String> {
    let uri = state
        .profiles
        .lock()
        .unwrap()
        .active()
        .map(|p| p.uri.clone())
        .ok_or_else(|| "no active profile".to_string())?;
    state.supervisor.connect(uri);
    Ok(())
}

#[tauri::command]
fn disconnect(state: State<AppState>) {
    state.supervisor.disconnect();
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
            set_settings
        ])
        .setup(|app| {
            let handle = app.handle().clone();
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
