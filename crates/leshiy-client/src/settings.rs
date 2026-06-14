//! User-facing settings. Serialized to JSON by the Tauri shell (Plan 3); defaults
//! match the approved spec (English, kill-switch ON, auto transport, SOCKS 1080).
use crate::split_tunnel::SplitTunnel;
use crate::subscription::Subscription;
use serde::{Deserialize, Serialize};

/// Which transport the dialer should prefer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportPref {
    /// QUIC first, REALITY fallback (the spec default).
    #[default]
    Auto,
    /// QUIC only.
    Quic,
    /// REALITY (TCP) only.
    Tcp,
}

/// Tunnel mode: the existing local SOCKS proxy, or full-device VPN (TUN).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Local SOCKS5 proxy (today's behavior; the default).
    #[default]
    Proxy,
    /// Full-tunnel VPN via a TUN device (all device traffic).
    Vpn,
}

/// What should happen when the user closes the main window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloseBehavior {
    /// Prompt the user every time (the default until they pick "remember").
    #[default]
    Ask,
    /// Fully quit the application.
    Quit,
    /// Hide the window to the system tray.
    Minimize,
}

/// Per-app VPN routing (Android only). Which apps' traffic the tunnel captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PerAppMode {
    /// All apps go through the VPN (the default; only this app is excluded for loop avoidance).
    #[default]
    Off,
    /// ONLY the listed apps go through the VPN (addAllowedApplication).
    Include,
    /// All apps EXCEPT the listed go through the VPN (addDisallowedApplication).
    Exclude,
}

/// Per-app routing rules (Android `VpnService` allowed/disallowed applications). Package names.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PerAppRules {
    #[serde(default)]
    pub mode: PerAppMode,
    #[serde(default)]
    pub packages: Vec<String>,
}

/// Persisted application settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default = "default_true")]
    pub kill_switch: bool,
    #[serde(default)]
    pub transport: TransportPref,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_vpn_mtu")]
    pub vpn_mtu: u16,
    #[serde(default = "default_vpn_dns")]
    pub vpn_dns: String,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default)]
    pub start_minimized: bool,
    /// What to do when the user closes the main window (ask / quit / minimize to tray).
    #[serde(default)]
    pub close_behavior: CloseBehavior,
    /// Global split-tunnel ruleset (manual rules). Empty (the default) means plain full tunnel.
    #[serde(default)]
    pub split_tunnel: SplitTunnel,
    /// Configured community rule subscriptions (each with its own Include/Exclude direction).
    #[serde(default)]
    pub rule_subscriptions: Vec<Subscription>,
    /// Per-app VPN routing (Android only; ignored elsewhere).
    #[serde(default)]
    pub per_app: PerAppRules,
}

fn default_language() -> String {
    "en".to_string()
}
fn default_true() -> bool {
    true
}
fn default_socks_port() -> u16 {
    1080
}
fn default_vpn_mtu() -> u16 {
    1400
}
fn default_vpn_dns() -> String {
    "1.1.1.1".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: default_language(),
            kill_switch: default_true(),
            transport: TransportPref::Auto,
            mode: Mode::Proxy,
            vpn_mtu: default_vpn_mtu(),
            vpn_dns: default_vpn_dns(),
            socks_port: default_socks_port(),
            start_minimized: false,
            close_behavior: CloseBehavior::Ask,
            split_tunnel: SplitTunnel::default(),
            rule_subscriptions: Vec::new(),
            per_app: PerAppRules::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let s = Settings::default();
        assert_eq!(s.language, "en");
        assert!(s.kill_switch);
        assert_eq!(s.transport, TransportPref::Auto);
        assert_eq!(s.socks_port, 1080);
        assert!(!s.start_minimized);
    }

    #[test]
    fn settings_default_mode_is_proxy() {
        assert_eq!(Settings::default().mode, Mode::Proxy);
    }

    #[test]
    fn settings_default_vpn_fields() {
        let s = Settings::default();
        assert_eq!(s.vpn_mtu, 1400);
        assert_eq!(s.vpn_dns, "1.1.1.1");
    }

    #[test]
    fn missing_vpn_fields_fall_back_to_defaults() {
        // Old settings files (pre-VPN) deserialize with the new fields defaulted.
        let s: Settings = serde_json::from_str(r#"{"language":"en","mode":"vpn"}"#).unwrap();
        assert_eq!(s.mode, Mode::Vpn);
        assert_eq!(s.vpn_mtu, 1400);
        assert_eq!(s.vpn_dns, "1.1.1.1");
    }

    #[test]
    fn mode_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Mode::Vpn).unwrap(), "\"vpn\"");
    }

    #[test]
    fn json_round_trips() {
        let s = Settings {
            language: "ru".into(),
            transport: TransportPref::Tcp,
            ..Settings::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        // A forward/backward-compatible empty object yields all defaults.
        let s: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn transport_serializes_lowercase() {
        let json = serde_json::to_string(&TransportPref::Quic).unwrap();
        assert_eq!(json, "\"quic\"");
    }

    #[test]
    fn settings_default_split_tunnel_is_empty_exclude() {
        use crate::split_tunnel::SplitMode;
        let s = Settings::default();
        assert!(s.split_tunnel.is_empty());
        assert_eq!(s.split_tunnel.mode, SplitMode::Exclude);
    }

    #[test]
    fn old_settings_file_without_split_tunnel_defaults() {
        // A pre-split-tunnel settings.json deserializes with an empty ruleset.
        let s: Settings = serde_json::from_str(r#"{"language":"en","mode":"vpn"}"#).unwrap();
        assert!(s.split_tunnel.is_empty());
    }

    #[test]
    fn settings_default_close_behavior_is_ask() {
        assert_eq!(Settings::default().close_behavior, CloseBehavior::Ask);
    }

    #[test]
    fn old_settings_file_without_close_behavior_defaults_to_ask() {
        // A pre-close-behavior settings.json deserializes with Ask.
        let s: Settings = serde_json::from_str(r#"{"language":"en","mode":"vpn"}"#).unwrap();
        assert_eq!(s.close_behavior, CloseBehavior::Ask);
    }

    #[test]
    fn close_behavior_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&CloseBehavior::Minimize).unwrap(),
            "\"minimize\""
        );
    }

    #[test]
    fn close_behavior_round_trips() {
        let s = Settings {
            close_behavior: CloseBehavior::Quit,
            ..Settings::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.close_behavior, CloseBehavior::Quit);
        assert_eq!(s, back);
    }
}
