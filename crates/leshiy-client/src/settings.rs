//! User-facing settings. Serialized to JSON by the Tauri shell (Plan 3); defaults
//! match the approved spec (English, kill-switch ON, auto transport, SOCKS 1080).
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
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default)]
    pub start_minimized: bool,
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

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: default_language(),
            kill_switch: default_true(),
            transport: TransportPref::Auto,
            mode: Mode::Proxy,
            socks_port: default_socks_port(),
            start_minimized: false,
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
}
