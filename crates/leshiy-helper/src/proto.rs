//! Control protocol: newline-delimited JSON over the helper's Unix socket. Mirrors
//! `leshiy-reality/src/control.rs` (tagged `Request` enum, struct `Response`). `State`
//! and `Rates` are reused from `leshiy-client` so callers (CLI + GUI) share one vocabulary.
use leshiy_client::settings::TransportPref;
use leshiy_client::{Rates, State};
use serde::{Deserialize, Serialize};

/// Parameters to start a full-tunnel VPN. Field-for-field the inputs `leshiy-tun`'s
/// engine needs; the helper resolves the server IP + gateway itself (privileged side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartParams {
    /// The `leshiy://` server URI.
    pub uri: String,
    /// Preferred transport (VPN uses TCP/REALITY for UDP today).
    pub transport: TransportPref,
    /// TUN MTU.
    pub mtu: u16,
    /// TUN interface name.
    pub tun_name: String,
    /// DNS resolver forced through the tunnel.
    pub dns: String,
    /// Global split-tunnel ruleset. Omitted by older callers → empty (plain full tunnel).
    #[serde(default)]
    pub split_tunnel: leshiy_client::SplitTunnel,
}

/// A request from the caller to the helper. One JSON object per line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    /// Build the tunnel + bring up the TUN device (idempotent guard: errors if running).
    StartVpn(StartParams),
    /// Tear down the active session (restores routes/DNS). No-op if idle.
    Stop,
    /// Return a one-shot `Status` snapshot.
    GetStatus,
    /// Stream `Event` frames (one JSON line each) as state/stats change, until the
    /// connection is closed by the caller.
    Subscribe,
}

/// A one-shot status snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub state: State,
    pub rates: Rates,
}

/// A push notification on a `Subscribe` connection. Either field may be `None` when
/// only one of state/stats changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub state: Option<State>,
    pub rates: Option<Rates>,
}

/// A response from the helper. One JSON object per line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "kebab-case")]
pub enum Response {
    /// Acknowledgement for `StartVpn` / `Stop`.
    Ok,
    /// Reply to `GetStatus`.
    Status { status: Status },
    /// A streamed push frame on a `Subscribe` connection.
    Event(Event),
    /// A failure (e.g. `"unauthorized"`, the engine error). Carries no oracle detail
    /// beyond the `HelperError` `Display` string.
    Err { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use leshiy_client::settings::TransportPref;
    use leshiy_client::{Rates, State};

    fn sample_params() -> StartParams {
        StartParams {
            uri: "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000".into(),
            transport: TransportPref::Tcp,
            mtu: 1400,
            tun_name: "leshiy0".into(),
            dns: "1.1.1.1".into(),
            split_tunnel: leshiy_client::SplitTunnel::default(),
        }
    }

    #[test]
    fn start_params_without_split_tunnel_defaults() {
        // An old caller's StartVpn (no split_tunnel field) deserializes to an empty ruleset.
        let line = r#"{"cmd":"start-vpn","uri":"leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000","transport":"tcp","mtu":1400,"tun_name":"leshiy0","dns":"1.1.1.1"}"#;
        let req: Request = serde_json::from_str(line).unwrap();
        let Request::StartVpn(p) = req else {
            panic!("expected StartVpn");
        };
        assert!(p.split_tunnel.is_empty());
    }

    #[test]
    fn start_params_round_trips_with_split() {
        use leshiy_client::{SplitMode, SplitTunnel};
        let mut p = sample_params();
        p.split_tunnel =
            SplitTunnel::parse_lines(SplitMode::Include, "10.0.0.0/8\nexample.com\n").unwrap();
        let back: StartParams = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn start_request_round_trips() {
        let req = Request::StartVpn(sample_params());
        let line = serde_json::to_string(&req).unwrap();
        // Tagged enum: the "cmd" discriminator must be present (mirrors control.rs).
        assert!(line.contains("\"cmd\":\"start-vpn\""));
        let back: Request = serde_json::from_str(&line).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn control_requests_round_trip() {
        for req in [Request::Stop, Request::GetStatus, Request::Subscribe] {
            let line = serde_json::to_string(&req).unwrap();
            let back: Request = serde_json::from_str(&line).unwrap();
            assert_eq!(back, req);
        }
    }

    #[test]
    fn status_and_event_responses_round_trip() {
        let rates = Rates {
            up_bps: 1,
            down_bps: 2,
            total_up: 3,
            total_down: 4,
        };
        let status = Response::Status {
            status: Status {
                state: State::Connected,
                rates,
            },
        };
        let line = serde_json::to_string(&status).unwrap();
        let back: Response = serde_json::from_str(&line).unwrap();
        assert_eq!(back, status);

        let evt = Response::Event(Event {
            state: Some(State::Reconnecting),
            rates: None,
        });
        let back: Response = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        assert_eq!(back, evt);
    }

    #[test]
    fn ok_and_err_responses_round_trip() {
        let ok: Response =
            serde_json::from_str(&serde_json::to_string(&Response::Ok).unwrap()).unwrap();
        assert_eq!(ok, Response::Ok);
        let err = Response::Err {
            message: "unauthorized".into(),
        };
        let back: Response = serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();
        assert_eq!(back, err);
    }
}
