//! End-to-end ICMP echo tunnel: authed REALITY client → server → ping socket → loopback and
//! back (ADR-0030). Proves CAP_ICMP negotiation, the `icmp:` open scheme, the server relay, and
//! the identifier restoration all work together — the last of which is invisible to unit tests,
//! because only a real ping socket rewrites the id out from under us.
//!
//! Skips where `net.ipv4.ping_group_range` is unset (`1 0`, the kernel default, on a stock dev
//! box). The container sets it; see `docker::run_cmd` and `install.sh`.
use leshiy_core::icmp;
use leshiy_reality::client::connect_reality;
use leshiy_reality::config::{ClientAuthConfig, ServerAuthConfig};
use leshiy_reality::egress::{DirectEgress, Egress};
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::server::run_reality_server;
use leshiy_reality::user::InMemoryUserStore;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The id the client's "ping" chooses. The server must put this back on the reply: the kernel
/// will have overwritten it with the ping socket's local port on the way out.
const CLIENT_ECHO_ID: u16 = 0xBEEF;
const CLIENT_ECHO_SEQ: u16 = 7;

/// Whether this host allows unprivileged ICMP sockets at all.
async fn ping_sockets_allowed() -> bool {
    DirectEgress::allowing_private()
        .open_icmp("127.0.0.1")
        .await
        .is_ok()
}

fn echo_request() -> Vec<u8> {
    let mut req = vec![icmp::V4_ECHO_REQUEST, 0, 0, 0];
    req.extend_from_slice(&CLIENT_ECHO_ID.to_be_bytes());
    req.extend_from_slice(&CLIENT_ECHO_SEQ.to_be_bytes());
    req.extend_from_slice(b"leshiy-icmp-e2e");
    assert!(icmp::set_v4_checksum(&mut req));
    req
}

#[tokio::test]
async fn authed_icmp_echo_roundtrips_and_preserves_the_client_identifier() {
    if !ping_sockets_allowed().await {
        eprintln!(
            "skipping authed_icmp_echo_roundtrips: no unprivileged ICMP socket \
             (net.ipv4.ping_group_range is {:?}). Enable with: \
             sudo sysctl -w 'net.ipv4.ping_group_range=0 2147483647'",
            std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range")
                .unwrap_or_default()
                .trim()
        );
        return;
    }

    let server_static = [0x55u8; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server_static)).to_bytes();
    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(server_static),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
        max_time_diff: Duration::from_secs(120),
        dest: "www.example.com:443".into(),
        dest_by_sni: Default::default(),
    });
    let cert = Arc::new(ServerCert::generate());

    let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let saddr = sl.local_addr().unwrap().to_string();
    {
        let scfg = scfg.clone();
        let cert = cert.clone();
        tokio::spawn(async move {
            let store = Arc::new(InMemoryUserStore::from_short_ids(
                scfg.short_ids.iter().copied(),
            ));
            let _ = run_reality_server(
                sl,
                scfg,
                store,
                Arc::new(DirectEgress::allowing_private()),
                cert,
            )
            .await;
        });
    }

    let mut last = String::new();
    for _ in 0..50 {
        match try_once(&saddr, server_public).await {
            Ok(()) => return,
            Err(e) => {
                last = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("authed icmp echo failed after retries: {last}");
}

async fn try_once(saddr: &str, server_public: [u8; 32]) -> Result<(), String> {
    let ccfg = ClientAuthConfig {
        server_public,
        short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        sni: "www.example.com".into(),
    };
    let conn = connect_reality(saddr, ccfg)
        .await
        .map_err(|e| e.to_string())?;
    // A bare IP: ICMP has no ports.
    let mut flow = conn
        .open_icmp("127.0.0.1")
        .await
        .map_err(|e| e.to_string())?;
    flow.send(echo_request().into())
        .await
        .map_err(|e| e.to_string())?;
    let got = tokio::time::timeout(Duration::from_secs(5), flow.recv())
        .await
        .map_err(|_| "recv timeout".to_string())?
        .map_err(|e| e.to_string())?;

    if !icmp::is_echo_reply(&got, false) {
        return Err(format!("not an echo reply: {:?}", &got[..got.len().min(8)]));
    }
    // The heart of it. The kernel replaced our id with the socket's port on the way out; if the
    // server did not put ours back, a real `ping` would ignore this reply as somebody else's.
    let id = u16::from_be_bytes([got[4], got[5]]);
    if id != CLIENT_ECHO_ID {
        return Err(format!("identifier not restored: {id:#06x}"));
    }
    let seq = u16::from_be_bytes([got[6], got[7]]);
    if seq != CLIENT_ECHO_SEQ {
        return Err(format!("sequence mangled: {seq}"));
    }
    // Restoring the id invalidated the checksum; the server must have recomputed it, or the
    // client's stack would drop the reply on the floor.
    if icmp::checksum(&got) != 0 {
        return Err("checksum not recomputed after the id was restored".into());
    }
    if &got[icmp::HEADER_LEN..] != b"leshiy-icmp-e2e" {
        return Err("payload not echoed intact".into());
    }
    Ok(())
}

/// Only echo goes out. A relay that forwarded arbitrary ICMP would let any client emit Redirects
/// from the exit's address — so the server must drop this rather than hand it to the socket.
#[tokio::test]
async fn non_echo_icmp_is_not_relayed() {
    if !ping_sockets_allowed().await {
        eprintln!("skipping non_echo_icmp_is_not_relayed: no unprivileged ICMP socket");
        return;
    }
    let server_static = [0x56u8; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server_static)).to_bytes();
    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(server_static),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
        max_time_diff: Duration::from_secs(120),
        dest: "www.example.com:443".into(),
        dest_by_sni: Default::default(),
    });
    let cert = Arc::new(ServerCert::generate());
    let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let saddr = sl.local_addr().unwrap().to_string();
    {
        let scfg = scfg.clone();
        let cert = cert.clone();
        tokio::spawn(async move {
            let store = Arc::new(InMemoryUserStore::from_short_ids(
                scfg.short_ids.iter().copied(),
            ));
            let _ = run_reality_server(
                sl,
                scfg,
                store,
                Arc::new(DirectEgress::allowing_private()),
                cert,
            )
            .await;
        });
    }

    let ccfg = ClientAuthConfig {
        server_public,
        short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        sni: "www.example.com".into(),
    };
    let mut conn = None;
    for _ in 0..50 {
        if let Ok(c) = connect_reality(&saddr, ccfg.clone()).await {
            conn = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let conn = conn.expect("server never came up");
    let mut flow = conn.open_icmp("127.0.0.1").await.unwrap();

    // An ICMP Redirect (type 5) — well-formed, but not echo.
    let mut redirect = vec![5u8, 0, 0, 0, 0, 0, 0, 0];
    redirect.extend_from_slice(b"payload");
    assert!(icmp::set_v4_checksum(&mut redirect));
    flow.send(redirect.into()).await.unwrap();

    // Nothing should come back: the server drops it before the socket ever sees it.
    let got = tokio::time::timeout(Duration::from_secs(2), flow.recv()).await;
    assert!(
        got.is_err(),
        "a non-echo message must not be relayed, got {got:?}"
    );
}
