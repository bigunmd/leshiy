//! End-to-end UDP datagram tunnel: authed REALITY client → server → UDP egress → UDP echo.
//! Proves CAP_DATAGRAM negotiation + datagram framing + server UDP relay work together.
use leshiy_reality::client::connect_reality;
use leshiy_reality::config::{ClientAuthConfig, ServerAuthConfig};
use leshiy_reality::egress::DirectEgress;
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::server::run_reality_server;
use leshiy_reality::user::InMemoryUserStore;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Spawn a UDP echo server. Returns "127.0.0.1:<port>".
async fn spawn_udp_echo() -> String {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            if let Ok((n, from)) = s.recv_from(&mut b).await {
                let _ = s.send_to(&b[..n], from).await;
            }
        }
    });
    addr
}

#[tokio::test]
async fn authed_datagram_echo() {
    let echo = spawn_udp_echo().await;

    let server_static = [0x55u8; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server_static)).to_bytes();
    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(server_static),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
        max_time_diff: Duration::from_secs(120),
        dest: "www.example.com:443".into(),
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

    // Retry the whole connect+roundtrip to tolerate server startup ordering.
    let mut last = String::new();
    for _ in 0..50 {
        match try_once(&saddr, server_public, &echo).await {
            Ok(()) => return,
            Err(e) => {
                last = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("authed datagram echo failed after retries: {last}");
}

async fn try_once(saddr: &str, server_public: [u8; 32], echo: &str) -> Result<(), String> {
    let ccfg = ClientAuthConfig {
        server_public,
        short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        sni: "www.example.com".into(),
    };
    let conn = connect_reality(saddr, ccfg)
        .await
        .map_err(|e| e.to_string())?;
    // `open_datagram` returns a mux `Stream` (kind = Udp); its inherent send/recv
    // map onto Datagram frames.
    let mut flow = conn.open_datagram(echo).await.map_err(|e| e.to_string())?;
    flow.send(b"udp-e2e".to_vec())
        .await
        .map_err(|e| e.to_string())?;
    let got = tokio::time::timeout(Duration::from_secs(2), flow.recv())
        .await
        .map_err(|_| "recv timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if got == b"udp-e2e" {
        Ok(())
    } else {
        Err(format!("mismatch: {got:?}"))
    }
}
