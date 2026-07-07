//! Connector end-to-end tests: client → A (entry) → B (exit) → echo.
//!
//! Three scenarios:
//!   1. `connector_quic_front_two_hop`   — A is a QUIC server; B is a QUIC server.
//!   2. `connector_reality_front_two_hop` — A is a REALITY server; B is a QUIC server.
//!   3. `connector_enforces_at_entry`    — A has a data cap; enforcement stops transfer at A.
//!
//! Topology (all three): echo ← B (QUIC, DirectEgress, allows CONNECTOR_SID=[2;8])
//!                            ← A (entry, ConnectorEgress→B, allows USER_SID=[1;8])
//!                            ← client

use leshiy_quic::{
    client::run_quic_client,
    connector::ConnectorEgress,
    endpoint::{CertVerification, cert_sha256},
    masquerade::Masquerade,
};
use leshiy_reality::{
    client::run_reality_client,
    config::{ClientAuthConfig, ServerAuthConfig},
    egress::DirectEgress,
    handshake::ServerCert,
    server::run_reality_server,
    user::{InMemoryUserStore, User},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Short-ID constants
// ---------------------------------------------------------------------------

const USER_SID: [u8; 8] = [1; 8];
const CONNECTOR_SID: [u8; 8] = [2; 8];
const EXIT_SID: [u8; 8] = [3; 8];

// ---------------------------------------------------------------------------
// Common helpers
// ---------------------------------------------------------------------------

/// Spawn a plain TCP echo server; returns its "host:port" address string.
async fn spawn_echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 4096];
                    loop {
                        let n = s.read(&mut b).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        if s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
    a
}

/// Generate a self-signed certificate for "example.test" using rcgen 0.13.
fn self_signed() -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["example.test".into()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    (vec![cert_der], key_der)
}

/// Bind a free TCP port, drop the listener, return the address.
fn free_tcp_addr() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

/// Bind a QUIC server on an ephemeral port and start its accept loop, returning the bound
/// address. RACE-FREE: the endpoint owns the socket from bind through serve, so a parallel
/// test can never grab the port in a gap — unlike `free_udp_addr` + `run_quic_server(addr)`,
/// whose drop/rebind window caused intermittent "certificate pin mismatch".
fn spawn_quic_node(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    store: Arc<dyn leshiy_reality::user::UserStore>,
    egress: Arc<dyn leshiy_reality::egress::Egress>,
) -> std::net::SocketAddr {
    let ep = leshiy_quic::endpoint::server_endpoint("127.0.0.1:0".parse().unwrap(), certs, key)
        .expect("bind quic endpoint");
    let addr = ep.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = leshiy_quic::server::serve_quic_on_endpoint(
            ep,
            store,
            leshiy_quic::masquerade::Masquerade::default(),
            egress,
        )
        .await;
    });
    addr
}

/// Drive a full SOCKS5 CONNECT over the given SOCKS proxy to the echo address,
/// send `payload`, read exactly `payload.len()` bytes back.
async fn socks_connect_echo(
    socks: std::net::SocketAddr,
    echo: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut c = TcpStream::connect(socks).await.map_err(|e| e.to_string())?;

    // SOCKS5 greeting: VER=5, NMETHODS=1, NO_AUTH=0
    c.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.map_err(|e| e.to_string())?;

    // SOCKS5 CONNECT: domain ATYP (0x03)
    let (h, p) = echo.rsplit_once(':').unwrap();
    let host = h.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&p.parse::<u16>().unwrap().to_be_bytes());
    c.write_all(&req).await.map_err(|e| e.to_string())?;

    // SOCKS5 reply (10-byte fixed for IPv4 reply)
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.map_err(|e| e.to_string())?;
    if rep[1] != 0 {
        return Err(format!("socks reply {}", rep[1]));
    }

    // Send payload and read it back
    c.write_all(payload).await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; payload.len()];
    c.read_exact(&mut got).await.map_err(|e| e.to_string())?;
    Ok(got)
}

/// Spawn a rustls TLS 1.3 "dest" server (self-signed cert for www.example.com).
/// Used by the REALITY-front test as the borrowed-site destination.
async fn spawn_rustls_dest() -> String {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["www.example.com".to_string()]).unwrap();
    let cert_der: CertificateDer<'static> = cert.into();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let server_cfg = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("bad protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("failed to build rustls ServerConfig");
    let acc = TlsAcceptor::from(Arc::new(server_cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            if let Ok((s, _)) = l.accept().await {
                let a = acc.clone();
                tokio::spawn(async move {
                    let _ = a.accept(s).await;
                });
            }
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// Helper: spawn Exit B as a QUIC server with DirectEgress.
// Returns (b_addr, b_pin) where b_pin = SHA-256 of B's end-entity cert.
// ---------------------------------------------------------------------------

async fn spawn_exit_b() -> (std::net::SocketAddr, [u8; 32]) {
    let (b_certs, b_key) = self_signed();
    let b_pin = cert_sha256(b_certs[0].as_ref());
    let b_store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: CONNECTOR_SID,
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }]));
    let b_addr = spawn_quic_node(
        b_certs,
        b_key,
        b_store,
        Arc::new(DirectEgress::allowing_private()),
    );
    // Give B a moment to start listening before callers try to connect.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (b_addr, b_pin)
}

// ---------------------------------------------------------------------------
// Test 1: connector_quic_front_two_hop
//
// client → A (QUIC, ConnectorEgress→B) → B (QUIC, DirectEgress) → echo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connector_quic_front_two_hop() {
    let echo = spawn_echo().await;

    // Step 1: start B.
    let (b_addr, b_pin) = spawn_exit_b().await;

    // Step 2: build A's egress (ConnectorEgress → B).
    // B must already be listening when ConnectorEgress::connect runs (warm QUIC handshake).
    let connector = ConnectorEgress::connect(
        b_addr,
        "example.test",
        CONNECTOR_SID,
        CertVerification::Pinned(b_pin),
    )
    .await
    .expect("ConnectorEgress::connect to B must succeed");

    // Step 3: start A as a QUIC server with the ConnectorEgress.
    let (a_certs, a_key) = self_signed();
    let a_pin = cert_sha256(a_certs[0].as_ref());
    let a_store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: USER_SID,
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }]));
    let a_addr = spawn_quic_node(a_certs, a_key, a_store, Arc::new(connector));

    // Step 4: start the client pointing at A.
    let socks = free_tcp_addr();
    tokio::spawn(async move {
        let _ = run_quic_client(
            a_addr,
            "example.test",
            socks,
            USER_SID,
            CertVerification::Pinned(a_pin),
        )
        .await;
    });

    // Step 5: retry SOCKS5 → echo round-trip (tolerates startup ordering).
    let payload = b"connector-quic-two-hop".to_vec();
    let mut last = String::from("(no attempt yet)");
    for _ in 0..60 {
        match socks_connect_echo(socks, &echo, &payload).await {
            Ok(g) if g == payload => return, // PASS
            Ok(_) => last = "payload mismatch".into(),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("connector_quic_front_two_hop failed after 60 retries: {last}");
}

// ---------------------------------------------------------------------------
// Test 2: connector_reality_front_two_hop
//
// client → A (REALITY/TCP, ConnectorEgress→B) → B (QUIC, DirectEgress) → echo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connector_reality_front_two_hop() {
    let echo = spawn_echo().await;

    // Step 1: start B (QUIC exit).
    let (b_addr, b_pin) = spawn_exit_b().await;

    // Step 2: build A's egress (ConnectorEgress → B).
    let connector = ConnectorEgress::connect(
        b_addr,
        "example.test",
        CONNECTOR_SID,
        CertVerification::Pinned(b_pin),
    )
    .await
    .expect("ConnectorEgress::connect to B must succeed");

    // Step 3: set up A as a REALITY server.
    // REALITY needs a borrowed-site "dest" — spawn a real rustls server.
    let dest = spawn_rustls_dest().await;

    let server_static = [0x42u8; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server_static)).to_bytes();

    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(server_static),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([USER_SID]),
        max_time_diff: Duration::from_secs(120),
        dest,
        dest_by_sni: Default::default(),
    });
    let cert = Arc::new(ServerCert::generate());

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr_tcp = a_listener.local_addr().unwrap().to_string();
    {
        let scfg = scfg.clone();
        let cert = cert.clone();
        let egress = Arc::new(connector);
        tokio::spawn(async move {
            let a_store = Arc::new(InMemoryUserStore::from_short_ids([USER_SID]));
            let _ = run_reality_server(a_listener, scfg, a_store, egress, cert).await;
        });
    }

    // Step 4: start the REALITY client.
    let socks_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_l.local_addr().unwrap().to_string();
    drop(socks_l);
    {
        let a_addr_tcp = a_addr_tcp.clone();
        let socks_addr = socks_addr.clone();
        tokio::spawn(async move {
            let ccfg = ClientAuthConfig {
                server_public,
                short_id: USER_SID,
                sni: "www.example.com".into(),
            };
            let _ = run_reality_client(&a_addr_tcp, ccfg, &socks_addr).await;
        });
    }

    // Step 5: retry SOCKS5 → echo round-trip.
    let socks_sa: std::net::SocketAddr = socks_addr.parse().unwrap();
    let payload = b"connector-reality-two-hop".to_vec();
    let mut last = String::from("(no attempt yet)");
    for _ in 0..60 {
        match socks_connect_echo(socks_sa, &echo, &payload).await {
            Ok(g) if g == payload => return, // PASS
            Ok(_) => last = "payload mismatch".into(),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("connector_reality_front_two_hop failed after 60 retries: {last}");
}

// ---------------------------------------------------------------------------
// Test 3: connector_enforces_at_entry
//
// A has a small data_cap; pushing >cap through the connector is cut at A.
// Uses QUIC-front (simplest).
// ---------------------------------------------------------------------------

/// Stream `total` bytes through the SOCKS proxy to the echo in `chunk_size` chunks;
/// returns how many bytes were successfully echoed back before the connection was cut.
async fn stream_through_socks_echo(
    socks: std::net::SocketAddr,
    echo: &str,
    total: usize,
    chunk_size: usize,
) -> usize {
    let mut c = match TcpStream::connect(socks).await {
        Ok(s) => s,
        Err(_) => return 0,
    };
    // SOCKS5 greeting
    if c.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return 0;
    }
    let mut sel = [0u8; 2];
    if c.read_exact(&mut sel).await.is_err() {
        return 0;
    }
    // SOCKS5 CONNECT
    let (h, p) = echo.rsplit_once(':').unwrap();
    let host = h.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&p.parse::<u16>().unwrap().to_be_bytes());
    if c.write_all(&req).await.is_err() {
        return 0;
    }
    let mut rep = [0u8; 10];
    if c.read_exact(&mut rep).await.is_err() {
        return 0;
    }
    if rep[1] != 0 {
        return 0;
    }

    let chunk = vec![0u8; chunk_size];
    let mut echoed = 0usize;
    let mut sent = 0usize;

    while sent < total {
        let n = chunk_size.min(total - sent);
        if c.write_all(&chunk[..n]).await.is_err() {
            break;
        }
        sent += n;

        // Read back what we can within a short timeout.
        let mut buf = vec![0u8; n];
        let mut read = 0usize;
        while read < n {
            match tokio::time::timeout(Duration::from_millis(500), c.read(&mut buf[read..])).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                    return echoed + read;
                }
                Ok(Ok(k)) => read += k,
            }
        }
        echoed += read;
    }
    echoed
}

#[tokio::test]
async fn connector_enforces_at_entry() {
    const CAP: u64 = 100 * 1024; // 100 KB cap on A's user
    const PAYLOAD: usize = 512 * 1024; // 512 KB >> cap

    let echo = spawn_echo().await;

    // Step 1: start B (no cap on CONNECTOR_SID).
    let (b_addr, b_pin) = spawn_exit_b().await;

    // Step 2: build ConnectorEgress → B.
    let connector = ConnectorEgress::connect(
        b_addr,
        "example.test",
        CONNECTOR_SID,
        CertVerification::Pinned(b_pin),
    )
    .await
    .expect("ConnectorEgress::connect to B");

    // Step 3: start A with USER_SID capped at 100 KB.
    let (a_certs, a_key) = self_signed();
    let a_pin = cert_sha256(a_certs[0].as_ref());
    let a_store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: USER_SID,
        enabled: true,
        expires_at: None,
        data_cap: Some(CAP),
        rate_up: None,
        rate_down: None,
    }]));
    let a_addr = spawn_quic_node(a_certs, a_key, a_store, Arc::new(connector));

    // Step 4: start the client.
    let socks = free_tcp_addr();
    tokio::spawn(async move {
        let _ = run_quic_client(
            a_addr,
            "example.test",
            socks,
            USER_SID,
            CertVerification::Pinned(a_pin),
        )
        .await;
    });

    // Wait for client SOCKS listener to be up.
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(socks).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "SOCKS listener never came up for enforcement test");

    // Step 5: stream 512 KB — must be cut before all of it echoes back.
    let echoed = stream_through_socks_echo(socks, &echo, PAYLOAD, 8 * 1024).await;

    assert!(
        echoed < PAYLOAD,
        "data cap at A should have cut the transfer (echoed {echoed} bytes, payload={PAYLOAD})"
    );

    println!(
        "connector_enforces_at_entry: echoed {echoed} bytes before cut (cap={CAP}, payload={PAYLOAD})"
    );
}

// ---------------------------------------------------------------------------
// Helpers for the reconnect test
// ---------------------------------------------------------------------------

/// Deep-copy a PrivateKeyDer by serializing to DER bytes and rebuilding.
fn clone_key(
    key: &rustls::pki_types::PrivateKeyDer<'static>,
) -> rustls::pki_types::PrivateKeyDer<'static> {
    let der: Vec<u8> = match key {
        rustls::pki_types::PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der().to_vec(),
        rustls::pki_types::PrivateKeyDer::Sec1(k) => k.secret_sec1_der().to_vec(),
        rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        _ => panic!("unknown key type"),
    };
    rustls::pki_types::PrivateKeyDer::try_from(der).expect("clone key")
}

/// Poll until a UDP socket can NO LONGER be bound at `addr` — i.e. the server task has
/// claimed the port and is ready to accept. (A successful bind means the server hasn't
/// taken the port yet, so we keep waiting.)
async fn wait_udp(addr: std::net::SocketAddr) {
    // Give the server task time to bind and start accepting.
    // We probe by trying to bind (which should FAIL while server holds the port, meaning it's ready).
    for _ in 0..50 {
        // If we can bind, the server hasn't taken the port yet — wait more.
        // If bind fails, the server owns the port — it's ready.
        if std::net::UdpSocket::bind(addr).is_err() {
            return; // server is up
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Last resort: just wait a bit.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// Spawn a UDP echo server; returns its "127.0.0.1:<port>".
async fn spawn_udp_echo() -> String {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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

/// Open a UDP association through the egress to `target`, send `payload`, read it back.
async fn udp_roundtrip_through_egress(
    eg: &leshiy_quic::connector::ConnectorEgress,
    target: &str,
    payload: &[u8],
) -> Result<(), String> {
    use leshiy_reality::egress::Egress;
    let mut u = eg.open_udp(target).await.map_err(|e| e.to_string())?;
    // Retry: the first datagram can race the far-side association setup.
    for attempt in 0..5 {
        u.send(payload).await.map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(500), u.recv(&mut buf)).await {
            Ok(Ok(n)) if &buf[..n] == payload => return Ok(()),
            _ if attempt < 4 => continue,
            other => return Err(format!("no udp echo: {other:?}")),
        }
    }
    Err("no udp echo after retries".into())
}

/// A (ConnectorEgress → B) carries UDP to an echo via CONNECT-UDP through the two-hop path.
#[tokio::test]
async fn connector_udp_two_hop() {
    let udp_echo = spawn_udp_echo().await;
    let (b_addr, b_pin) = spawn_exit_b().await;
    let connector = ConnectorEgress::connect(
        b_addr,
        "example.test",
        CONNECTOR_SID,
        CertVerification::Pinned(b_pin),
    )
    .await
    .expect("ConnectorEgress::connect to B must succeed");
    udp_roundtrip_through_egress(&connector, &udp_echo, b"connector-udp-e2e")
        .await
        .expect("UDP echo through the connector");
}

/// Open a single tunnel through the egress to `target`, write `payload`, read it back.
async fn roundtrip_through_egress(
    eg: &leshiy_quic::connector::ConnectorEgress,
    target: &str,
    payload: &[u8],
) -> Result<(), String> {
    use leshiy_reality::egress::Egress;
    let (mut r, mut w) = eg.open(target).await.map_err(|e| e.to_string())?;
    w.write_all(payload).await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; payload.len()];
    let mut n = 0;
    while n < payload.len() {
        let k = r.read(&mut got[n..]).await.map_err(|e| e.to_string())?;
        if k == 0 {
            return Err("EOF before full payload".into());
        }
        n += k;
    }
    if got == payload {
        Ok(())
    } else {
        Err(format!("payload mismatch: got {:?}", got))
    }
}

// ---------------------------------------------------------------------------
// Test 5: connector_chain_three_hops  (A → B → C → echo)
//
// C (DirectEgress, EXIT_SID=[3;8]) ← B (ConnectorEgress→C, CONNECTOR_SID=[2;8])
//                                  ← A (ConnectorEgress→B, USER_SID=[1;8])
//                                  ← client
//
// Build order: C first (no dependencies), then B (connects to C), then A
// (connects to B), then the client.  The payload must travel A→B→C→echo.
// ---------------------------------------------------------------------------

/// Build an `InMemoryUserStore` with a single user that allows `short_id`.
fn single_user_store(short_id: [u8; 8]) -> Arc<dyn leshiy_reality::user::UserStore> {
    Arc::new(InMemoryUserStore::new(vec![User {
        short_id,
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }])) as Arc<dyn leshiy_reality::user::UserStore>
}

#[tokio::test]
async fn connector_chain_three_hops() {
    let echo = spawn_echo().await;

    // --- C: the real exit (DirectEgress). Accepts EXIT_SID=[3;8]. ---
    let (c_certs, c_key) = self_signed();
    let c_pin = cert_sha256(c_certs[0].as_ref());
    let c_store = single_user_store(EXIT_SID);
    let c_addr = spawn_quic_node(
        c_certs,
        c_key,
        c_store,
        Arc::new(DirectEgress::allowing_private()),
    );
    wait_udp(c_addr).await;

    // --- B: mid-hop (ConnectorEgress→C). Accepts CONNECTOR_SID=[2;8]. ---
    let (b_certs, b_key) = self_signed();
    let b_pin = cert_sha256(b_certs[0].as_ref());
    let b_egress = ConnectorEgress::connect(
        c_addr,
        "example.test",
        EXIT_SID,
        CertVerification::Pinned(c_pin),
    )
    .await
    .expect("ConnectorEgress::connect B→C must succeed");
    let b_store = single_user_store(CONNECTOR_SID);
    let b_addr = spawn_quic_node(b_certs, b_key, b_store, Arc::new(b_egress));
    wait_udp(b_addr).await;

    // --- A: entry (ConnectorEgress→B). Accepts USER_SID=[1;8]. ---
    let (a_certs, a_key) = self_signed();
    let a_pin = cert_sha256(a_certs[0].as_ref());
    let a_egress = ConnectorEgress::connect(
        b_addr,
        "example.test",
        CONNECTOR_SID,
        CertVerification::Pinned(b_pin),
    )
    .await
    .expect("ConnectorEgress::connect A→B must succeed");
    let a_store = single_user_store(USER_SID);
    let a_addr = spawn_quic_node(a_certs, a_key, a_store, Arc::new(a_egress));
    wait_udp(a_addr).await;

    // --- Client: connects to A, gets a SOCKS5 port. ---
    let socks = free_tcp_addr();
    tokio::spawn(async move {
        let _ = run_quic_client(
            a_addr,
            "example.test",
            socks,
            USER_SID,
            CertVerification::Pinned(a_pin),
        )
        .await;
    });

    // --- Drive SOCKS5 → echo through the full A→B→C→echo chain. ---
    let payload = b"chain-three-hops".to_vec();
    let mut last = String::from("(no attempt yet)");
    for _ in 0..80 {
        match socks_connect_echo(socks, &echo, &payload).await {
            Ok(g) if g == payload => return, // PASS
            Ok(_) => last = "payload mismatch".into(),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("connector_chain_three_hops failed after 80 retries: {last}");
}

// ---------------------------------------------------------------------------
// Test 4: connector_reconnects_after_exit_restart
//
// ConnectorEgress → B-v1; kill B-v1; restart B-v2 at same addr+cert; next open reconnects.
// ---------------------------------------------------------------------------

/// Build a B-server endpoint at `addr`, retrying the bind for a short while so the test
/// is robust against the previous holder still releasing the UDP port after `close()`.
async fn bind_b_endpoint(
    addr: std::net::SocketAddr,
    certs: &[CertificateDer<'static>],
    key: &rustls::pki_types::PrivateKeyDer<'static>,
) -> quinn::Endpoint {
    for _ in 0..50 {
        match leshiy_quic::endpoint::server_endpoint(addr, certs.to_vec(), clone_key(key)) {
            Ok(ep) => return ep,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    }
    leshiy_quic::endpoint::server_endpoint(addr, certs.to_vec(), clone_key(key))
        .expect("bind B endpoint at addr")
}

#[tokio::test]
async fn connector_reconnects_after_exit_restart() {
    let echo = spawn_echo().await;
    let (b_certs, b_key) = self_signed();
    let b_pin = cert_sha256(b_certs[0].as_ref());
    let b_store = || {
        Arc::new(InMemoryUserStore::new(vec![User {
            short_id: [2; 8],
            enabled: true,
            expires_at: None,
            data_cap: None,
            rate_up: None,
            rate_down: None,
        }])) as Arc<dyn leshiy_reality::user::UserStore>
    };

    // --- B v1: build the endpoint HERE so the test OWNS it and can close() it.
    //     Bind on :0 to get a race-free ephemeral port; read the address back from the endpoint. ---
    let ep1 = leshiy_quic::endpoint::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        b_certs.clone(),
        clone_key(&b_key),
    )
    .expect("bind B-v1 endpoint");
    let b_addr = ep1.local_addr().expect("local_addr");
    let srv1 = tokio::spawn({
        let (ep, s) = (ep1.clone(), b_store());
        async move {
            let _ = leshiy_quic::server::serve_quic_on_endpoint(
                ep,
                s,
                Masquerade::default(),
                Arc::new(DirectEgress::allowing_private()),
            )
            .await;
        }
    });

    let eg = leshiy_quic::connector::ConnectorEgress::connect(
        b_addr,
        "example.test",
        [2; 8],
        CertVerification::Pinned(b_pin),
    )
    .await
    .expect("connect to B-v1");

    // Open #1 — must succeed through B-v1 to echo (this proves conn1 is live).
    roundtrip_through_egress(&eg, &echo, b"one")
        .await
        .expect("first roundtrip must succeed");

    // --- Kill conn1 for real: close() tears down ALL of ep1's live connections
    //     immediately (not just the accept loop). Then drop ep1 + its server task so the
    //     UDP socket is released and B-v2 can rebind the same addr. ---
    ep1.close(0u32.into(), b"restart");
    srv1.abort();
    let _ = srv1.await;
    drop(ep1);
    // Give the OS a moment to release the UDP socket before rebinding.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // --- B v2: fresh endpoint at the SAME addr + cert (bind retries until the port frees). ---
    let ep2 = bind_b_endpoint(b_addr, &b_certs, &b_key).await;
    let _srv2 = tokio::spawn({
        let (ep, s) = (ep2.clone(), b_store());
        async move {
            let _ = leshiy_quic::server::serve_quic_on_endpoint(
                ep,
                s,
                Masquerade::default(),
                Arc::new(DirectEgress::allowing_private()),
            )
            .await;
        }
    });
    wait_udp(b_addr).await;

    // Open #2 — conn1 is DEAD, so open_connect transport-fails → ConnectorEgress must
    // RECONNECT to B-v2 and round-trip again. Retry to absorb B-v2 readiness timing.
    let mut last = String::new();
    let mut ok = false;
    for _ in 0..30 {
        match roundtrip_through_egress(&eg, &echo, b"two").await {
            Ok(_) => {
                ok = true;
                break;
            }
            Err(e) => {
                last = e;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    assert!(ok, "connector did not reconnect after exit restart: {last}");
}
