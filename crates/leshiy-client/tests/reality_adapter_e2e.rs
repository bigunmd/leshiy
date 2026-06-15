//! Live REALITY adapter oracle: an authed `RealTransport` dial → open → byte round-trip
//! through a real in-process REALITY server to an echo target. Proves the REALITY
//! `ProxyStream`/`Tunnel`/`Transport` adapters work end-to-end over the real mux.
use leshiy_client::TransportPref;
use leshiy_client::adapter::RealTransport;
use leshiy_client::transport::Transport;
use leshiy_client::transport::Tunnel;
use leshiy_client::{
    ByteCounters, NoopProxy, State, SupervisorConfig, serve_metered, spawn_supervisor,
};
use leshiy_reality::config::{ServerAuthConfig, format_reality_uri};
use leshiy_reality::egress::DirectEgress;
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::server::run_reality_server;
use leshiy_reality::user::InMemoryUserStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// rustls TLS 1.3 "dest" for www.example.com. Returns "127.0.0.1:<port>".
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
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("rustls ServerConfig");
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

/// Plain TCP echo server. Returns "127.0.0.1:<port>".
async fn spawn_echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    loop {
                        let n = s.read(&mut b).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        let _ = s.write_all(&b[..n]).await;
                    }
                });
            }
        }
    });
    addr
}

async fn round_trip_once(uri: &str, echo: &str) -> Result<(), String> {
    let tunnel = RealTransport
        .dial(uri, TransportPref::Tcp)
        .await
        .map_err(|e| e.to_string())?;
    let mut stream = tunnel.open(echo).await.map_err(|e| e.to_string())?;
    stream
        .send(b"leshiy-adapter-e2e".to_vec())
        .await
        .map_err(|e| e.to_string())?;
    let mut got = Vec::new();
    while got.len() < 18 {
        let chunk = stream.recv().await.map_err(|e| e.to_string())?;
        if chunk.is_empty() {
            break;
        }
        got.extend_from_slice(&chunk);
    }
    if got == b"leshiy-adapter-e2e" {
        Ok(())
    } else {
        Err(format!("echo mismatch: {got:?}"))
    }
}

#[tokio::test]
async fn reality_adapter_round_trip() {
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    let server_static = [0x55u8; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server_static)).to_bytes();
    let short_id = [1u8, 2, 3, 4, 0, 0, 0, 0];

    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(server_static),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([short_id]),
        max_time_diff: Duration::from_secs(120),
        dest,
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

    let uri = format_reality_uri(&server_public, &saddr, "www.example.com", &short_id);

    // Retry loop tolerates runtime startup ordering.
    let mut last = String::new();
    for _ in 0..50 {
        match round_trip_once(&uri, &echo).await {
            Ok(()) => return,
            Err(e) => {
                last = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("reality adapter round-trip failed after retries: {last}");
}

/// Minimal SOCKS5 CONNECT + echo round-trip. Returns Ok if the bytes echo back.
async fn try_socks_echo(socks_addr: &str, echo: &str) -> Result<(), String> {
    let mut c = TcpStream::connect(socks_addr)
        .await
        .map_err(|e| e.to_string())?;
    c.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.map_err(|e| e.to_string())?;
    let (h, p) = echo.rsplit_once(':').unwrap();
    let host = h.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&p.parse::<u16>().unwrap().to_be_bytes());
    c.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.map_err(|e| e.to_string())?;
    if rep[1] != 0x00 {
        return Err(format!("socks reply {}", rep[1]));
    }
    c.write_all(b"leshiy-supervisor-e2e")
        .await
        .map_err(|e| e.to_string())?;
    let mut got = [0u8; 21];
    c.read_exact(&mut got).await.map_err(|e| e.to_string())?;
    if &got == b"leshiy-supervisor-e2e" {
        Ok(())
    } else {
        Err("echo mismatch".into())
    }
}

/// Spin up an echo target + rustls dest + REALITY server; return (uri, echo_addr).
async fn start_reality_server() -> (String, String) {
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;
    let server_static = [0x55u8; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server_static)).to_bytes();
    let short_id = [1u8, 2, 3, 4, 0, 0, 0, 0];
    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(server_static),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([short_id]),
        max_time_diff: Duration::from_secs(120),
        dest,
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
    let uri = format_reality_uri(&server_public, &saddr, "www.example.com", &short_id);
    (uri, echo)
}

/// Bind :0 then drop to get a likely-free local SOCKS address.
async fn free_socks_addr() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

#[tokio::test]
async fn metered_listener_round_trip_and_counts() {
    let (uri, echo) = start_reality_server().await;

    let mut tunnel: Option<Arc<dyn Tunnel>> = None;
    for _ in 0..50 {
        if let Ok(boxed) = RealTransport.dial(&uri, TransportPref::Tcp).await {
            tunnel = Some(Arc::from(boxed));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let tunnel = tunnel.expect("dial a reality tunnel");

    let counters = Arc::new(ByteCounters::new());
    let socks_addr = free_socks_addr().await;
    tokio::spawn(serve_metered(tunnel, socks_addr, counters.clone()));

    let mut ok = false;
    let mut last = String::new();
    for _ in 0..50 {
        match try_socks_echo(&socks_addr.to_string(), &echo).await {
            Ok(()) => {
                ok = true;
                break;
            }
            Err(e) => {
                last = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert!(ok, "metered SOCKS echo failed: {last}");
    let (up, down) = counters.totals();
    assert!(
        up > 0 && down > 0,
        "counters did not move: up={up} down={down}"
    );
}

#[tokio::test]
async fn supervisor_connects_serves_and_disconnects() {
    let (uri, echo) = start_reality_server().await;
    let socks_addr = free_socks_addr().await;

    let cfg = SupervisorConfig {
        socks_addr,
        pref: TransportPref::Tcp,
        ..SupervisorConfig::default()
    };
    let handle = spawn_supervisor(RealTransport, NoopProxy, cfg);
    let mut srx = handle.subscribe_state();
    handle.connect(uri.clone());

    // Reach Connected. The machine does NOT auto-retry the FIRST dial, so a dial that
    // races server startup lands in `Error`; re-issue Connect on Error.
    let reached = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let s = *srx.borrow_and_update();
            if s == State::Connected {
                return;
            }
            if s == State::Error {
                tokio::time::sleep(Duration::from_millis(100)).await;
                handle.connect(uri.clone());
            }
            if srx.changed().await.is_err() {
                panic!("state channel closed before Connected");
            }
        }
    })
    .await;
    assert!(reached.is_ok(), "supervisor never reached Connected");

    let mut ok = false;
    for _ in 0..50 {
        if try_socks_echo(&socks_addr.to_string(), &echo).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "SOCKS echo via supervisor failed");

    handle.disconnect();
    let disc = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if *srx.borrow_and_update() == State::Disconnected {
                return;
            }
            if srx.changed().await.is_err() {
                return;
            }
        }
    })
    .await;
    assert!(disc.is_ok(), "supervisor never reached Disconnected");
}
