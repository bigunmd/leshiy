// In-process REALITY e2e oracle (M1.3d Task 4).
//
// `authed_tunnel_echo`   — authed client → REALITY server → mux → relay → echo target.
//                          Proves auth + handshake takeover + TLS tunnel + mux + relay work end-to-end.
// `prober_gets_real_dest` — plain (non-auth) ClientHello → serve_connection relays it to
//                           the real rustls dest; client gets a genuine ServerHello back.
use leshiy_reality::client::run_reality_client;
use leshiy_reality::config::{ClientAuthConfig, ServerAuthConfig};
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

/// Spawn a rustls TLS 1.3 "dest" server (self-signed cert for www.example.com).
/// Returns "127.0.0.1:<port>".
///
/// Uses the DEFAULT rustls CryptoProvider (aws-lc-rs, PQ-preferring: X25519MLKEM768
/// first). The REALITY client now sends a real 0x11EC key_share, so the dest selects
/// X25519MLKEM768, the REALITY server encapsulates (ML-KEM + X25519 hybrid), and the
/// client decapsulates — proving the HRR gap is closed end-to-end.
async fn spawn_rustls_dest() -> String {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["www.example.com".to_string()]).unwrap();

    let cert_der: CertificateDer<'static> = cert.into();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    // Use the aws-lc-rs PQ-preferring provider — X25519MLKEM768 (0x11EC) is selected
    // because our ClientHello now includes a real ML-KEM encapsulation key share.
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

/// Spawn a plain TCP echo server. Returns "127.0.0.1:<port>".
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
                        s.write_all(&b[..n]).await.unwrap();
                    }
                });
            }
        }
    });
    addr
}

/// Attempt one SOCKS5 CONNECT → echo payload round-trip.
async fn try_socks_echo(socks_addr: &str, echo: &str) -> Result<(), String> {
    let mut c = TcpStream::connect(socks_addr)
        .await
        .map_err(|e| e.to_string())?;
    // Greeting
    c.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.map_err(|e| e.to_string())?;
    // CONNECT request (ATYP=domain)
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
    // Send payload and expect it echoed back
    c.write_all(b"leshiy-reality-e2e")
        .await
        .map_err(|e| e.to_string())?;
    let mut got = [0u8; 18];
    c.read_exact(&mut got).await.map_err(|e| e.to_string())?;
    if &got == b"leshiy-reality-e2e" {
        Ok(())
    } else {
        Err("echo mismatch".into())
    }
}

/// The oracle: an authed REALITY client tunnels a SOCKS5 CONNECT to an echo target.
/// Proves auth → handshake takeover → TLS tunnel → mux → relay → echo all work together.
#[tokio::test]
async fn authed_tunnel_echo() {
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    let server_static = [0x55u8; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server_static)).to_bytes();

    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(server_static),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
        max_time_diff: Duration::from_secs(120),
        dest,
    });
    let cert = Arc::new(ServerCert::generate());

    // Spawn the REALITY server.
    let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let saddr = sl.local_addr().unwrap().to_string();
    {
        let scfg = scfg.clone();
        let cert = cert.clone();
        tokio::spawn(async move {
            let store = std::sync::Arc::new(InMemoryUserStore::from_short_ids(
                scfg.short_ids.iter().copied(),
            ));
            let _ =
                run_reality_server(sl, scfg, store, std::sync::Arc::new(DirectEgress), cert).await;
        });
    }

    // Pick a free SOCKS port by binding :0 then dropping.
    let cl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = cl.local_addr().unwrap().to_string();
    drop(cl);

    // Spawn the REALITY client.
    {
        let saddr = saddr.clone();
        let socks = socks_addr.clone();
        tokio::spawn(async move {
            let ccfg = ClientAuthConfig {
                server_public,
                short_id: [1, 2, 3, 4, 0, 0, 0, 0],
                sni: "www.example.com".into(),
            };
            let _ = run_reality_client(&saddr, ccfg, &socks).await;
        });
    }

    // Drive SOCKS5 → echo through the tunnel.
    // Retry loop tolerates runtime startup ordering.
    let mut last_err = String::new();
    for _ in 0..50 {
        match try_socks_echo(&socks_addr, &echo).await {
            Ok(()) => return,
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("authed tunnel echo failed after retries: {last_err}");
}

/// Anti-probe check: an unauthed (plain) ClientHello is relayed to the real rustls dest;
/// the client receives a genuine ServerHello back (not an alert or garbage).
#[tokio::test]
async fn prober_gets_real_dest() {
    let dest = spawn_rustls_dest().await;
    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new([0x55u8; 32]),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
        max_time_diff: Duration::from_secs(120),
        dest,
    });
    let cert = Arc::new(ServerCert::generate());

    let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let saddr = sl.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = sl.accept().await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let store = std::sync::Arc::new(InMemoryUserStore::from_short_ids(
            scfg.short_ids.iter().copied(),
        ));
        let _ = leshiy_reality::server::serve_connection(
            s,
            scfg,
            store,
            std::sync::Arc::new(DirectEgress),
            cert,
            now,
        )
        .await;
    });

    // Connect as an unauthed prober with a plain ClientHello.
    let mut c = TcpStream::connect(saddr).await.unwrap();
    let ch = leshiy_tls::client_hello::build_client_hello(
        &leshiy_tls::fingerprint::Profile::yandex(),
        "www.example.com",
        &[3u8; 32],
        &[0u8; 1184],
        [4u8; 32],
    );
    leshiy_tls::record::write_record(
        &mut c,
        &leshiy_tls::record::Record {
            content_type: leshiy_tls::record::HANDSHAKE,
            payload: ch,
        },
    )
    .await
    .unwrap();

    // The real dest's ServerHello should come back through the relay.
    let rec = leshiy_tls::record::read_record(&mut c).await.unwrap();
    leshiy_tls::server_hello::check_not_alert(rec.content_type, &rec.payload)
        .expect("dest ServerHello, not alert");
    leshiy_tls::server_hello::parse_server_hello(&rec.payload).expect("parse dest SH");
}

// A well-formed TLS record whose payload is NOT a ClientHello must be forwarded to dest
// (anti-probe: garbage gets a genuine dest session). Uses a plain echo as "dest" so the
// relay is directly assertable: the forwarded record bytes echo back through the relay.
#[tokio::test]
async fn garbage_is_relayed_to_dest() {
    let echo = spawn_echo().await;
    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new([0x55u8; 32]),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
        max_time_diff: Duration::from_secs(120),
        dest: echo,
    });
    let cert = Arc::new(ServerCert::generate());
    let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let saddr = sl.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = sl.accept().await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let store = std::sync::Arc::new(InMemoryUserStore::from_short_ids(
            scfg.short_ids.iter().copied(),
        ));
        let _ = leshiy_reality::server::serve_connection(
            s,
            scfg,
            store,
            std::sync::Arc::new(DirectEgress),
            cert,
            now,
        )
        .await;
    });

    let mut c = TcpStream::connect(saddr).await.unwrap();
    let garbage = leshiy_tls::record::Record {
        content_type: 0x17, // application_data, not a handshake/ClientHello
        payload: b"this-is-not-a-clienthello".to_vec(),
    };
    leshiy_tls::record::write_record(&mut c, &garbage)
        .await
        .unwrap();
    let expect = garbage.encode();
    let mut got = vec![0u8; expect.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut got))
        .await
        .expect("relay timed out")
        .expect("read echoed bytes");
    assert_eq!(
        got, expect,
        "garbage record should be relayed to dest and echoed back"
    );
}
