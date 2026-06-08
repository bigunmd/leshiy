use leshiy_quic::{client::run_quic_client, masquerade::Masquerade, server::run_quic_server};
use leshiy_reality::user::{InMemoryUserStore, User, UserStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn a simple TCP echo server; returns its "host:port" address string.
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

/// Bind a free UDP port, drop the socket, return the address.
/// The retry loop in the tests tolerates the small TOCTOU window.
fn free_udp_addr() -> std::net::SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

/// Bind a free TCP port, drop the listener, return the address.
fn free_tcp_addr() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

/// Spawn `run_quic_server` and return the UDP address it is listening on.
async fn start_server(store: Arc<dyn UserStore>) -> std::net::SocketAddr {
    let (certs, key) = self_signed();
    let bound = free_udp_addr();
    tokio::spawn(async move {
        let _ = run_quic_server(bound, certs, key, store, Masquerade::default()).await;
    });
    bound
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

    // SOCKS5 reply (10-byte fixed header for IPv4 reply)
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

// ---------------------------------------------------------------------------
// Test 1: happy path — SOCKS5 → QUIC → echo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks5_over_quic_echo() {
    let echo = spawn_echo().await;
    let store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: [1; 8],
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }]));
    let server = start_server(store).await;
    let socks = free_tcp_addr();

    {
        let echo2 = echo.clone();
        let _ = echo2; // suppress unused warning
        tokio::spawn(async move {
            let _ = run_quic_client(server, "example.test", socks, [1; 8], true).await;
        });
    }

    let payload = b"hello-over-quic".to_vec();
    let mut last = String::from("(no attempt yet)");
    for _ in 0..50 {
        match socks_connect_echo(socks, &echo, &payload).await {
            Ok(g) if g == payload => return, // PASS
            Ok(_) => last = "payload mismatch".into(),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("socks5_over_quic_echo failed after 50 retries: {last}");
}

// ---------------------------------------------------------------------------
// Test 2: unknown short_id is refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_short_id_refused() {
    let echo = spawn_echo().await;
    let store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: [1; 8],
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }]));
    let server = start_server(store).await;
    let socks = free_tcp_addr();

    // Client uses short_id [9;8] which is NOT in the store.
    tokio::spawn(async move {
        let _ = run_quic_client(server, "example.test", socks, [9; 8], true).await;
    });

    // First confirm the client's SOCKS listener is actually up (TCP-connectable) — so a
    // failure below means "tunnel refused", NOT "client never started" (non-vacuous test).
    let mut client_up = false;
    for _ in 0..30 {
        if tokio::net::TcpStream::connect(socks).await.is_ok() {
            client_up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(client_up, "client SOCKS listener never came up");

    // The client is up, but the server closed its unauthorized QUIC connection, so every
    // SOCKS5→echo round-trip must FAIL (the tunnel can't carry data).
    let mut ok = false;
    for _ in 0..15 {
        if socks_connect_echo(socks, &echo, b"x").await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !ok,
        "unauthorized short_id should not be able to tunnel data"
    );
}

// ---------------------------------------------------------------------------
// Test 3: per-user data cap is enforced over QUIC
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
                    // Connection cut or timeout — cap hit
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
async fn data_cap_enforced_over_quic() {
    const CAP: u64 = 100 * 1024; // 100 KB
    const PAYLOAD: usize = 512 * 1024; // 512 KB >> cap

    let echo = spawn_echo().await;
    let store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: [2; 8],
        enabled: true,
        expires_at: None,
        data_cap: Some(CAP),
        rate_up: None,
        rate_down: None,
    }]));
    let server = start_server(store).await;
    let socks = free_tcp_addr();

    tokio::spawn(async move {
        let _ = run_quic_client(server, "example.test", socks, [2; 8], true).await;
    });

    // Wait for client to come up.
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(socks).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "SOCKS port never became available for data_cap test");

    // Stream 512 KB through echo — the relay must cut the transfer before all of
    // it gets through.  Up+down are both counted, so the effective per-byte budget
    // is ~50 KB of echoed data before the server closes the stream.
    let echoed = stream_through_socks_echo(socks, &echo, PAYLOAD, 8 * 1024).await;

    assert!(
        echoed < PAYLOAD,
        "data cap should have cut the transfer (echoed {echoed} bytes, payload was {PAYLOAD})"
    );

    println!("data_cap_enforced_over_quic: echoed {echoed} bytes (cap={CAP}, payload={PAYLOAD})");
}
