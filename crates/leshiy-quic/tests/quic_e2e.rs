use bytes::Buf;
use leshiy_quic::{
    client::run_quic_client,
    endpoint::{CertVerification, cert_sha256},
    masquerade::Masquerade,
    server::run_quic_server,
};
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

/// Spawn `run_quic_server` and return the UDP address it is listening on plus the SHA-256 pin
/// of the server's end-entity certificate.
async fn start_server(store: Arc<dyn UserStore>) -> (std::net::SocketAddr, [u8; 32]) {
    let (certs, key) = self_signed();
    let pin = cert_sha256(certs[0].as_ref());
    let bound = free_udp_addr();
    tokio::spawn(async move {
        let _ = run_quic_server(bound, certs, key, store, Masquerade::default()).await;
    });
    (bound, pin)
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
    let (server, pin) = start_server(store).await;
    let socks = free_tcp_addr();

    {
        let echo2 = echo.clone();
        let _ = echo2; // suppress unused warning
        tokio::spawn(async move {
            let _ = run_quic_client(
                server,
                "example.test",
                socks,
                [1; 8],
                CertVerification::Pinned(pin),
            )
            .await;
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
    let (server, pin) = start_server(store).await;
    let socks = free_tcp_addr();

    // Client uses short_id [9;8] which is NOT in the store.
    tokio::spawn(async move {
        let _ = run_quic_client(
            server,
            "example.test",
            socks,
            [9; 8],
            CertVerification::Pinned(pin),
        )
        .await;
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
    let (server, pin) = start_server(store).await;
    let socks = free_tcp_addr();

    tokio::spawn(async move {
        let _ = run_quic_client(
            server,
            "example.test",
            socks,
            [2; 8],
            CertVerification::Pinned(pin),
        )
        .await;
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

// ---------------------------------------------------------------------------
// Test 3b: data cap is enforced on the UPLOAD (UP) direction specifically
// ---------------------------------------------------------------------------

/// Spawn a TCP sink that reads and discards all incoming bytes (never echoes).
/// Returns its "host:port" address string.
async fn spawn_sink() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 4096];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {} // discard
                        }
                    }
                });
            }
        }
    });
    a
}

#[tokio::test]
async fn data_cap_enforced_upload() {
    // Cap is intentionally small so we exhaust it quickly.
    const CAP: u64 = 80 * 1024; // 80 KB
    const CHUNK: usize = 8 * 1024; // 8 KB per write
    const TOTAL: usize = 512 * 1024; // 512 KB >> cap

    // Use a sink so UP bytes are NOT echoed back — this is a pure upload test.
    let sink = spawn_sink().await;
    let store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: [3; 8],
        enabled: true,
        expires_at: None,
        data_cap: Some(CAP),
        rate_up: None,
        rate_down: None,
    }]));
    let (server, pin) = start_server(store).await;
    let socks = free_tcp_addr();

    tokio::spawn(async move {
        let _ = run_quic_client(
            server,
            "example.test",
            socks,
            [3; 8],
            CertVerification::Pinned(pin),
        )
        .await;
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
    assert!(
        ready,
        "SOCKS port never became available for data_cap_upload test"
    );

    // Connect via SOCKS5.
    let mut c = TcpStream::connect(socks).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.unwrap();

    let (h, p) = sink.rsplit_once(':').unwrap();
    let host = h.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&p.parse::<u16>().unwrap().to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "SOCKS CONNECT failed");

    // Push data in small chunks.  After the cap is hit the server will close
    // the QUIC stream, propagating back through the client relay to close our
    // SOCKS TCP.  We detect the cut by watching for a write OR read error.
    //
    // We interleave a small-timeout read after every chunk to detect EOF
    // quickly, without blocking indefinitely.
    let chunk = vec![0xABu8; CHUNK];
    let mut sent = 0usize;
    let mut connection_cut = false;

    'outer: while sent < TOTAL {
        let n = CHUNK.min(TOTAL - sent);
        match tokio::time::timeout(Duration::from_secs(5), c.write_all(&chunk[..n])).await {
            Ok(Ok(_)) => sent += n,
            _ => {
                connection_cut = true;
                break 'outer;
            }
        }
        // After every write, peek to see if the server has closed our end.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(10), c.read(&mut probe)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                connection_cut = true;
                break 'outer;
            }
            _ => {} // timeout or data (shouldn't arrive from sink)
        }
    }

    // If all writes succeeded (no write error), wait a bit for propagation then
    // try a final read — the server must have closed the stream by now.
    if !connection_cut {
        let mut probe = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(3), c.read(&mut probe)).await {
            Ok(Ok(0)) | Ok(Err(_)) => connection_cut = true,
            _ => {}
        }
    }

    assert!(
        connection_cut,
        "upload cap should have closed the connection before all {TOTAL} bytes were accepted \
         (sent {sent} bytes, cap={CAP})"
    );

    println!("data_cap_enforced_upload: sent {sent} bytes before cut (cap={CAP}, total={TOTAL})");
}

// ---------------------------------------------------------------------------
// Test 4: prober GET gets masquerade page
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prober_get_gets_masquerade() {
    let store = Arc::new(InMemoryUserStore::new(vec![])); // no users
    let (server, pin) = start_server(store).await;

    // Wait briefly for the server to start listening.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Raw h3 client: connect, GET "/", expect 200 + body containing "It works".
    let ep = leshiy_quic::endpoint::client_endpoint(CertVerification::Pinned(pin)).unwrap();
    let conn = ep.connect(server, "example.test").unwrap().await.unwrap();
    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri("https://example.test/")
        .body(())
        .unwrap();
    let mut stream = send_req.send_request(req).await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "prober GET / should receive 200 masquerade"
    );

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let c = chunk.chunk();
            body.extend_from_slice(c);
            let n = c.len();
            chunk.advance(n);
        }
    }
    assert!(
        String::from_utf8_lossy(&body).contains("It works"),
        "prober should get the masquerade page, got: {:?}",
        String::from_utf8_lossy(&body)
    );
}

// ---------------------------------------------------------------------------
// Test 5: unauthorized CONNECT does not get a tunnel (gets masquerade, not 200)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthorized_connect_no_tunnel() {
    let store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: [1; 8],
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }]));
    let (server, pin) = start_server(store).await;

    // Wait briefly for the server to start listening.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let ep = leshiy_quic::endpoint::client_endpoint(CertVerification::Pinned(pin)).unwrap();
    let conn = ep.connect(server, "example.test").unwrap().await.unwrap();
    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // CONNECT with a short_id NOT in the store → masquerade, not a tunnel.
    let req = http::Request::builder()
        .method("CONNECT")
        .uri("example.com:80")
        .header("leshiy-auth", hex::encode([9u8; 8]))
        .body(())
        .unwrap();
    let mut stream = send_req.send_request(req).await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_ne!(
        resp.status(),
        200,
        "unauthorized CONNECT must NOT get a 200 tunnel (got {})",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Test 6: wrong cert pin is rejected (no tunnel established)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_pin_rejected() {
    let echo = spawn_echo().await;
    let store = Arc::new(InMemoryUserStore::new(vec![User {
        short_id: [1; 8],
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }]));
    let (server, _pin) = start_server(store).await;
    let socks = free_tcp_addr();
    tokio::spawn(async move {
        let _ = run_quic_client(
            server,
            "example.test",
            socks,
            [1; 8],
            CertVerification::Pinned([0xAB; 32]),
        )
        .await;
    });
    // wrong pin → QUIC handshake fails → SOCKS never tunnels
    let mut client_up = false;
    for _ in 0..15 {
        if tokio::net::TcpStream::connect(socks).await.is_ok() {
            client_up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // client may not even bind SOCKS (connect fails first); either way no tunnel:
    let mut ok = false;
    for _ in 0..10 {
        if socks_connect_echo(socks, &echo, b"x").await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!ok, "wrong cert pin must not tunnel");
    let _ = client_up;
}
