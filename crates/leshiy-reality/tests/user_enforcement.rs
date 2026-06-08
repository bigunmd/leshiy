// Per-user enforcement e2e oracle (M1.5a Task 4).
//
// Tests:
//   `unlimited_user_unchanged`      — regression: no-limits user tunnels SOCKS5→echo.
//   `expired_user_is_relayed_to_dest` — expired user → authorize→None → genuine dest TLS.
//   `data_cap_disconnects`           — user with 100 KB cap; stream cut after cap crossed.
//   `rate_limit_throttles_download`  — user with 200 KB/s rate_down; 1 MB takes ≥ ~3 s.
//
// Harness mirrored from reality_e2e.rs.
use leshiy_reality::client::run_reality_client;
use leshiy_reality::config::{ClientAuthConfig, ServerAuthConfig};
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::server::run_reality_server;
use leshiy_reality::user::{InMemoryUserStore, User};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// ─── shared test keys ────────────────────────────────────────────────────────
const SERVER_SECRET: [u8; 32] = [0x55u8; 32];
const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 0, 0, 0, 0];

fn server_public() -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(SERVER_SECRET)).to_bytes()
}

// ─── test helpers (mirrored from reality_e2e.rs) ─────────────────────────────

/// Spawn a rustls TLS 1.3 dest (self-signed, www.example.com, DEFAULT PQ provider).
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

/// Spawn a plain TCP echo server. Returns "127.0.0.1:<port>".
async fn spawn_echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
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
    addr
}

/// Attempt one SOCKS5 CONNECT → echo payload round-trip. Returns Ok on success.
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
    c.write_all(b"leshiy-user-enforcement-test")
        .await
        .map_err(|e| e.to_string())?;
    let mut got = [0u8; 28];
    c.read_exact(&mut got).await.map_err(|e| e.to_string())?;
    if &got == b"leshiy-user-enforcement-test" {
        Ok(())
    } else {
        Err("echo mismatch".into())
    }
}

/// Build a ServerAuthConfig + cert. `user` controls whether the client is authorized.
/// The server is seeded with a single `User`; the same SHORT_ID is used by the client.
struct Harness {
    socks_addr: String,
    _server: tokio::task::JoinHandle<()>,
    _client: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Spawn a REALITY server with `user` in its store, plus the paired client.
    /// `dest` is the fallback dest address.
    async fn spawn(user: User, dest: String) -> Self {
        let scfg = Arc::new(ServerAuthConfig {
            static_secret: Zeroizing::new(SERVER_SECRET),
            server_names: HashSet::from(["www.example.com".to_string()]),
            short_ids: HashSet::from([SHORT_ID]),
            max_time_diff: Duration::from_secs(120),
            dest,
        });
        let cert = Arc::new(ServerCert::generate());

        let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let saddr = sl.local_addr().unwrap().to_string();

        let store = Arc::new(InMemoryUserStore::new(vec![user]));
        let server = {
            let scfg = scfg.clone();
            let cert = cert.clone();
            let store = store.clone();
            tokio::spawn(async move {
                let _ = run_reality_server(sl, scfg, store, cert).await;
            })
        };

        // Reserve a free port then release it before spawning the client.
        let cl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = cl.local_addr().unwrap().to_string();
        drop(cl);

        let client = {
            let saddr = saddr.clone();
            let socks = socks_addr.clone();
            tokio::spawn(async move {
                let ccfg = ClientAuthConfig {
                    server_public: server_public(),
                    short_id: SHORT_ID,
                    sni: "www.example.com".into(),
                };
                let _ = run_reality_client(&saddr, ccfg, &socks).await;
            })
        };

        Harness {
            socks_addr,
            _server: server,
            _client: client,
        }
    }
}

/// Construct an unlimited `User` (the M1.4a baseline).
fn unlimited_user() -> User {
    User {
        short_id: SHORT_ID,
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: None,
    }
}

// ─── Test 1: unlimited user (regression / harness baseline) ──────────────────

#[tokio::test]
async fn unlimited_user_unchanged() {
    let echo = spawn_echo().await;
    let dest = spawn_rustls_dest().await;
    let h = Harness::spawn(unlimited_user(), dest).await;

    let mut last_err = String::new();
    for _ in 0..50 {
        match try_socks_echo(&h.socks_addr, &echo).await {
            Ok(()) => return,
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("unlimited_user_unchanged failed after retries: {last_err}");
}

// ─── Test 2: expired user → relayed to dest, NOT tunneled ────────────────────

#[tokio::test]
async fn expired_user_is_relayed_to_dest() {
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // expires_at = 1 (epoch + 1s) which is definitely in the past
    let user = User {
        short_id: SHORT_ID,
        enabled: true,
        expires_at: Some(1), // far in the past
        data_cap: None,
        rate_up: None,
        rate_down: None,
    };

    let h = Harness::spawn(user, dest).await;

    // Give client time to start listening.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The client opens a tunnel to the server. The server's authorize returns None
    // (expired user) → bidirectional copy to dest (a real TLS server). The SOCKS5
    // connection to the echo server should fail because the server relays to dest
    // instead of tunneling to echo.
    //
    // Practical assertion: after a bounded number of attempts, SOCKS5→echo never
    // succeeds. We allow ~15 tries with a short sleep each to be robust vs timing.
    // A non-zero success count would mean the enforcement is broken.
    let mut success_count = 0u32;
    for _ in 0..15 {
        if try_socks_echo(&h.socks_addr, &echo).await.is_ok() {
            success_count += 1;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        success_count, 0,
        "expired user should never tunnel through to echo (got {success_count} successes)"
    );
}

// ─── Test 3: data cap disconnects mid-transfer ────────────────────────────────

/// Open a SOCKS5-over-REALITY tunnel to `echo` and send `total_bytes` in chunks,
/// reading the echo back. Returns the total bytes echoed before the connection dropped.
async fn stream_through_echo(
    socks_addr: &str,
    echo: &str,
    total_bytes: usize,
    chunk_size: usize,
) -> usize {
    // SOCKS5 handshake
    let mut c = match TcpStream::connect(socks_addr).await {
        Ok(c) => c,
        Err(_) => return 0,
    };
    c.set_nodelay(true).ok();

    // greeting
    if c.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return 0;
    }
    let mut sel = [0u8; 2];
    if c.read_exact(&mut sel).await.is_err() {
        return 0;
    }

    // CONNECT request (ATYP=domain)
    let (h, p) = echo.rsplit_once(':').unwrap();
    let host = h.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&p.parse::<u16>().unwrap().to_be_bytes());
    if c.write_all(&req).await.is_err() {
        return 0;
    }
    let mut rep = [0u8; 10];
    if c.read_exact(&mut rep).await.is_err() || rep[1] != 0x00 {
        return 0;
    }

    // Stream total_bytes in chunks, counting echoed bytes
    let send_buf: Vec<u8> = (0..chunk_size).map(|i| (i & 0xFF) as u8).collect();
    let mut total_sent = 0usize;
    let mut total_echoed = 0usize;
    let mut recv_buf = vec![0u8; chunk_size];

    // Split the connection so we can write and read independently.
    // We'll use a simple approach: write a chunk, then read it back.
    while total_sent < total_bytes {
        let this_send = chunk_size.min(total_bytes - total_sent);
        match c.write_all(&send_buf[..this_send]).await {
            Ok(()) => total_sent += this_send,
            Err(_) => break,
        }

        // Read the echo back (may get partial on cap-cut)
        let mut echoed = 0usize;
        while echoed < this_send {
            let want = this_send - echoed;
            match tokio::time::timeout(Duration::from_secs(5), c.read(&mut recv_buf[..want])).await
            {
                Ok(Ok(0)) => {
                    // connection closed
                    return total_echoed + echoed;
                }
                Ok(Ok(n)) => echoed += n,
                Ok(Err(_)) | Err(_) => {
                    // timeout or IO error → cap cut
                    return total_echoed + echoed;
                }
            }
        }
        total_echoed += echoed;
    }

    total_echoed
}

#[tokio::test]
async fn data_cap_disconnects() {
    // Cap = 100 KB. The 64 KB flush boundary means the relay reports usage at ~64 KB
    // and checks still_allowed. Cap > 64 KB, so we need to cross the cap threshold.
    // We send 512 KB >> 100 KB cap to ensure we definitely cross the flush boundary.
    //
    // The echo server counts both UP (client→server) and DOWN (server→client) usage,
    // so each echoed byte consumes 2 bytes of cap (sent + received).
    // With cap=100 KB and 2× counting, the relay cuts after ~50 KB of data.
    //
    // Fresh REALITY connection test: after the cap is spent, a second client
    // spawning a NEW REALITY TCP connection will have authorize() return None,
    // getting relayed to dest instead of tunneled.
    const CAP: u64 = 100 * 1024; // 100 KB
    const PAYLOAD: usize = 512 * 1024; // 512 KB >> cap

    let echo = spawn_echo().await;
    let dest = spawn_rustls_dest().await;

    // Share the store between both clients (same user pool, same cap tracking).
    let scfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(SERVER_SECRET),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([SHORT_ID]),
        max_time_diff: Duration::from_secs(120),
        dest: dest.clone(),
    });
    let cert = Arc::new(ServerCert::generate());

    let user = User {
        short_id: SHORT_ID,
        enabled: true,
        expires_at: None,
        data_cap: Some(CAP),
        rate_up: None,
        rate_down: None,
    };

    // Use a shared InMemoryUserStore so cap usage is tracked across clients.
    let store = Arc::new(InMemoryUserStore::new(vec![user]));

    let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let saddr = sl.local_addr().unwrap().to_string();
    {
        let scfg = scfg.clone();
        let cert = cert.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let _ = run_reality_server(sl, scfg, store, cert).await;
        });
    }

    // Spawn first client
    let cl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks1 = cl.local_addr().unwrap().to_string();
    drop(cl);
    {
        let saddr = saddr.clone();
        let socks = socks1.clone();
        tokio::spawn(async move {
            let ccfg = ClientAuthConfig {
                server_public: server_public(),
                short_id: SHORT_ID,
                sni: "www.example.com".into(),
            };
            let _ = run_reality_client(&saddr, ccfg, &socks).await;
        });
    }

    // Wait for first client to be ready
    let mut ready = false;
    for _ in 0..30 {
        if TcpStream::connect(&socks1).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "SOCKS1 port never became available");

    // Stream 512 KB → should be cut mid-way once the cap is reached.
    let echoed = stream_through_echo(&socks1, &echo, PAYLOAD, 8 * 1024).await;

    // The transfer must be cut before all 512 KB are echoed.
    // Since up+down are both counted, effective per-byte cap is ~50 KB echoed.
    // Be generous: assert we get less than full 512 KB (the cut happened).
    assert!(
        echoed < PAYLOAD,
        "data cap should have cut the transfer (echoed {echoed} bytes, payload was {PAYLOAD})"
    );

    println!("data_cap_disconnects: echoed {echoed} bytes (cap={CAP}, payload={PAYLOAD})");

    // Give the relay a moment to flush final usage accounting.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify fresh REALITY connection is refused: spawn a second client that makes a
    // NEW TCP connection to the REALITY server. The server calls authorize() again —
    // over-cap user → None → relayed to dest (real TLS).
    //
    // From the client's perspective: run_reality_client gets a genuine dest TLS session
    // instead of a REALITY tunnel, so its establish_client() fails → the function returns
    // an error BEFORE it binds the SOCKS listener. We use a one-shot tokio task and
    // assert it finishes with an error (doesn't run indefinitely as a real tunnel).
    let cl2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks2 = cl2.local_addr().unwrap().to_string();
    drop(cl2);
    let client2_result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::spawn({
            let saddr = saddr.clone();
            let socks = socks2.clone();
            async move {
                let ccfg = ClientAuthConfig {
                    server_public: server_public(),
                    short_id: SHORT_ID,
                    sni: "www.example.com".into(),
                };
                run_reality_client(&saddr, ccfg, &socks).await
            }
        }),
    )
    .await;

    match client2_result {
        Ok(Ok(inner)) => {
            // inner is Result<(), RealityError>
            // run_reality_client returned - either error (expected) or somehow succeeded
            // If it returned Err → correct behavior (blocked)
            // If it returned Ok → the client somehow stayed up (shouldn't happen since
            //   the SOCKS port was released and SOCKS listener would fail to bind)
            assert!(
                inner.is_err(),
                "over-cap fresh client should get an error (dest relay), not Ok"
            );
        }
        Ok(Err(join_err)) => {
            // Task panicked — treat as failure
            panic!("client2 task panicked: {join_err}");
        }
        Err(_timeout) => {
            // The client didn't return in 10s, meaning it successfully bound the SOCKS port
            // and is now listening — that would only happen if the tunnel worked, which is wrong.
            panic!(
                "over-cap client2 is still running after 10s — this means the tunnel succeeded \
                 when it should have been relayed to dest"
            );
        }
    }
}

// ─── Test 4: rate limit throttles download ────────────────────────────────────

/// Send `total_bytes` through the tunnel using SOCKS5, measure elapsed time.
/// Returns elapsed duration and total bytes echoed.
async fn timed_transfer(socks_addr: &str, echo: &str, total_bytes: usize) -> (Duration, usize) {
    let mut c = match TcpStream::connect(socks_addr).await {
        Ok(c) => c,
        Err(_) => return (Duration::ZERO, 0),
    };
    c.set_nodelay(true).ok();

    // SOCKS5 handshake
    if c.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return (Duration::ZERO, 0);
    }
    let mut sel = [0u8; 2];
    if c.read_exact(&mut sel).await.is_err() {
        return (Duration::ZERO, 0);
    }

    let (h, p) = echo.rsplit_once(':').unwrap();
    let host = h.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&p.parse::<u16>().unwrap().to_be_bytes());
    if c.write_all(&req).await.is_err() {
        return (Duration::ZERO, 0);
    }
    let mut rep = [0u8; 10];
    if c.read_exact(&mut rep).await.is_err() || rep[1] != 0x00 {
        return (Duration::ZERO, 0);
    }

    // Measure the transfer time
    let t0 = Instant::now();
    let chunk_size = 8 * 1024usize;
    let send_buf: Vec<u8> = (0..chunk_size).map(|i| (i & 0xFF) as u8).collect();
    let mut total_sent = 0usize;
    let mut total_echoed = 0usize;
    let mut recv_buf = vec![0u8; chunk_size];

    while total_sent < total_bytes {
        let this_send = chunk_size.min(total_bytes - total_sent);
        match c.write_all(&send_buf[..this_send]).await {
            Ok(()) => total_sent += this_send,
            Err(_) => break,
        }

        let mut echoed = 0usize;
        while echoed < this_send {
            let want = this_send - echoed;
            match tokio::time::timeout(Duration::from_secs(30), c.read(&mut recv_buf[..want])).await
            {
                Ok(Ok(0)) => return (t0.elapsed(), total_echoed + echoed),
                Ok(Ok(n)) => echoed += n,
                Ok(Err(_)) | Err(_) => return (t0.elapsed(), total_echoed + echoed),
            }
        }
        total_echoed += echoed;
    }

    (t0.elapsed(), total_echoed)
}

#[tokio::test]
async fn rate_limit_throttles_download() {
    // Rate: 200 KB/s download. Payload: 1 MB.
    // Theory: 1 MB / 200 KB/s = 5 s.
    // Floor assertion: elapsed ≥ 3 s (40% tolerance below theory).
    // Ceiling: ≤ 30 s (ensures the test doesn't hang).
    //
    // The echo server echoes bytes back to the client, so the "download" path
    // (target→client) is rate-limited. Each echoed byte goes through the DOWN bucket.
    // The upload (client→server) is unlimited (rate_up: None).
    const RATE_DOWN: u32 = 200 * 1024; // 200 KB/s
    const PAYLOAD: usize = 1024 * 1024; // 1 MB
    const FLOOR_SECS: u64 = 3; // 1MB / 200KB/s = 5s, floor at 3s (generous)

    let echo = spawn_echo().await;
    let dest = spawn_rustls_dest().await;

    let throttled_user = User {
        short_id: SHORT_ID,
        enabled: true,
        expires_at: None,
        data_cap: None,
        rate_up: None,
        rate_down: Some(RATE_DOWN),
    };

    let h = Harness::spawn(throttled_user, dest.clone()).await;

    // Wait for socks to be ready
    let mut ready = false;
    for _ in 0..30 {
        if TcpStream::connect(&h.socks_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "throttled SOCKS port never became available");

    let (throttled_elapsed, throttled_echoed) = timed_transfer(&h.socks_addr, &echo, PAYLOAD).await;

    assert_eq!(
        throttled_echoed, PAYLOAD,
        "throttled transfer should complete (echoed {throttled_echoed}/{PAYLOAD})"
    );
    assert!(
        throttled_elapsed >= Duration::from_secs(FLOOR_SECS),
        "throttled transfer should take ≥ {FLOOR_SECS}s (took {throttled_elapsed:.2?})"
    );
    assert!(
        throttled_elapsed <= Duration::from_secs(30),
        "throttled transfer took too long (>{:?}): {throttled_elapsed:.2?}",
        Duration::from_secs(30)
    );

    println!(
        "rate_limit_throttles_download: {throttled_echoed} bytes in {throttled_elapsed:.2?} \
         (rate_down={RATE_DOWN} B/s, theory ~{:.1}s)",
        PAYLOAD as f64 / RATE_DOWN as f64
    );
}
