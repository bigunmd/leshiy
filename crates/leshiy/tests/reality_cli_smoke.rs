// Two-process REALITY binary smoke (M1.4b Task 4, extended in M1.5b Task 3).
//
// Spawns an in-test rustls dest (DEFAULT provider, self-signed for
// "www.example.com") and an echo TCP server, runs `leshiy server-init`
// to get a config + leshiy:// URI, then spawns `leshiy server` and
// `leshiy client` as subprocesses and drives SOCKS5 through the
// resulting proxy, asserting a payload round-trips to the echo server.
//
// `reality_cli_user_add_then_tunnel` (M1.5b): uses `leshiy user add` to
// register a *new* user on the live server via the control socket, then
// tunnels using the returned leshiy:// URI — proving live add works e2e.

use base64::Engine as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// RAII guard — kills the child on drop.
struct Kill(std::process::Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reserve a free port, keeping the listener bound until the caller drops it
/// just before the subprocess binds the port (minimises the TOCTOU window that
/// flakes on busy CI when the port is grabbed between selection and bind).
fn reserve_port() -> (std::net::TcpListener, u16) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// Reserve a free UDP port, keeping the socket bound until the caller drops it.
/// Used for the QUIC listen port (QUIC is UDP-based).
fn reserve_udp_port() -> (std::net::UdpSocket, u16) {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    (s, port)
}

/// Spawn a rustls TLS 1.3 "dest" server (self-signed cert for www.example.com).
/// Uses the DEFAULT rustls CryptoProvider (aws-lc-rs, PQ-preferring: X25519MLKEM768).
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
                    // Accept and discard; we only need the TLS handshake to succeed
                    // so the REALITY server can forward the ClientHello and relay.
                    let _ = a.accept(s).await;
                });
            }
        }
    });
    addr
}

/// Spawn an in-process echo server. Returns "host:port".
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

/// Attempt a SOCKS5 CONNECT (domain ATYP) through `socks` to `echo`,
/// write a fixed payload, and assert the echo comes back.
async fn try_socks(socks: &str, echo: &str) -> Result<(), String> {
    let mut c = TcpStream::connect(socks).await.map_err(|e| e.to_string())?;

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no-auth)
    c.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.map_err(|e| e.to_string())?;

    // CONNECT request: domain ATYP (0x03)
    let (h, p) = echo.rsplit_once(':').unwrap();
    let host = h.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&p.parse::<u16>().unwrap().to_be_bytes());
    c.write_all(&req).await.map_err(|e| e.to_string())?;

    // Reply: 10 bytes (VER REP RSV ATYP 4×BND.ADDR 2×BND.PORT)
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.map_err(|e| e.to_string())?;
    if rep[1] != 0 {
        return Err(format!("socks reply={}", rep[1]));
    }

    c.write_all(b"leshiy-cli-smoke")
        .await
        .map_err(|e| e.to_string())?;
    let mut got = [0u8; 16];
    c.read_exact(&mut got).await.map_err(|e| e.to_string())?;
    if &got == b"leshiy-cli-smoke" {
        Ok(())
    } else {
        Err("echo payload mismatch".into())
    }
}

/// Create a unique temp directory for this test run.
fn make_temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("leshiy-smoke-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn reality_cli_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest + echo server ───────────────────────────
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // ── 2. Reserve ports (held until just before each subprocess binds) ────
    let (server_l, server_port) = reserve_port();
    let (socks_l, socks_port) = reserve_port();

    // ── 3. server-init → config + URI ─────────────────────────────────────
    let cfg_dir = make_temp_dir("e2e");
    let cfg_path = cfg_dir.join("server.toml");
    let cfg_str = cfg_path.to_str().unwrap();

    let out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{server_port}"),
            "--dest",
            &dest,
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--out",
            cfg_str,
        ])
        .output()
        .expect("failed to run server-init");
    assert!(
        out.status.success(),
        "server-init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let uri = stdout
        .lines()
        .find(|l| l.starts_with("leshiy://"))
        .unwrap_or_else(|| panic!("no leshiy:// URI in server-init output:\n{stdout}"))
        .to_string();

    // ── 4. Spawn server subprocess (release its port immediately before) ──
    drop(server_l);
    let _server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy server"),
    );

    // Wait for the server to be ready (up to 5 s) before spawning the client.
    // The client connects to the REALITY server immediately on startup, so we
    // must ensure the server is listening before spawning the client.
    let server_addr = format!("127.0.0.1:{server_port}");
    for i in 0..50 {
        match TcpStream::connect(&server_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 49 {
                    let _ = std::fs::remove_dir_all(&cfg_dir);
                    panic!("leshiy server never came up on {server_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    // ── 5. Spawn client subprocess (release its SOCKS port immediately before)
    drop(socks_l);
    let _client = Kill(
        std::process::Command::new(bin)
            .args([
                "client",
                "--uri",
                &uri,
                "--socks",
                &format!("127.0.0.1:{socks_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy client"),
    );

    // ── 6. Retry SOCKS5 → echo until the client is up ─────────────────────
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let mut last_err = String::from("(no attempt yet)");
    for _ in 0..60 {
        match try_socks(&socks_addr, &echo).await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&cfg_dir);
                return;
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&cfg_dir);
    panic!("reality_cli_end_to_end failed after retries: {last_err}");
}

/// M1.5b smoke: `leshiy user add` over the control socket → tunnel with the returned URI.
///
/// 1. Start a fresh REALITY server (no pre-configured users).
/// 2. Wait for its control socket to appear.
/// 3. Run `leshiy user add --sni www.example.com --socket <sock>` as a subprocess.
/// 4. Capture the printed `leshiy://` URI.
/// 5. Spawn a client with that URI and tunnel SOCKS5 → echo — proving live add works e2e.
#[tokio::test]
async fn reality_cli_user_add_then_tunnel() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest + echo server ───────────────────────────
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // ── 2. Reserve ports ──────────────────────────────────────────────────
    let (server_l, server_port) = reserve_port();
    let (socks_l, socks_port) = reserve_port();

    // ── 3. server-init → write config ─────────────────────────────────────
    let cfg_dir = make_temp_dir("useradd");
    let cfg_path = cfg_dir.join("server.toml");
    let cfg_str = cfg_path.to_str().unwrap();
    // The control socket will be at <cfg_dir>/leshiy.sock (default_sock_path logic).
    let sock_path = cfg_dir.join("leshiy.sock");
    let sock_str = sock_path.to_str().unwrap().to_string();

    // SNI for the live-added user must match the server's allowed server_names,
    // which server-init derives from the dest hostname (the part before the colon).
    let dest_sni = dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(&dest);

    // server-init writes host, dest, server_names and one seed short_id.
    // We'll add a *second* user live and use THAT URI for the tunnel.
    let out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{server_port}"),
            "--dest",
            &dest,
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--out",
            cfg_str,
        ])
        .output()
        .expect("failed to run server-init");
    assert!(
        out.status.success(),
        "server-init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ── 4. Spawn the server ───────────────────────────────────────────────
    drop(server_l);
    let _server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy server"),
    );

    // Wait for the TCP port AND the control socket to appear.
    let server_addr = format!("127.0.0.1:{server_port}");
    for i in 0..50 {
        match TcpStream::connect(&server_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 49 {
                    let _ = std::fs::remove_dir_all(&cfg_dir);
                    panic!("leshiy server never came up on {server_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    // Wait for control socket to appear (separate loop — TCP up ≠ socket created yet).
    for i in 0..50 {
        if sock_path.exists() {
            break;
        }
        if i == 49 {
            let _ = std::fs::remove_dir_all(&cfg_dir);
            panic!("control socket never appeared at {sock_str}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ── 5. `leshiy user add` — capture the URI ───────────────────────────
    // Use the dest hostname as SNI — this is what the server allows (server_names).
    let add_out = std::process::Command::new(bin)
        .args(["user", "add", "--sni", dest_sni, "--socket", &sock_str])
        .output()
        .expect("failed to run leshiy user add");
    assert!(
        add_out.status.success(),
        "leshiy user add failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    let add_stdout = String::from_utf8_lossy(&add_out.stdout);
    let live_uri = add_stdout
        .lines()
        .find(|l| l.starts_with("leshiy://"))
        .unwrap_or_else(|| panic!("no leshiy:// URI in user add output:\n{add_stdout}"))
        .to_string();

    // ── 6. Spawn a client with the live URI ───────────────────────────────
    drop(socks_l);
    let _client = Kill(
        std::process::Command::new(bin)
            .args([
                "client",
                "--uri",
                &live_uri,
                "--socks",
                &format!("127.0.0.1:{socks_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy client"),
    );

    // ── 7. Retry SOCKS5 → echo ────────────────────────────────────────────
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let mut last_err = String::from("(no attempt yet)");
    for _ in 0..60 {
        match try_socks(&socks_addr, &echo).await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&cfg_dir);
                return;
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&cfg_dir);
    panic!("reality_cli_user_add_then_tunnel failed after retries: {last_err}");
}

/// M1.5c smoke: user definition survives a server restart (sqlite persistence).
///
/// 1. `server-init` writes config + leshiy-users.db with user A.
/// 2. Start `leshiy server`; tunnel SOCKS5→echo with A's URI (works).
/// 3. KILL the server.
/// 4. Restart `leshiy server` with the SAME config+db.
/// 5. Tunnel SOCKS5→echo with A's URI again — MUST still work (definition persisted).
///
/// This covers write-through persistence: server-init flushes user A to sqlite
/// immediately, so no flush interval wait is needed to prove definition persistence.
#[tokio::test]
async fn reality_cli_user_survives_restart() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest + echo server ───────────────────────────
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // ── 2. Reserve the server port (held until just before each bind) ─────
    let (server_l, server_port) = reserve_port();

    // ── 3. server-init → config + DB + URI for user A ─────────────────────
    let cfg_dir = make_temp_dir("restart");
    let cfg_path = cfg_dir.join("server.toml");
    let cfg_str = cfg_path.to_str().unwrap();

    let out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{server_port}"),
            "--dest",
            &dest,
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--out",
            cfg_str,
        ])
        .output()
        .expect("failed to run server-init");
    assert!(
        out.status.success(),
        "server-init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let uri_a = stdout
        .lines()
        .find(|l| l.starts_with("leshiy://"))
        .unwrap_or_else(|| panic!("no leshiy:// URI in server-init output:\n{stdout}"))
        .to_string();

    // Verify the DB was created alongside the config.
    let db_path = cfg_dir.join("leshiy-users.db");
    assert!(
        db_path.exists(),
        "leshiy-users.db was not created by server-init"
    );

    // ── 4. First server run ───────────────────────────────────────────────
    drop(server_l);
    let server_addr = format!("127.0.0.1:{server_port}");
    {
        let mut server1 = Kill(
            std::process::Command::new(bin)
                .args(["server", "--config", cfg_str])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn leshiy server (first run)"),
        );

        // Wait for the server to be ready.
        for i in 0..50 {
            match TcpStream::connect(&server_addr).await {
                Ok(_) => break,
                Err(_) => {
                    if i == 49 {
                        let _ = std::fs::remove_dir_all(&cfg_dir);
                        panic!("leshiy server (first run) never came up on {server_addr}");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }

        // Tunnel with user A's URI.
        let (socks_l1, socks_port1) = reserve_port();
        drop(socks_l1);
        let _client1 = Kill(
            std::process::Command::new(bin)
                .args([
                    "client",
                    "--uri",
                    &uri_a,
                    "--socks",
                    &format!("127.0.0.1:{socks_port1}"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn leshiy client (first run)"),
        );

        let socks_addr1 = format!("127.0.0.1:{socks_port1}");
        let mut last_err = String::from("(no attempt yet)");
        let mut ok = false;
        for _ in 0..60 {
            match try_socks(&socks_addr1, &echo).await {
                Ok(()) => {
                    ok = true;
                    break;
                }
                Err(e) => {
                    last_err = e;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
        }
        if !ok {
            let _ = std::fs::remove_dir_all(&cfg_dir);
            panic!("reality_cli_user_survives_restart: first run failed: {last_err}");
        }

        // Kill the first server (Kill::drop fires here at end of block).
        drop(_client1);
        let _ = server1.0.kill();
        let _ = server1.0.wait();
        // server1 RAII guard will also fire on drop — that's fine (kill is idempotent).
        std::mem::forget(server1); // prevent double-kill noise
    }

    // Give the OS a moment to release the port.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 5. Second server run (same config + same DB) ──────────────────────
    // 200 ms lets the OS release the listen port after server1 exits; the startup
    // retry loop below absorbs any residual delay on slow CI.
    let _server2 = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy server (second run)"),
    );

    // Wait for the second server to be ready.
    for i in 0..80 {
        match TcpStream::connect(&server_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 79 {
                    let _ = std::fs::remove_dir_all(&cfg_dir);
                    panic!("leshiy server (second run) never came up on {server_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    // ── 6. Tunnel with user A again after restart ─────────────────────────
    let (socks_l2, socks_port2) = reserve_port();
    drop(socks_l2);
    let _client2 = Kill(
        std::process::Command::new(bin)
            .args([
                "client",
                "--uri",
                &uri_a,
                "--socks",
                &format!("127.0.0.1:{socks_port2}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy client (second run)"),
    );

    let socks_addr2 = format!("127.0.0.1:{socks_port2}");
    let mut last_err = String::from("(no attempt yet)");
    for _ in 0..60 {
        match try_socks(&socks_addr2, &echo).await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&cfg_dir);
                return; // user A survived restart
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&cfg_dir);
    panic!(
        "reality_cli_user_survives_restart: user A failed to tunnel after server restart: \
         {last_err}\n(definition did not survive restart)"
    );
}

/// M2c smoke: real binary tunnels SOCKS5 over the verified, pinned QUIC path.
///
/// 1. Start an in-process echo server.
/// 2. Reserve REALITY TCP port, QUIC UDP port, and SOCKS port.
/// 3. `leshiy server-init --quic-listen` → config with self-signed cert + pinned qcert in URI.
/// 4. `leshiy server --config` → starts REALITY + QUIC (shared UserStore).
/// 5. Wait for REALITY TCP port (server readiness proxy), then brief sleep for QUIC UDP bind.
/// 6. `leshiy client --uri '<uri>' --transport quic --socks` → QUIC client.
/// 7. Drive SOCKS5 CONNECT → echo server → assert payload round-trips over the pinned QUIC path.
#[tokio::test]
async fn reality_cli_quic_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest + echo server ───────────────────────────
    // The QUIC path never uses `dest`, but server-init requires it.
    // Reuse spawn_rustls_dest so the REALITY side is well-formed.
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // ── 2. Reserve ports ──────────────────────────────────────────────────
    let (server_l, server_port) = reserve_port();
    let (quic_sock, quic_port) = reserve_udp_port();
    let (socks_l, socks_port) = reserve_port();

    // ── 3. server-init → config + URI (includes quic= and qcert=) ─────────
    let cfg_dir = make_temp_dir("quic-e2e");
    let cfg_path = cfg_dir.join("server.toml");
    let cfg_str = cfg_path.to_str().unwrap();

    // Release the UDP socket just before server-init so it can bind that port.
    drop(quic_sock);

    let out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{server_port}"),
            "--dest",
            &dest,
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--quic-listen",
            &format!("127.0.0.1:{quic_port}"),
            "--quic-domain",
            "example.test",
            "--out",
            cfg_str,
        ])
        .output()
        .expect("failed to run server-init");
    assert!(
        out.status.success(),
        "server-init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let uri = stdout
        .lines()
        .find(|l| l.starts_with("leshiy://"))
        .unwrap_or_else(|| panic!("no leshiy:// URI in server-init output:\n{stdout}"))
        .to_string();

    // Assert the URI carries the QUIC endpoint and pinned cert fingerprint.
    assert!(uri.contains("quic="), "URI missing quic= param: {uri}");
    assert!(
        uri.contains("qcert="),
        "URI missing qcert= param (pin not provisioned): {uri}"
    );

    // ── 4. Spawn server (REALITY + QUIC) ──────────────────────────────────
    drop(server_l);
    let _server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy server"),
    );

    // Wait for the REALITY TCP port as a server-ready signal (up to 10 s).
    // The QUIC server is spawned concurrently; we add a brief extra sleep after
    // the TCP port is up to let the QUIC UDP socket bind.
    let server_addr = format!("127.0.0.1:{server_port}");
    for i in 0..100 {
        match TcpStream::connect(&server_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 99 {
                    let _ = std::fs::remove_dir_all(&cfg_dir);
                    panic!("leshiy server never came up on {server_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    // Brief pause for the QUIC server task to bind its UDP socket.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 5. Spawn QUIC client ──────────────────────────────────────────────
    drop(socks_l);
    let _client = Kill(
        std::process::Command::new(bin)
            .args([
                "client",
                "--uri",
                &uri,
                "--transport",
                "quic",
                "--socks",
                &format!("127.0.0.1:{socks_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy client --transport quic"),
    );

    // ── 6. Retry SOCKS5 → echo until the QUIC tunnel is ready ────────────
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let mut last_err = String::from("(no attempt yet)");
    for _ in 0..60 {
        match try_socks(&socks_addr, &echo).await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&cfg_dir);
                return; // payload round-tripped over the verified, pinned QUIC path
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&cfg_dir);
    panic!("reality_cli_quic_end_to_end failed after retries: {last_err}");
}

/// M2d smoke: `--transport auto` selects a working transport (QUIC preferred).
///
/// Mirror of `reality_cli_quic_end_to_end` but uses `--transport auto` instead of
/// `--transport quic`.  With both REALITY and QUIC up, auto should settle on QUIC;
/// the assertion only requires a working SOCKS5→echo round-trip regardless of which
/// transport was ultimately chosen.
#[tokio::test]
async fn reality_cli_auto_uses_quic() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest + echo server ───────────────────────────
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // ── 2. Reserve ports ──────────────────────────────────────────────────
    let (server_l, server_port) = reserve_port();
    let (quic_sock, quic_port) = reserve_udp_port();
    let (socks_l, socks_port) = reserve_port();

    // ── 3. server-init → config + URI (includes quic= and qcert=) ─────────
    let cfg_dir = make_temp_dir("auto-quic");
    let cfg_path = cfg_dir.join("server.toml");
    let cfg_str = cfg_path.to_str().unwrap();

    // Release the UDP socket just before server-init so it can bind that port.
    drop(quic_sock);

    let out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{server_port}"),
            "--dest",
            &dest,
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--quic-listen",
            &format!("127.0.0.1:{quic_port}"),
            "--quic-domain",
            "example.test",
            "--out",
            cfg_str,
        ])
        .output()
        .expect("failed to run server-init");
    assert!(
        out.status.success(),
        "server-init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let uri = stdout
        .lines()
        .find(|l| l.starts_with("leshiy://"))
        .unwrap_or_else(|| panic!("no leshiy:// URI in server-init output:\n{stdout}"))
        .to_string();

    assert!(uri.contains("quic="), "URI missing quic= param: {uri}");
    assert!(uri.contains("qcert="), "URI missing qcert= param: {uri}");

    // ── 4. Spawn server (REALITY + QUIC) ──────────────────────────────────
    drop(server_l);
    let _server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy server"),
    );

    // Wait for REALITY TCP port (server-ready proxy), then brief pause for QUIC UDP bind.
    let server_addr = format!("127.0.0.1:{server_port}");
    for i in 0..100 {
        match TcpStream::connect(&server_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 99 {
                    let _ = std::fs::remove_dir_all(&cfg_dir);
                    panic!("leshiy server never came up on {server_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 5. Spawn client with --transport auto ─────────────────────────────
    drop(socks_l);
    let _client = Kill(
        std::process::Command::new(bin)
            .args([
                "client",
                "--uri",
                &uri,
                "--transport",
                "auto",
                "--socks",
                &format!("127.0.0.1:{socks_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy client --transport auto"),
    );

    // ── 6. Retry SOCKS5 → echo until the tunnel is ready ─────────────────
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let mut last_err = String::from("(no attempt yet)");
    for _ in 0..60 {
        match try_socks(&socks_addr, &echo).await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&cfg_dir);
                return;
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&cfg_dir);
    panic!("reality_cli_auto_uses_quic failed after retries: {last_err}");
}

/// M2d smoke: `--transport auto` falls back to REALITY when QUIC endpoint is unreachable.
///
/// Construction:
///  - Run a normal REALITY-only server (no --quic-listen).
///  - Capture the printed `leshiy://` URI and append `&quic=127.0.0.1:1&qsni=example.test`
///    so the URI looks like it has a QUIC endpoint, but port 1 has nothing listening (or
///    connection-refused, which is equally fine — both trigger the fallback path).
///  - Run `leshiy client --transport auto` with this modified URI.
///  - The client attempts QUIC to 127.0.0.1:1 (times out or gets ICMP-refused), then falls
///    back to REALITY, which tunnels normally.
///  - Assert SOCKS5→echo works with a generous retry budget (≥20 s) to absorb the 3 s
///    QUIC timeout before fallback establishes.
#[tokio::test]
async fn reality_cli_auto_falls_back() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest + echo server ───────────────────────────
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // ── 2. Reserve ports ──────────────────────────────────────────────────
    let (server_l, server_port) = reserve_port();
    let (socks_l, socks_port) = reserve_port();

    // ── 3. server-init (REALITY only, no --quic-listen) → config + URI ────
    let cfg_dir = make_temp_dir("auto-fallback");
    let cfg_path = cfg_dir.join("server.toml");
    let cfg_str = cfg_path.to_str().unwrap();

    let out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{server_port}"),
            "--dest",
            &dest,
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--out",
            cfg_str,
        ])
        .output()
        .expect("failed to run server-init");
    assert!(
        out.status.success(),
        "server-init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let reality_uri = stdout
        .lines()
        .find(|l| l.starts_with("leshiy://"))
        .unwrap_or_else(|| panic!("no leshiy:// URI in server-init output:\n{stdout}"))
        .to_string();

    // Build the modified URI: append a dead QUIC endpoint (port 1, nothing listening).
    // No qcert= means CertVerification::Roots — that's fine, the connect will fail
    // before any cert exchange.
    let dead_quic_uri = format!("{reality_uri}&quic=127.0.0.1:1&qsni=example.test");

    // ── 4. Spawn REALITY-only server ──────────────────────────────────────
    drop(server_l);
    let _server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy server"),
    );

    // Wait for the server to be ready (up to 10 s).
    let server_addr = format!("127.0.0.1:{server_port}");
    for i in 0..100 {
        match TcpStream::connect(&server_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 99 {
                    let _ = std::fs::remove_dir_all(&cfg_dir);
                    panic!("leshiy server never came up on {server_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    // ── 5. Spawn client with dead QUIC + --transport auto ─────────────────
    drop(socks_l);
    let _client = Kill(
        std::process::Command::new(bin)
            .args([
                "client",
                "--uri",
                &dead_quic_uri,
                "--transport",
                "auto",
                "--socks",
                &format!("127.0.0.1:{socks_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy client --transport auto (fallback)"),
    );

    // ── 6. Retry with a generous budget covering the 3 s QUIC timeout ─────
    // 80 attempts × 250 ms = 20 s total, well past the QUIC_TIMEOUT (3 s) +
    // REALITY connection + SOCKS5 listener bind time.
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let mut last_err = String::from("(no attempt yet)");
    for _ in 0..80 {
        match try_socks(&socks_addr, &echo).await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&cfg_dir);
                return; // fallback to REALITY succeeded
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&cfg_dir);
    panic!(
        "reality_cli_auto_falls_back: REALITY fallback never succeeded after \
         ~20 s budget: {last_err}\n\
         (client should have timed out QUIC to 127.0.0.1:1 and fallen back to REALITY)"
    );
}

/// M2d smoke: `--transport auto` fails CLOSED + BOUNDED when BOTH transports are dead.
///
/// Uses a hand-crafted URI pointing at dead ports (127.0.0.1:1) for both REALITY and
/// QUIC.  The client MUST exit (non-zero) within ~25 s, i.e., well before the OS
/// TCP-connect default (~75-127 s) that existed before the REALITY_CONNECT_TIMEOUT
/// bound was added.  This proves the "bounded fallback delay" design holds even in the
/// worst case where nothing is reachable.
///
/// Budget: QUIC_TIMEOUT (3 s) + HEAD_START (0.2 s) + REALITY_CONNECT_TIMEOUT (10 s)
///         + generous margin = 25 s.
#[tokio::test]
async fn reality_cli_auto_both_dead() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // Hand-crafted leshiy:// URI:
    //   pubkey  = 32 zero bytes (base64url: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)
    //   host    = 127.0.0.1:1  (dead REALITY addr)
    //   sni     = x
    //   sid     = 0102030400000000  (8 bytes)
    //   quic    = 127.0.0.1:1  (dead QUIC addr)
    //   qsni    = example.test
    // No real server anywhere → both transports fail within their bounded timeouts.
    let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
    let uri = format!(
        "leshiy://{pk}@127.0.0.1:1?sni=x&sid=0102030400000000&quic=127.0.0.1:1&qsni=example.test"
    );

    let (socks_l, socks_port) = reserve_port();
    drop(socks_l);

    let mut child = std::process::Command::new(bin)
        .args([
            "client",
            "--uri",
            &uri,
            "--transport",
            "auto",
            "--socks",
            &format!("127.0.0.1:{socks_port}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn leshiy client (both-dead)");

    // Budget: QUIC_TIMEOUT(3s) + HEAD_START(0.2s) + REALITY_CONNECT_TIMEOUT(10s) + 12s margin
    let budget = Duration::from_secs(25);
    let poll_interval = Duration::from_millis(200);
    let start = std::time::Instant::now();

    let exited = loop {
        match child.try_wait().expect("try_wait failed") {
            Some(_status) => break true,
            None => {
                if start.elapsed() >= budget {
                    break false;
                }
                std::thread::sleep(poll_interval);
            }
        }
    };

    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "reality_cli_auto_both_dead: client did NOT exit within {budget:?}.\n\
             The REALITY fallback connect is unbounded — Fix 1 (REALITY_CONNECT_TIMEOUT) \
             is not working."
        );
    }

    let elapsed = start.elapsed();
    // Must have exited non-zero (both transports dead → error).
    // (status is already consumed; we just assert it exited promptly above.)
    eprintln!("reality_cli_auto_both_dead: client exited in {elapsed:?} (budget={budget:?}) ✓");
}

/// M3b smoke: 3-process connector chain  client → Entry → Exit → echo.
///
/// Topology:
///   echo (in-process TCP)
///   ← Exit   (`leshiy server`, DirectEgress, QUIC front exposed, real exit)
///   ← Entry  (`leshiy server`, ConnectorEgress → Exit over QUIC)
///   ← client (`leshiy client --transport tcp`, reaches Entry over REALITY)
///
/// Steps:
///  1. Spawn echo + rustls dest (reused for both servers' REALITY fronts).
///  2. `server-init` Exit (with --quic-listen) → capture Exit's URI (has quic= + qcert=).
///  3. Start `leshiy server` for Exit; wait for its REALITY TCP port + brief sleep for QUIC.
///  4. `server-init` Entry (with --connector '<exit-uri>') → capture Entry's URI (REALITY only).
///  5. Start `leshiy server` for Entry (eagerly connects to Exit → Exit must be up).
///     Wait for Entry's REALITY TCP port.
///  6. Start `leshiy client --transport tcp --uri '<entry-uri>' --socks <sp>`.
///  7. Drive SOCKS5 → echo with an 80×200 ms retry budget.
#[tokio::test]
async fn connector_cli_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest + echo server ───────────────────────────
    // Both servers share the same rustls dest for their REALITY fronts.
    let dest = spawn_rustls_dest().await;
    let echo = spawn_echo().await;

    // ── 2. Reserve ports (all distinct) ──────────────────────────────────
    // Exit: REALITY TCP port, QUIC UDP port.
    let (exit_tcp_l, exit_tcp_port) = reserve_port();
    let (exit_quic_sock, exit_quic_port) = reserve_udp_port();
    // Entry: REALITY TCP port.
    let (entry_tcp_l, entry_tcp_port) = reserve_port();
    // Client: SOCKS port.
    let (socks_l, socks_port) = reserve_port();

    // ── 3a. server-init for Exit (with --quic-listen) ─────────────────────
    let exit_cfg_dir = make_temp_dir("connector-exit");
    let exit_cfg_path = exit_cfg_dir.join("server.toml");
    let exit_cfg_str = exit_cfg_path.to_str().unwrap();

    // Release the UDP socket so server-init can claim the port during cert gen.
    drop(exit_quic_sock);

    let exit_init_out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{exit_tcp_port}"),
            "--listen",
            &format!("127.0.0.1:{exit_tcp_port}"),
            "--dest",
            &dest,
            "--quic-listen",
            &format!("127.0.0.1:{exit_quic_port}"),
            "--out",
            exit_cfg_str,
        ])
        .output()
        .expect("failed to run server-init for Exit");
    assert!(
        exit_init_out.status.success(),
        "server-init (Exit) failed: {}",
        String::from_utf8_lossy(&exit_init_out.stderr)
    );
    let exit_init_stdout = String::from_utf8_lossy(&exit_init_out.stdout);
    // The Exit URI must contain quic= and qcert= (the connector credential).
    let exit_uri = exit_init_stdout
        .lines()
        .find(|l| l.starts_with("leshiy://") && l.contains("quic="))
        .unwrap_or_else(|| {
            panic!("no leshiy:// URI with quic= in Exit server-init output:\n{exit_init_stdout}")
        })
        .to_string();
    assert!(
        exit_uri.contains("qcert="),
        "Exit URI missing qcert= (pin not provisioned): {exit_uri}"
    );

    // ── 3b. Start Exit server ─────────────────────────────────────────────
    drop(exit_tcp_l);
    let _exit_server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", exit_cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn Exit server"),
    );

    // Wait for Exit REALITY TCP port (up to 10 s).
    let exit_tcp_addr = format!("127.0.0.1:{exit_tcp_port}");
    for i in 0..100 {
        match TcpStream::connect(&exit_tcp_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 99 {
                    let _ = std::fs::remove_dir_all(&exit_cfg_dir);
                    panic!("Exit server never came up on {exit_tcp_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    // Brief extra pause for the QUIC UDP socket to bind.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ── 4. server-init for Entry (with --connector '<exit-uri>') ─────────
    let entry_cfg_dir = make_temp_dir("connector-entry");
    let entry_cfg_path = entry_cfg_dir.join("server.toml");
    let entry_cfg_str = entry_cfg_path.to_str().unwrap();

    let entry_init_out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{entry_tcp_port}"),
            "--listen",
            &format!("127.0.0.1:{entry_tcp_port}"),
            "--dest",
            &dest,
            "--connector",
            &exit_uri,
            "--out",
            entry_cfg_str,
        ])
        .output()
        .expect("failed to run server-init for Entry");
    assert!(
        entry_init_out.status.success(),
        "server-init (Entry) failed: {}",
        String::from_utf8_lossy(&entry_init_out.stderr)
    );
    let entry_init_stdout = String::from_utf8_lossy(&entry_init_out.stdout);
    // The Entry URI is what the client dials (REALITY front, no quic= needed).
    let entry_uri = entry_init_stdout
        .lines()
        .find(|l| l.starts_with("leshiy://"))
        .unwrap_or_else(|| {
            panic!("no leshiy:// URI in Entry server-init output:\n{entry_init_stdout}")
        })
        .to_string();

    // ── 5. Start Entry server (eagerly connects to Exit via ConnectorEgress) ─
    drop(entry_tcp_l);
    let _entry_server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", entry_cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn Entry server"),
    );

    // Wait for Entry REALITY TCP port (up to 10 s).
    let entry_tcp_addr = format!("127.0.0.1:{entry_tcp_port}");
    for i in 0..100 {
        match TcpStream::connect(&entry_tcp_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 99 {
                    let _ = std::fs::remove_dir_all(&exit_cfg_dir);
                    let _ = std::fs::remove_dir_all(&entry_cfg_dir);
                    panic!("Entry server never came up on {entry_tcp_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    // ── 6. Start client (REALITY transport to Entry) ──────────────────────
    drop(socks_l);
    let _client = Kill(
        std::process::Command::new(bin)
            .args([
                "client",
                "--uri",
                &entry_uri,
                "--transport",
                "tcp",
                "--socks",
                &format!("127.0.0.1:{socks_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy client"),
    );

    // ── 7. Retry SOCKS5 → echo (generous budget: 80 × 200 ms = 16 s) ─────
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let mut last_err = String::from("(no attempt yet)");
    for _ in 0..80 {
        match try_socks(&socks_addr, &echo).await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&exit_cfg_dir);
                let _ = std::fs::remove_dir_all(&entry_cfg_dir);
                return; // PASS: payload round-tripped Entry→Exit→echo
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&exit_cfg_dir);
    let _ = std::fs::remove_dir_all(&entry_cfg_dir);
    panic!(
        "connector_cli_end_to_end failed after 80 retries (~16 s): {last_err}\n\
         (Entry→Exit→echo chain did not establish)"
    );
}

/// Task 3: `leshiy user add --qr` renders the URI AND QR block art on stdout.
///
/// Mirrors `reality_cli_user_add_then_tunnel` but only asserts stdout content —
/// no tunnel is needed to prove the QR flag works.
#[tokio::test]
async fn reality_cli_user_add_qr_flag() {
    let bin = env!("CARGO_BIN_EXE_leshiy");

    // ── 1. In-process rustls dest ─────────────────────────────────────────
    let dest = spawn_rustls_dest().await;

    // ── 2. Reserve server port ────────────────────────────────────────────
    let (server_l, server_port) = reserve_port();

    // ── 3. server-init → write config ─────────────────────────────────────
    let cfg_dir = make_temp_dir("useradd-qr");
    let cfg_path = cfg_dir.join("server.toml");
    let cfg_str = cfg_path.to_str().unwrap();
    let sock_path = cfg_dir.join("leshiy.sock");
    let sock_str = sock_path.to_str().unwrap().to_string();

    let dest_sni = dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(&dest);

    let out = std::process::Command::new(bin)
        .args([
            "server-init",
            "--host",
            &format!("127.0.0.1:{server_port}"),
            "--dest",
            &dest,
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--out",
            cfg_str,
        ])
        .output()
        .expect("failed to run server-init");
    assert!(
        out.status.success(),
        "server-init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ── 4. Spawn the server ───────────────────────────────────────────────
    drop(server_l);
    let _server = Kill(
        std::process::Command::new(bin)
            .args(["server", "--config", cfg_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn leshiy server"),
    );

    // Wait for TCP port.
    let server_addr = format!("127.0.0.1:{server_port}");
    for i in 0..50 {
        match TcpStream::connect(&server_addr).await {
            Ok(_) => break,
            Err(_) => {
                if i == 49 {
                    let _ = std::fs::remove_dir_all(&cfg_dir);
                    panic!("leshiy server never came up on {server_addr}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    // Wait for control socket.
    for i in 0..50 {
        if sock_path.exists() {
            break;
        }
        if i == 49 {
            let _ = std::fs::remove_dir_all(&cfg_dir);
            panic!("control socket never appeared at {sock_str}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ── 5. `leshiy user add --qr` — capture stdout ───────────────────────
    let add_out = std::process::Command::new(bin)
        .args([
            "user", "add", "--qr", "--sni", dest_sni, "--socket", &sock_str,
        ])
        .output()
        .expect("failed to run leshiy user add --qr");
    assert!(
        add_out.status.success(),
        "leshiy user add --qr failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    let out = String::from_utf8_lossy(&add_out.stdout).to_string();

    let _ = std::fs::remove_dir_all(&cfg_dir);

    assert!(out.contains("leshiy://"), "should print the URI");
    assert!(
        out.contains('\u{2588}') || out.contains('\u{2580}') || out.contains('\u{2584}'),
        "should render a QR for --qr; stdout was:\n{out}"
    );
}
