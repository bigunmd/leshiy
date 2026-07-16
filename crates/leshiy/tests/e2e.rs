// End-to-end integration tests for Leshiy.
//
// `end_to_end_socks5_echo`: drives the leshiy_core library paths directly —
// spawns an echo TCP server, a leshiy server (Session::accept + Mux
// Role::Server), and a leshiy client (Session::connect + Mux Role::Client),
// opens a stream through the tunnel, sends bytes, and asserts they come back
// byte-for-byte (with a 5-second timeout).
//
// The two-process binary smoke (server-init / server / client + rustls dest)
// lives in reality_cli_smoke.rs (M1.4b Task 4).

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Spawn an in-process echo server. Returns the bound address as "host:port".
async fn spawn_echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    s.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    });
    addr
}

// ─── Test: core library e2e ───────────────────────────────────────────────────

#[tokio::test]
async fn end_to_end_socks5_echo() {
    let echo = spawn_echo().await;

    // 1. server keypair + listener
    let kp = leshiy_core::handshake::generate_keypair().unwrap();
    let server_pub = kp.public.clone();
    let server_priv = kp.private.clone();
    let srv_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = srv_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (sock, _) = srv_listener.accept().await.unwrap();
        let sess = leshiy_core::session::Session::accept(
            sock,
            &server_priv,
            leshiy_core::handshake::PROTOCOL_MAJOR,
        )
        .await
        .unwrap();
        let (r, w) = sess.into_halves();
        let mut mux = leshiy_core::mux::Mux::start(
            r,
            w,
            leshiy_core::version::Hello::new(1, 1, 0),
            leshiy_core::mux::Role::Server,
        )
        .await
        .unwrap();

        let mut stream = mux.accept().await.unwrap();
        let up = TcpStream::connect(&stream.target).await.unwrap();
        let (mut ur, mut uw) = up.into_split();
        loop {
            tokio::select! {
                i = stream.recv() => match i {
                    Ok(b) => uw.write_all(&b).await.unwrap(),
                    Err(_) => break,
                },
                r = async {
                    let mut b = vec![0u8; 4096];
                    let n = ur.read(&mut b).await.unwrap_or(0);
                    b.truncate(n);
                    b
                } => {
                    if r.is_empty() { break; }
                    stream.send(r.into()).await.unwrap();
                }
            }
        }
    });

    // 2. client session + mux, open a stream to the echo server
    let sock = TcpStream::connect(srv_addr).await.unwrap();
    let ckp = leshiy_core::handshake::generate_keypair().unwrap();
    let sess = leshiy_core::session::Session::connect(
        sock,
        &server_pub,
        &ckp.private,
        leshiy_core::handshake::PROTOCOL_MAJOR,
    )
    .await
    .unwrap();
    let (r, w) = sess.into_halves();
    let mut mux = leshiy_core::mux::Mux::start(
        r,
        w,
        leshiy_core::version::Hello::new(1, 1, 0),
        leshiy_core::mux::Role::Client,
    )
    .await
    .unwrap();

    let mut s = mux.open(&echo).await.unwrap();
    s.send(b"leshiy-roundtrip".to_vec().into()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), s.recv())
        .await
        .expect("timed out waiting for echo")
        .expect("stream closed before echo");
    assert_eq!(got.as_ref(), b"leshiy-roundtrip");
}
