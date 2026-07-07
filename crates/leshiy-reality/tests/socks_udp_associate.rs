//! End-to-end SOCKS5 UDP ASSOCIATE: a local UDP app → SOCKS5 UDP relay → authed REALITY tunnel →
//! server UDP egress → UDP echo, and back. Proves the local UDP frontend exposes the (already
//! tested) mux datagram tunnel to real UDP clients.
use leshiy_reality::client::{RealityConn, connect_reality, serve_socks5};
use leshiy_reality::config::{ClientAuthConfig, ServerAuthConfig};
use leshiy_reality::egress::DirectEgress;
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::server::run_reality_server;
use leshiy_reality::user::InMemoryUserStore;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Spawn a UDP echo server. Returns its "127.0.0.1:<port>".
async fn spawn_udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
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

/// Build a SOCKS5 UDP request datagram: RSV(2)=0, FRAG(1)=0, ATYP=IPv4, DST.ADDR, DST.PORT, DATA.
fn socks_udp_request(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8, 0, 0, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(v4) => pkt.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => panic!("test uses v4"),
    }
    pkt.extend_from_slice(&target.port().to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

#[tokio::test]
async fn socks5_udp_associate_echo() {
    let echo = spawn_udp_echo().await;

    // Stand up an authed REALITY server with a DirectEgress that allows loopback (echo is local).
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
        match try_once(&saddr, server_public, echo).await {
            Ok(()) => return,
            Err(e) => {
                last = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("socks5 udp associate echo failed after retries: {last}");
}

async fn try_once(saddr: &str, server_public: [u8; 32], echo: SocketAddr) -> Result<(), String> {
    let ccfg = ClientAuthConfig {
        server_public,
        short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        sni: "www.example.com".into(),
    };
    let conn: RealityConn = connect_reality(saddr, ccfg)
        .await
        .map_err(|e| e.to_string())?;

    // Serve SOCKS5 on an ephemeral loopback port.
    let socks_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let socks_addr = socks_listener.local_addr().map_err(|e| e.to_string())?;
    drop(socks_listener); // free the port for serve_socks5 to re-bind
    tokio::spawn(async move {
        let _ = serve_socks5(conn, &socks_addr.to_string()).await;
    });
    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SOCKS5 UDP ASSOCIATE handshake over TCP: greeting → request → read the relay's bound addr.
    let mut ctrl = tokio::net::TcpStream::connect(socks_addr)
        .await
        .map_err(|e| e.to_string())?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ctrl.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?; // VER, 1 method, no-auth
    let mut sel = [0u8; 2];
    ctrl.read_exact(&mut sel).await.map_err(|e| e.to_string())?;
    if sel != [0x05, 0x00] {
        return Err(format!("bad method selection: {sel:?}"));
    }
    // UDP ASSOCIATE request: VER, CMD=3, RSV, ATYP=1, 0.0.0.0:0 (client's expected source).
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| e.to_string())?;
    // Reply: VER, REP, RSV, ATYP=1, BND.ADDR(4), BND.PORT(2).
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply)
        .await
        .map_err(|e| e.to_string())?;
    if reply[1] != 0x00 {
        return Err(format!("associate rejected: rep={}", reply[1]));
    }
    let relay_addr = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    // Send a UDP datagram (wrapped in the SOCKS UDP header) to the relay, expect the echo back.
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let req = socks_udp_request(echo, b"socks-udp-e2e");
    sock.send_to(&req, relay_addr)
        .await
        .map_err(|e| e.to_string())?;

    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .map_err(|_| "recv timeout".to_string())?
        .map_err(|e| e.to_string())?;
    // Reply is RSV(2)+FRAG(1)+ATYP(1)+ADDR(4)+PORT(2) = 10-byte header, then the echoed data.
    if n < 10 {
        return Err(format!("short reply: {n} bytes"));
    }
    let payload = &buf[10..n];
    // Keep the control connection alive until here so the association isn't torn down early.
    drop(ctrl);
    if payload == b"socks-udp-e2e" {
        Ok(())
    } else {
        Err(format!("mismatch: {payload:?}"))
    }
}
