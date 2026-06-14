//! Build a REALITY-authed ClientHello (auth blob embedded in session_id),
//! plus the runtime: connect, authenticate, establish the REALITY tunnel,
//! and serve a local SOCKS5 proxy over it.
use crate::auth::{AuthPayload, aad_from_client_hello, derive_auth_key, seal_session_id};
use crate::config::ClientAuthConfig;
use crate::tunnel::{establish_client, into_transport};
use leshiy_core::handshake::PROTOCOL_MAJOR;
use leshiy_core::mux::{Mux, Role};
use leshiy_core::version::Hello;
use leshiy_tls::client_hello::build_client_hello;
use leshiy_tls::fingerprint::Profile;
use leshiy_tls::record::{HANDSHAKE, Record, write_record};
use leshiy_tls::tls13::mlkem::{MlKemDecapKey, generate as mlkem_generate};
use rand::RngCore;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const SID_OFFSET: usize = 39;
/// Leshiy application version sealed into the (encrypted) auth payload — tracks the
/// crate release version, distinct from the wire PROTOCOL_MAJOR. Never sent in clear.
const LESHIY_VERSION: [u8; 3] = [1, 0, 0];

/// Returns (ClientHello bytes, ephemeral x25519 private key bytes, ML-KEM-768 decap key).
/// The ephemeral x25519 private and the ML-KEM decap key are BOTH reused in M1.3 for
/// the TLS key exchange, so they are returned. The caller threads `mlkem_dk` into
/// `client_handshake` so it can decapsulate the server's ciphertext.
pub fn build_authed_client_hello(
    profile: &Profile,
    cfg: &ClientAuthConfig,
    now_secs: u32,
) -> (Vec<u8>, Zeroizing<[u8; 32]>, MlKemDecapKey) {
    // 1. ephemeral x25519 (reusable StaticSecret so M1.3 can reuse it)
    let mut ephem_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ephem_bytes);
    let ephem = StaticSecret::from(ephem_bytes);
    let ephem_pub = PublicKey::from(&ephem).to_bytes();

    // 2. generate ML-KEM-768 keypair; the ek goes into the ClientHello, dk is returned to caller
    let (mlkem_dk, mlkem_ek) = mlkem_generate();

    // 3. choose the ClientHello random
    let mut ch_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ch_random);

    // 4. derive auth_key from shared = X25519(ephem, server_static_pub)
    let shared = Zeroizing::new(
        ephem
            .diffie_hellman(&PublicKey::from(cfg.server_public))
            .to_bytes(),
    );
    let auth_key = derive_auth_key(&shared, &ch_random);

    // 5. build the ClientHello with our random + ephemeral key_share + real ML-KEM ek
    let mut ch = build_client_hello(profile, &cfg.sni, &ephem_pub, &mlkem_ek, ch_random);

    // 6. seal the auth payload into session_id (AAD = CH with session_id zeroed)
    let aad = aad_from_client_hello(&ch);
    let payload = AuthPayload {
        version: LESHIY_VERSION,
        unix_secs: now_secs,
        short_id: cfg.short_id,
    };
    let sid = seal_session_id(&auth_key, &ch_random, &payload, &aad);
    let end = (SID_OFFSET + 32).min(ch.len());
    ch[SID_OFFSET..end].copy_from_slice(&sid[..end - SID_OFFSET]);

    (ch, Zeroizing::new(ephem_bytes), mlkem_dk)
}

/// The Hello value used on both ends of the REALITY tunnel — MUST match `server_hello()`.
fn client_hello_version() -> Hello {
    Hello {
        version: PROTOCOL_MAJOR,
        min_supported: 1,
        capabilities: leshiy_core::version::CAP_DATAGRAM,
    }
}

/// Minimal SOCKS5 (no-auth, CONNECT only). Returns ("host:port", io).
/// Mirror of v0 `leshiy::client::socks5_accept`, errors mapped to `RealityError`.
pub async fn socks5_accept<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
) -> crate::Result<(String, S)> {
    use crate::RealityError;
    // Greeting
    let mut head = [0u8; 2];
    io.read_exact(&mut head).await.map_err(RealityError::Io)?;
    if head[0] != 0x05 {
        return Err(RealityError::Malformed("not socks5".into()));
    }
    let mut methods = vec![0u8; head[1] as usize];
    io.read_exact(&mut methods)
        .await
        .map_err(RealityError::Io)?;
    io.write_all(&[0x05, 0x00])
        .await
        .map_err(RealityError::Io)?; // no-auth selected

    // Request
    let mut req = [0u8; 4];
    io.read_exact(&mut req).await.map_err(RealityError::Io)?;
    if req[1] != 0x01 {
        // CMD must be CONNECT
        io.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(RealityError::Io)?;
        return Err(RealityError::Malformed("only CONNECT supported".into()));
    }
    let host = match req[3] {
        0x01 => {
            // IPv4
            let mut a = [0u8; 4];
            io.read_exact(&mut a).await.map_err(RealityError::Io)?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            // Domain
            let mut l = [0u8; 1];
            io.read_exact(&mut l).await.map_err(RealityError::Io)?;
            let mut d = vec![0u8; l[0] as usize];
            io.read_exact(&mut d).await.map_err(RealityError::Io)?;
            String::from_utf8_lossy(&d).to_string()
        }
        0x04 => {
            // IPv6
            let mut a = [0u8; 16];
            io.read_exact(&mut a).await.map_err(RealityError::Io)?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return Err(RealityError::Malformed("bad atyp".into())),
    };
    let mut p = [0u8; 2];
    io.read_exact(&mut p).await.map_err(RealityError::Io)?;
    let port = u16::from_be_bytes(p);
    // Success reply: VER=5, REP=0, RSV=0, ATYP=1 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
    io.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(RealityError::Io)?;
    Ok((format!("{host}:{port}"), io))
}

/// An established REALITY tunnel, ready for SOCKS5 serving.
pub struct RealityConn {
    pub(crate) mux: Arc<Mutex<Mux>>,
}

impl RealityConn {
    /// Open a tunneled stream to `target` ("host:port") over the mux.
    pub async fn open(&self, target: &str) -> crate::Result<leshiy_core::mux::Stream> {
        self.mux
            .lock()
            .await
            .open(target)
            .await
            .map_err(|e| crate::RealityError::Malformed(e.to_string()))
    }

    /// Open a UDP datagram association to `target` ("host:port") over the mux.
    pub async fn open_datagram(&self, target: &str) -> crate::Result<leshiy_core::mux::Stream> {
        self.mux
            .lock()
            .await
            .open_datagram(target)
            .await
            .map_err(|e| crate::RealityError::Malformed(e.to_string()))
    }

    /// Resolves once the underlying tunnel has dropped (the mux's reader or writer
    /// task exited). Used by the supervisor to trigger reconnect.
    pub async fn closed(&self) {
        let mut rx = self.mux.lock().await.closed_receiver();
        let _ = rx.wait_for(|v| *v).await;
    }
}

/// Open the TCP connection to the REALITY server. On Android the socket must be **protected**
/// from the VpnService (so the SYN egresses the physical NIC instead of looping back into our own
/// tunnel) — we create the socket via `TcpSocket`, hand its fd to the registered protect callback
/// *before* connecting, then connect. Everywhere else this is a plain `TcpStream::connect`.
async fn connect_server(server_addr: &str) -> std::io::Result<TcpStream> {
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        use tokio::net::TcpSocket;
        // `TcpSocket` needs a concrete addr (not a host:port string), so resolve first.
        let addr = tokio::net::lookup_host(server_addr)
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("no address for server"))?;
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        leshiy_core::protect::protect_fd(socket.as_raw_fd());
        socket.connect(addr).await
    }
    #[cfg(not(target_os = "android"))]
    {
        TcpStream::connect(server_addr).await
    }
}

/// Connect to the REALITY server, authenticate, and establish the mux tunnel.
/// Returns a [`RealityConn`] that can be passed to [`serve_socks5`].
pub async fn connect_reality(
    server_addr: &str,
    cfg: ClientAuthConfig,
) -> crate::Result<RealityConn> {
    let sock = connect_server(server_addr)
        .await
        .map_err(crate::RealityError::Io)?;
    sock.set_nodelay(true).ok();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    let (ch, ephem, mlkem_dk) = build_authed_client_hello(&Profile::yandex(), &cfg, now);

    // Recompute auth_key: X25519(ephem, server_pub) then HKDF with the CH random.
    let shared = zeroize::Zeroizing::new(
        StaticSecret::from(*ephem)
            .diffie_hellman(&PublicKey::from(cfg.server_public))
            .to_bytes(),
    );
    let random = leshiy_tls::ja::extract_client_hello_fields(&ch)
        .map_err(crate::RealityError::Tls)?
        .random;
    let auth_key = derive_auth_key(&shared, &random);

    let (cr, mut cw) = tokio::io::split(sock);
    write_record(
        &mut cw,
        &Record {
            content_type: HANDSHAKE,
            payload: ch.clone(),
        },
    )
    .await
    .map_err(crate::RealityError::Tls)?;

    let (session, r, w) = establish_client(cr, cw, &ch, &ephem, &auth_key, &mlkem_dk).await?;
    let (tr, tw) = into_transport(&session, Role::Client, r, w);
    let mux = Arc::new(Mutex::new(
        Mux::start(tr, tw, client_hello_version(), Role::Client)
            .await
            .map_err(|e| crate::RealityError::Malformed(e.to_string()))?,
    ));

    Ok(RealityConn { mux })
}

/// Bind a SOCKS5 listener on `socks_addr` and serve tunneled connections over `conn`.
pub async fn serve_socks5(conn: RealityConn, socks_addr: &str) -> crate::Result<()> {
    let mux = conn.mux;
    let listener = TcpListener::bind(socks_addr)
        .await
        .map_err(crate::RealityError::Io)?;
    loop {
        let (cli, _) = listener.accept().await.map_err(crate::RealityError::Io)?;
        cli.set_nodelay(true).ok();
        let mux = mux.clone();
        tokio::spawn(async move {
            if let Ok((target, cli)) = socks5_accept(cli).await
                && let Ok(stream) = { mux.lock().await.open(&target).await }
            {
                let _ = pipe(cli, stream).await;
            }
        });
    }
}

/// Connect to the REALITY server, authenticate, establish the tunnel, and serve SOCKS5.
/// Back-compat wrapper: equivalent to `serve_socks5(connect_reality(server_addr, cfg).await?, socks_addr).await`.
pub async fn run_reality_client(
    server_addr: &str,
    cfg: ClientAuthConfig,
    socks_addr: &str,
) -> crate::Result<()> {
    serve_socks5(connect_reality(server_addr, cfg).await?, socks_addr).await
}

/// Bidirectional copy between a SOCKS5 TCP socket and a mux Stream.
/// Mirror of v0 `leshiy::client::pipe`.
async fn pipe(cli: TcpStream, mut stream: leshiy_core::mux::Stream) -> crate::Result<()> {
    let (mut r, mut w) = cli.into_split();
    loop {
        tokio::select! {
            inbound = stream.recv() => match inbound {
                Ok(b) => w.write_all(&b).await.map_err(crate::RealityError::Io)?,
                Err(_) => break,
            },
            res = async {
                let mut b = vec![0u8; 16384];
                let n = r.read(&mut b).await.map_err(crate::RealityError::Io)?;
                b.truncate(n);
                crate::Result::Ok(b)
            } => {
                let b = res?;
                if b.is_empty() { break; }
                stream.send(b).await.map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
            }
        }
    }
    let _ = stream.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthPayload, aad_from_client_hello, derive_auth_key, open_session_id};
    use crate::config::ClientAuthConfig;
    use leshiy_tls::ja::extract_client_hello_fields;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn authed_clienthello_opens_server_side() {
        let server_secret = StaticSecret::from([0x55u8; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let cfg = ClientAuthConfig {
            server_public,
            short_id: [1, 2, 3, 4, 0, 0, 0, 0],
            sni: "www.example.com".into(),
        };

        let (ch, ephem_priv, _mlkem_dk) = build_authed_client_hello(
            &leshiy_tls::fingerprint::Profile::yandex(),
            &cfg,
            1_700_000_000,
        );

        // server side: extract fields, recompute shared via static_secret x client ephemeral pub
        let f = extract_client_hello_fields(&ch).unwrap();
        let client_pub = f.key_share_x25519.unwrap();
        let shared = server_secret
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes();
        let auth_key = derive_auth_key(&shared, &f.random);
        let aad = aad_from_client_hello(&ch);
        let mut sid = [0u8; 32];
        sid.copy_from_slice(&f.session_id);
        let pt = open_session_id(&auth_key, &f.random, &sid, &aad).expect("server opens authed CH");
        let payload = AuthPayload::decode(&pt);
        assert_eq!(payload.unix_secs, 1_700_000_000);
        assert_eq!(payload.short_id, [1, 2, 3, 4, 0, 0, 0, 0]);
        // ephemeral private is reusable (32 bytes) for M1.3
        assert_eq!(ephem_priv.len(), 32);
    }
}
