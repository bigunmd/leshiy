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
/// Seconds of client silence we ask the server to tolerate (ADR-0031).
///
/// Requested unconditionally, not gated on any user setting — which is what keeps this out of
/// `Transport::dial`'s signature. A longer server tolerance costs a VPS almost nothing and helps
/// every client: a phone that sleeps under ten minutes keeps its tunnel outright, rather than
/// being torn down at 45s and re-dialing on wake. It does not weaken our own blackhole detection,
/// because that times the *server's* silence and the server still declares 45s and still pings
/// every 15s.
const CLIENT_IDLE_TOLERANCE: u32 = 600;

fn client_hello_version() -> Hello {
    Hello {
        version: PROTOCOL_MAJOR,
        min_supported: 1,
        capabilities: leshiy_core::version::CAP_DATAGRAM
            | leshiy_core::version::CAP_KEEPALIVE
            | leshiy_core::version::CAP_FLOWCONTROL
            | leshiy_core::version::CAP_ICMP
            | leshiy_core::version::CAP_IDLE_TOLERANCE,
        idle_tolerance: CLIENT_IDLE_TOLERANCE,
    }
}

/// A parsed SOCKS5 request: either a stream CONNECT or a UDP ASSOCIATE.
pub enum Socks5Cmd<S> {
    /// CONNECT to `target` ("host:port"); the success reply has already been sent on `io`.
    Connect { target: String, io: S },
    /// UDP ASSOCIATE. The reply is **not** yet sent (it must carry the relay's bound address,
    /// which only the caller knows once it binds the UDP socket). `io` is the TCP control
    /// connection — kept open to detect teardown; the client closing it ends the association.
    UdpAssociate { io: S },
}

/// Minimal SOCKS5 (no-auth). Returns ("host:port", io) for a CONNECT; errors on any other
/// command. Kept for callers whose transport cannot carry UDP (QUIC client, direct listener).
/// Mirror of v0 `leshiy::client::socks5_accept`, errors mapped to `RealityError`.
pub async fn socks5_accept<S: AsyncRead + AsyncWrite + Unpin>(io: S) -> crate::Result<(String, S)> {
    match socks5_accept_ext(io).await? {
        Socks5Cmd::Connect { target, io } => Ok((target, io)),
        Socks5Cmd::UdpAssociate { .. } => Err(crate::RealityError::Malformed(
            "only CONNECT supported".into(),
        )),
    }
}

/// Full SOCKS5 accept: handles the no-auth greeting and parses the request, distinguishing
/// CONNECT (0x01) from UDP ASSOCIATE (0x03). For CONNECT the success reply is sent here; for
/// UDP ASSOCIATE it is deferred to the caller (which binds the relay socket first).
pub async fn socks5_accept_ext<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
) -> crate::Result<Socks5Cmd<S>> {
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

    // Request: VER, CMD, RSV, ATYP
    let mut req = [0u8; 4];
    io.read_exact(&mut req).await.map_err(RealityError::Io)?;
    let cmd = req[1];
    // CONNECT (0x01) and UDP ASSOCIATE (0x03) are supported; BIND (0x02) and anything else aren't.
    if cmd != 0x01 && cmd != 0x03 {
        io.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(RealityError::Io)?;
        return Err(RealityError::Malformed("unsupported SOCKS command".into()));
    }
    let host = read_socks_addr(&mut io, req[3]).await?;
    let mut p = [0u8; 2];
    io.read_exact(&mut p).await.map_err(RealityError::Io)?;
    let port = u16::from_be_bytes(p);

    if cmd == 0x01 {
        // Success reply: VER=5, REP=0, RSV=0, ATYP=1 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
        io.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(RealityError::Io)?;
        Ok(Socks5Cmd::Connect {
            target: crate::addr::join_host_port(&host, port),
            io,
        })
    } else {
        // UDP ASSOCIATE — the DST.ADDR/DST.PORT above is the address the client will send *from*
        // (commonly 0.0.0.0:0); we don't restrict on it. The reply is sent by the caller once the
        // relay socket is bound.
        Ok(Socks5Cmd::UdpAssociate { io })
    }
}

/// Read a SOCKS5 address field (ATYP + ADDR) into a host string (no port).
async fn read_socks_addr<S: AsyncRead + Unpin>(io: &mut S, atyp: u8) -> crate::Result<String> {
    use crate::RealityError;
    Ok(match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            io.read_exact(&mut a).await.map_err(RealityError::Io)?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            io.read_exact(&mut l).await.map_err(RealityError::Io)?;
            let mut d = vec![0u8; l[0] as usize];
            io.read_exact(&mut d).await.map_err(RealityError::Io)?;
            String::from_utf8_lossy(&d).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            io.read_exact(&mut a).await.map_err(RealityError::Io)?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return Err(RealityError::Malformed("bad atyp".into())),
    })
}

/// An established REALITY tunnel, ready for SOCKS5 serving.
pub struct RealityConn {
    pub(crate) mux: Arc<Mutex<Mux>>,
    /// Lock-free view of the mux's last keepalive round-trip latency.
    rtt: leshiy_core::mux::RttHandle,
}

impl RealityConn {
    /// Last keepalive round-trip latency to the server in microseconds, if measured.
    pub fn rtt_micros(&self) -> Option<u64> {
        self.rtt.micros()
    }

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

    /// Open an ICMP echo association to `target` (a bare IP, no port) over the mux (ADR-0030).
    pub async fn open_icmp(&self, target: &str) -> crate::Result<leshiy_core::mux::Stream> {
        self.mux
            .lock()
            .await
            .open_icmp(target)
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
        // `TcpSocket` needs a concrete addr (not a host:port string), so resolve first. Try EVERY
        // resolved address (like `TcpStream::connect` does), not just the first — otherwise a
        // leading unreachable address (e.g. an AAAA on an IPv4-only network) fails the whole dial.
        let addrs: Vec<std::net::SocketAddr> =
            tokio::net::lookup_host(server_addr).await?.collect();
        let mut last_err =
            std::io::Error::new(std::io::ErrorKind::NotFound, "no address for server");
        for addr in addrs {
            let socket = match if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            } {
                Ok(s) => s,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            // Protect the socket from the VpnService so the SYN egresses the physical NIC (no-op
            // when no callback is registered — our own app is already excluded from the VPN).
            leshiy_core::protect::protect_fd(socket.as_raw_fd());
            match socket.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
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
    let started = Mux::start(tr, tw, client_hello_version(), Role::Client)
        .await
        .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
    // Grab the lock-free RTT handle before the mux moves behind the async mutex.
    let rtt = started.rtt_handle();
    let mux = Arc::new(Mutex::new(started));

    Ok(RealityConn { mux, rtt })
}

/// Bind a SOCKS5 listener on `socks_addr` and serve tunneled connections over `conn`.
/// Handles both CONNECT (TCP streams) and UDP ASSOCIATE (datagram flows) over the mux.
pub async fn serve_socks5(conn: RealityConn, socks_addr: &str) -> crate::Result<()> {
    let mux = conn.mux;
    let listener = TcpListener::bind(socks_addr)
        .await
        .map_err(crate::RealityError::Io)?;
    loop {
        let (cli, _) = listener.accept().await.map_err(crate::RealityError::Io)?;
        cli.set_nodelay(true).ok();
        // The UDP relay is bound on the interface the control connection arrived on (loopback for
        // a local SOCKS proxy); capture it before `cli` is moved into the accept.
        let bind_ip = cli
            .local_addr()
            .map(|a| a.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let mux = mux.clone();
        tokio::spawn(async move {
            match socks5_accept_ext(cli).await {
                Ok(Socks5Cmd::Connect { target, io }) => {
                    if let Ok(stream) = { mux.lock().await.open(&target).await } {
                        let _ = pipe(io, stream).await;
                    }
                }
                Ok(Socks5Cmd::UdpAssociate { io }) => {
                    let _ = serve_udp_associate(io, mux, bind_ip).await;
                }
                Err(_) => {}
            }
        });
    }
}

/// Serve one SOCKS5 UDP ASSOCIATE: bind a local UDP relay, reply with its address on the TCP
/// control connection, then relay the client's datagrams to per-target mux datagram flows and
/// their replies back. The association ends when the client closes the control connection (or it
/// errors) — UDP itself has no teardown signal.
async fn serve_udp_associate<S>(
    mut ctrl: S,
    mux: Arc<Mutex<leshiy_core::mux::Mux>>,
    bind_ip: std::net::IpAddr,
) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use crate::RealityError;
    let relay = Arc::new(
        tokio::net::UdpSocket::bind((bind_ip, 0))
            .await
            .map_err(RealityError::Io)?,
    );
    let bound = relay.local_addr().map_err(RealityError::Io)?;
    ctrl.write_all(&encode_assoc_reply(bound))
        .await
        .map_err(RealityError::Io)?;

    // One mux datagram flow per distinct target; the sender feeds the flow's UP direction.
    let mut assocs: std::collections::HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>>> =
        std::collections::HashMap::new();
    let mut client_addr: Option<std::net::SocketAddr> = None;
    let mut buf = vec![0u8; 65535];
    let mut ctrl_buf = [0u8; 256];
    loop {
        tokio::select! {
            // The control connection closing (or erroring) ends the whole association.
            r = ctrl.read(&mut ctrl_buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(_) => {} // clients don't normally send on it; ignore stray bytes
            },
            r = relay.recv_from(&mut buf) => {
                let (n, from) = match r { Ok(x) => x, Err(_) => break };
                // Pin the association to the first client source; drop spoofed packets from elsewhere.
                match client_addr {
                    None => client_addr = Some(from),
                    Some(a) if a != from => continue,
                    Some(_) => {}
                }
                let Some((target, data_off, header)) = parse_udp_datagram(&buf[..n]) else {
                    continue; // fragmented or malformed — dropped
                };
                let data = buf[data_off..n].to_vec();
                if !assocs.contains_key(&target) {
                    let stream = match mux.lock().await.open_datagram(&target).await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
                    tokio::spawn(udp_assoc_flow(stream, rx, relay.clone(), from, header));
                    assocs.insert(target.clone(), tx);
                }
                if let Some(tx) = assocs.get(&target) {
                    let _ = tx.send(data).await;
                }
            }
        }
    }
    Ok(())
}

/// Drive one target's datagram flow: forward UP datagrams from `up_rx` onto the mux `stream`, and
/// wrap DOWN datagrams from the tunnel in a SOCKS UDP header (echoing the request's target address)
/// and send them back to the client. Ends when either side closes.
async fn udp_assoc_flow(
    mut stream: leshiy_core::mux::Stream,
    mut up_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    relay: Arc<tokio::net::UdpSocket>,
    client_addr: std::net::SocketAddr,
    header: Vec<u8>,
) {
    // SOCKS UDP reply prefix: RSV(2)=0, FRAG(1)=0, then the echoed ATYP+ADDR+PORT of the target.
    let mut prefix = vec![0u8, 0, 0];
    prefix.extend_from_slice(&header);
    loop {
        tokio::select! {
            up = up_rx.recv() => match up {
                Some(data) => {
                    if stream.send(data.into()).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            down = stream.recv() => match down {
                Ok(b) => {
                    let mut pkt = prefix.clone();
                    pkt.extend_from_slice(&b);
                    if relay.send_to(&pkt, client_addr).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
        }
    }
}

/// Parse a SOCKS5 UDP request datagram: `RSV(2) FRAG(1) ATYP ADDR PORT DATA`. Returns the
/// target ("host:port"), the offset where DATA begins, and the raw `ATYP+ADDR+PORT` header bytes
/// (echoed back in replies). `None` if fragmented (FRAG != 0) or malformed.
fn parse_udp_datagram(pkt: &[u8]) -> Option<(String, usize, Vec<u8>)> {
    if pkt.len() < 4 || pkt[2] != 0 {
        return None; // too short, or fragmentation (unsupported — drop)
    }
    let atyp = pkt[3];
    let (host, addr_end) = match atyp {
        0x01 => {
            let a: [u8; 4] = pkt.get(4..8)?.try_into().ok()?;
            (std::net::Ipv4Addr::from(a).to_string(), 8)
        }
        0x04 => {
            let a: [u8; 16] = pkt.get(4..20)?.try_into().ok()?;
            (std::net::Ipv6Addr::from(a).to_string(), 20)
        }
        0x03 => {
            let len = *pkt.get(4)? as usize;
            let end = 5 + len;
            let d = pkt.get(5..end)?;
            (String::from_utf8_lossy(d).to_string(), end)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*pkt.get(addr_end)?, *pkt.get(addr_end + 1)?]);
    let data_off = addr_end + 2;
    if data_off > pkt.len() {
        return None;
    }
    // Header = ATYP+ADDR+PORT (pkt[3..data_off]), echoed verbatim in reply datagrams.
    Some((
        crate::addr::join_host_port(&host, port),
        data_off,
        pkt[3..data_off].to_vec(),
    ))
}

/// Build the SOCKS5 UDP ASSOCIATE success reply carrying the relay's bound address.
fn encode_assoc_reply(bound: std::net::SocketAddr) -> Vec<u8> {
    let mut r = vec![0x05, 0x00, 0x00];
    match bound.ip() {
        std::net::IpAddr::V4(v4) => {
            r.push(0x01);
            r.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            r.push(0x04);
            r.extend_from_slice(&v6.octets());
        }
    }
    r.extend_from_slice(&bound.port().to_be_bytes());
    r
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
                // Read at most one frame's worth so each read → one full TLS record.
                let mut b = vec![0u8; leshiy_core::frame::MAX_FRAME_PAYLOAD];
                let n = r.read(&mut b).await.map_err(crate::RealityError::Io)?;
                b.truncate(n);
                crate::Result::Ok(b)
            } => {
                let b = res?;
                if b.is_empty() { break; }
                stream.send(b.into()).await.map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
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
    fn both_ends_advertise_keepalive_so_liveness_is_negotiated() {
        // The mux only runs its idle-timeout/ping keepalive when BOTH peers advertise
        // CAP_KEEPALIVE. The client and server hellos must agree, or a blackholed REALITY
        // tunnel never trips closed() and the supervisor never reconnects.
        use leshiy_core::version::CAP_KEEPALIVE;
        assert_ne!(
            client_hello_version().capabilities & CAP_KEEPALIVE,
            0,
            "client must advertise CAP_KEEPALIVE"
        );
        assert_ne!(
            crate::server::server_hello().capabilities & CAP_KEEPALIVE,
            0,
            "server must advertise CAP_KEEPALIVE"
        );
    }

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
