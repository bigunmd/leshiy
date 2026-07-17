//! REALITY server: classify connections; relay unauthorized/prober traffic to dest.
use crate::auth::{AuthPayload, aad_from_client_hello, derive_auth_key, open_session_id};
use crate::config::ServerAuthConfig;
use leshiy_tls::ja::extract_client_hello_fields;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    Authed { short_id: [u8; 8], client_time: u32 },
    Unauthed,
}

/// Full classification result that also exposes the derived `auth_key` on success.
pub enum ClassificationFull {
    Authed {
        short_id: [u8; 8],
        client_time: u32,
        auth_key: Zeroizing<[u8; 32]>,
    },
    Unauthed,
}

/// Full classification of a ClientHello — returns the derived `auth_key` on success.
/// The short_id membership check has been removed; the UserStore is now the registry.
/// ANY failure (crypto, SNI, timestamp) => Unauthed (anti-probe).
pub fn classify_full(ch: &[u8], cfg: &ServerAuthConfig, now_secs: u32) -> ClassificationFull {
    let fields = match extract_client_hello_fields(ch) {
        Ok(f) => f,
        Err(_) => return ClassificationFull::Unauthed,
    };

    // Collect each validity condition WITHOUT early-returning, so the X25519 DH + HKDF + AEAD
    // work below runs for every well-formed ClientHello regardless of which check ultimately
    // fails. Otherwise a disallowed-SNI probe returns before doing any crypto while a
    // crypto-invalid-but-allowed-SNI probe pays the full cost — a timing oracle for "is my SNI
    // guess correct?" (M2). Every rejection still lands on the identical silent relay fallback.
    let sni_ok = matches!(&fields.sni, Some(s) if cfg.sni_allowed(s));
    let session_ok = fields.session_id.len() == 32;
    let keyshare_ok = fields.key_share_x25519.is_some();
    // Use the real client key share when present, else a fixed dummy so the DH still runs.
    let client_pub = fields.key_share_x25519.unwrap_or([0x09u8; 32]);

    // recompute shared + auth_key, then open the session_id — unconditionally.
    let server_secret = StaticSecret::from(*cfg.static_secret);
    let shared = Zeroizing::new(
        server_secret
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes(),
    );
    let auth_key = derive_auth_key(&shared, &fields.random);
    let aad = aad_from_client_hello(ch);
    // Zero-padded so the AEAD open is attempted even when session_id is the wrong length.
    let mut sid = [0u8; 32];
    let n = fields.session_id.len().min(32);
    sid[..n].copy_from_slice(&fields.session_id[..n]);
    let opened = open_session_id(&auth_key, &fields.random, &sid, &aad);

    // Now fold in every condition. Any failure => Unauthed (anti-probe).
    let Some(pt) = opened else {
        return ClassificationFull::Unauthed;
    };
    if !(sni_ok && session_ok && keyshare_ok) {
        return ClassificationFull::Unauthed;
    }
    let payload = AuthPayload::decode(&pt);
    // NOTE: short_id membership check removed — UserStore is now the registry.
    // timestamp window
    let diff = now_secs.abs_diff(payload.unix_secs) as u64;
    if diff > cfg.max_time_diff.as_secs() {
        return ClassificationFull::Unauthed;
    }
    ClassificationFull::Authed {
        short_id: payload.short_id,
        client_time: payload.unix_secs,
        auth_key,
    }
}

/// Pure classification of a ClientHello. ANY failure => Unauthed (anti-probe).
/// Delegates to `classify_full`; discards the `auth_key`.
pub fn classify(ch: &[u8], cfg: &ServerAuthConfig, now_secs: u32) -> Classification {
    match classify_full(ch, cfg, now_secs) {
        ClassificationFull::Authed {
            short_id,
            client_time,
            ..
        } => Classification::Authed {
            short_id,
            client_time,
        },
        ClassificationFull::Unauthed => Classification::Unauthed,
    }
}

use crate::egress::Egress;
use crate::handshake::ServerCert;
use crate::tunnel::{establish_server, into_transport};
use crate::user::{UserLimits, UserStore};
use leshiy_core::handshake::PROTOCOL_MAJOR;
use leshiy_core::mux::{Mux, Role};
use leshiy_core::version::Hello;
use leshiy_tls::record::read_record;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) fn server_hello() -> Hello {
    Hello {
        version: PROTOCOL_MAJOR,
        min_supported: 1,
        capabilities: leshiy_core::version::CAP_DATAGRAM
            | leshiy_core::version::CAP_KEEPALIVE
            | leshiy_core::version::CAP_FLOWCONTROL
            | leshiy_core::version::CAP_ICMP
            | leshiy_core::version::CAP_IDLE_TOLERANCE,
        // A server never suspends, so it asks for nothing beyond the default; advertising the cap
        // is what lets it *honour* a sleeping client's request (ADR-0031).
        idle_tolerance: leshiy_core::version::DEFAULT_IDLE_TOLERANCE,
    }
}

/// Handle one client connection: mirror the first record to dest, then relay (prober/garbage)
/// or take over (authed) and tunnel the mux streams to their targets.
#[allow(clippy::too_many_arguments)]
pub async fn serve_connection<S>(
    mut client: S,
    cfg: Arc<ServerAuthConfig>,
    store: Arc<dyn UserStore>,
    egress: Arc<dyn Egress>,
    cert: Arc<ServerCert>,
    replay: Arc<crate::replay::ReplayGuard>,
    now_secs: u32,
) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. read the client's first TLS record, bounded so a peer that completes the TCP
    //    handshake and then stalls (or dribbles a partial record) can't pin its admission
    //    slot forever — a slowloris against the ConnLimiter budget (H1). A timeout is the
    //    same silent drop as a garbage/bare TCP open.
    let first = match tokio::time::timeout(INITIAL_READ_TIMEOUT, read_record(&mut client)).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) | Err(_) => return Ok(()),
    };
    let first_bytes = first.encode();
    // 2. dial dest (bounded), forward the first record. Peek the SNI from the ClientHello so a
    //    multi-name deployment mirrors each advertised name to its OWN origin (per-SNI dest); a
    //    garbage/non-ClientHello first record just falls back to the default dest and is relayed.
    let peek_sni = leshiy_tls::ja::extract_client_hello_fields(&first.payload)
        .ok()
        .and_then(|f| f.sni);
    let mut dest = match connect_dest(cfg.dest_for(peek_sni.as_deref()), DEST_CONNECT_TIMEOUT).await
    {
        Some(d) => d,
        None => {
            // H4: a dest-dial failure must NOT produce an instant zero-byte close
            // — that is an active-probe distinguisher from a genuine TLS site.
            // Absorb client bytes for a bounded, per-connection-jittered period so
            // the failure resembles a stalled/overloaded server.
            //
            // The dial is bounded by DEST_CONNECT_TIMEOUT: a `dest` whose SYN (or
            // DNS lookup) black-holes — e.g. a container that can't resolve/reach
            // the borrowed site — must NOT hang the connection forever. Without the
            // bound, `TcpStream::connect` blocks on the OS timeout (tens of seconds)
            // and every client stalls with no response and no close.
            stall_then_drop(&mut client, &first_bytes).await;
            return Ok(());
        }
    };
    dest.set_nodelay(true).ok();
    dest.write_all(&first_bytes).await?;
    dest.flush().await?;
    // 3. decide
    let fields = leshiy_tls::ja::extract_client_hello_fields(&first.payload);
    if fields.is_err() {
        // garbage that still framed as a record → just relay to dest
        let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
        return Ok(());
    }
    match classify_full(&first.payload, &cfg, now_secs) {
        ClassificationFull::Unauthed => {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
            Ok(())
        }
        ClassificationFull::Authed {
            auth_key, short_id, ..
        } => {
            // Anti-replay: an exact replay of a previously-seen authenticated
            // ClientHello must NOT trigger the takeover behavior (which would be
            // a confirmation oracle for the censor). Downgrade to a genuine dest
            // relay — byte-identical to the Unauthed path. Legitimate clients use
            // a fresh random per connection, so they never collide.
            if let Ok(f) = &fields
                && let Some(key) = crate::replay::replay_key(&f.random, &f.session_id)
                && replay.check_and_record(key, now_secs as u64)
            {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
                return Ok(());
            }
            // Consult the UserStore: unknown/disabled/expired/over-cap → genuine dest session
            // (anti-probe: a rejected user gets a real dest session, indistinguishable from a prober).
            let now64 = now_secs as u64;
            let limits = match store.authorize(&short_id, now64) {
                Some(l) => l,
                None => {
                    // dest is still alive (we only read the ServerHello in the authed-ok branch below)
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
                    return Ok(());
                }
            };

            // steal dest's ServerHello (its first record), then drop dest. Bounded so a
            // slow/throttled dest can't hang an authorized client's connect and pin its
            // admission slot indefinitely (M1).
            let dest_sh_rec =
                match tokio::time::timeout(INITIAL_READ_TIMEOUT, read_record(&mut dest)).await {
                    Ok(Ok(r)) => r,
                    Ok(Err(_)) | Err(_) => return Ok(()),
                };
            let _ = dest.shutdown().await;
            drop(dest);
            let (cr, cw) = tokio::io::split(client);
            let (session, r, w) = establish_server(
                cr,
                cw,
                &first.payload,
                &dest_sh_rec.payload,
                &auth_key,
                &cert,
            )
            .await?;
            let (tr, tw) = into_transport(&session, Role::Server, r, w);
            let mut mux = Mux::start(tr, tw, server_hello(), Role::Server)
                .await
                .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
            loop {
                let mut stream = mux
                    .accept()
                    .await
                    .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
                let sid = short_id;
                let lim = limits.clone();
                let st = store.clone();
                let eg = egress.clone();
                tokio::spawn(async move {
                    match stream.kind {
                        leshiy_core::mux::StreamKind::Udp => {
                            let _ = relay_datagram(&mut stream, sid, lim, st, eg).await;
                        }
                        leshiy_core::mux::StreamKind::Tcp => {
                            let _ = relay_stream(&mut stream, sid, lim, st, eg).await;
                        }
                        leshiy_core::mux::StreamKind::Icmp => {
                            let _ = relay_icmp(&mut stream, sid, lim, st, eg).await;
                        }
                    }
                    let _ = stream.close().await;
                });
            }
        }
    }
}

/// Upper bound on the dest dial (TCP connect + any DNS resolution). A slow or
/// black-holed `dest` beyond this is treated as unreachable → `stall_then_drop`,
/// so a connection can never hang indefinitely on the borrowed-site dial.
const DEST_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Wall-clock bound on the first client record read and the dest ServerHello read. A peer (or a
/// throttled dest) that stalls mid-read must be dropped rather than pin a `ConnLimiter` slot
/// forever (H1/M1). Generous — a real handshake sends its first record immediately.
const INITIAL_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Connect to `dest`, bounded by `timeout`. Returns `None` on either a connect
/// error or a timeout — both mean "dest is not usable right now" and map to the
/// same anti-probe stall path, so the caller need not distinguish them.
async fn connect_dest(dest: &str, timeout: std::time::Duration) -> Option<TcpStream> {
    match tokio::time::timeout(timeout, TcpStream::connect(dest)).await {
        Ok(Ok(s)) => Some(s),
        Ok(Err(_)) => None, // connect refused / unreachable
        Err(_) => None,     // timed out (SYN or DNS black-holed)
    }
}

/// Absorb client bytes for a bounded, per-connection-jittered period, then drop.
/// Used when dest is unreachable so we don't emit a tell-tale instant close (H4).
/// The jitter is derived from the client's first record so it varies per peer
/// without needing an RNG, and is bounded to a few seconds.
async fn stall_then_drop<S>(client: &mut S, seed: &[u8])
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tokio::io::AsyncReadExt;
    let h = seed
        .iter()
        .fold(0u64, |a, &b| a.wrapping_mul(31).wrapping_add(b as u64));
    let secs = 1 + (h % 8); // 1..=8 seconds
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(deadline);
    let mut buf = [0u8; 1024];
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            r = client.read(&mut buf) => match r {
                Ok(0) | Err(_) => break, // peer gave up
                Ok(_) => {}              // discard and keep absorbing
            }
        }
    }
}

/// Open an egress connection to the stream's target and relay bytes both ways.
/// Throttles via per-user TokenBuckets (None = unlimited, skips consume entirely).
/// Reports usage every ~64 KB (atomic-only, ADR-0019 hot-path discipline).
async fn relay_stream(
    stream: &mut leshiy_core::mux::Stream,
    short_id: [u8; 8],
    limits: UserLimits,
    store: Arc<dyn UserStore>,
    egress: Arc<dyn Egress>,
) -> crate::Result<()> {
    let (mut ur, mut uw) = egress
        .open(&stream.target)
        .await
        .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
    let mut acc_up: u64 = 0;
    let mut acc_down: u64 = 0;
    const FLUSH: u64 = 64 * 1024; // report usage every ~64 KB (ADR-0019: atomic-only)
    // M4: re-check authorization on a timer too, so revocation / expiry / data-cap
    // bounds a *live* session within ~1s instead of waiting for the next 64 KB flush
    // (which a trickle of small streams may never reach).
    let mut revoke_tick = tokio::time::interval(std::time::Duration::from_secs(2));
    revoke_tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = revoke_tick.tick() => {
                if !store.still_allowed(&short_id, now_secs()) { break; }
            }
            inbound = stream.recv() => match inbound {           // client → target = UP
                Ok(b) => {
                    if let Some(tb) = &limits.up { tb.consume(b.len() as u64).await; }
                    uw.write_all(&b).await.map_err(crate::RealityError::Io)?;
                    acc_up += b.len() as u64;
                    if acc_up >= FLUSH {
                        store.add_usage(&short_id, acc_up, 0);
                        acc_up = 0;
                        let now = now_secs();
                        if !store.still_allowed(&short_id, now) { break; }
                    }
                }
                Err(_) => break,
            },
            res = async {
                // Read at most one frame's worth so each read → one full TLS record.
                let mut b = vec![0u8; leshiy_core::frame::MAX_FRAME_PAYLOAD];
                let n = ur.read(&mut b).await.map_err(crate::RealityError::Io)?;
                b.truncate(n);
                crate::Result::Ok(b)
            } => {
                let b = res?;
                if b.is_empty() { break; }
                let blen = b.len() as u64;
                if let Some(tb) = &limits.down { tb.consume(blen).await; }  // target → client = DOWN
                stream.send(b.into()).await.map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
                acc_down += blen;
                if acc_down >= FLUSH {
                    store.add_usage(&short_id, 0, acc_down);
                    acc_down = 0;
                    let now = now_secs();
                    if !store.still_allowed(&short_id, now) { break; }
                }
            }
        }
    }
    uw.shutdown().await.ok();
    store.add_usage(&short_id, acc_up, acc_down); // final flush of the tail
    Ok(())
}

/// Relay UDP datagrams between a mux datagram stream and a UDP egress socket.
/// Each `stream.recv()` is one datagram out; each `udp.recv()` is one datagram back.
/// A per-iteration idle timer expires the association (UDP has no teardown signal);
/// the client closing the flow (CLOSE frame) also ends it via a `stream.recv()` error.
async fn relay_datagram(
    stream: &mut leshiy_core::mux::Stream,
    short_id: [u8; 8],
    limits: UserLimits,
    store: Arc<dyn UserStore>,
    egress: Arc<dyn Egress>,
) -> crate::Result<()> {
    let mut udp = egress
        .open_udp(&stream.target)
        .await
        .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
    const IDLE: std::time::Duration = std::time::Duration::from_secs(60);
    let mut buf = vec![0u8; 65535];
    // M4: the UDP relay previously never re-checked authorization at all, so a
    // revoked/expired/over-cap user kept flowing until the idle timeout. Re-check
    // on a 1s timer.
    let mut revoke_tick = tokio::time::interval(std::time::Duration::from_secs(2));
    revoke_tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = revoke_tick.tick() => {
                if !store.still_allowed(&short_id, now_secs()) { break; }
            }
            inbound = stream.recv() => match inbound {       // client → target = UP
                Ok(b) => {
                    if let Some(tb) = &limits.up { tb.consume(b.len() as u64).await; }
                    let _ = udp.send(&b).await;
                    store.add_usage(&short_id, b.len() as u64, 0);
                }
                Err(_) => break,
            },
            r = udp.recv(&mut buf) => match r {              // target → client = DOWN
                Ok(n) => {
                    if let Some(tb) = &limits.down { tb.consume(n as u64).await; }
                    stream
                        .send(buf[..n].to_vec().into())
                        .await
                        .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
                    store.add_usage(&short_id, 0, n as u64);
                }
                Err(_) => break,
            },
            _ = tokio::time::sleep(IDLE) => break,
        }
    }
    Ok(())
}

/// Relay ICMP **echo** between a mux `icmp:` association and an unprivileged ping socket
/// (ADR-0030). Mirrors [`relay_datagram`] — same idle expiry, same re-auth tick, same token
/// buckets — with two ICMP-specific jobs.
///
/// First, only echo *requests* go out. Anything else the client managed to put on the wire is
/// dropped here rather than trusted, so this relay can never be used to emit a Redirect or a
/// forged Destination Unreachable.
///
/// Second, the identifier. A ping socket stamps its own local port over the echo id on send, so
/// the reply comes back bearing the kernel's id, not the one the user's `ping` chose — and their
/// `ping` would discard it as unrelated. Restore the id we last forwarded, then re-checksum: v4
/// here, v6 by the client, which is the only side that knows the addresses its pseudo-header
/// covers.
async fn relay_icmp(
    stream: &mut leshiy_core::mux::Stream,
    short_id: [u8; 8],
    limits: UserLimits,
    store: Arc<dyn UserStore>,
    egress: Arc<dyn Egress>,
) -> crate::Result<()> {
    let v6 = stream
        .target
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_ipv6())
        .unwrap_or(false);
    let mut icmp = egress
        .open_icmp(&stream.target)
        .await
        .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
    const IDLE: std::time::Duration = std::time::Duration::from_secs(30);
    let mut buf = vec![0u8; 65535];
    let mut last_id: Option<u16> = None;
    let mut revoke_tick = tokio::time::interval(std::time::Duration::from_secs(2));
    revoke_tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = revoke_tick.tick() => {
                if !store.still_allowed(&short_id, now_secs()) { break; }
            }
            inbound = stream.recv() => match inbound {       // client → target = UP
                Ok(b) => {
                    // Echo only. Everything else is dropped, not relayed.
                    let Some(echo) = leshiy_core::icmp::parse_echo_request(&b, v6) else {
                        tracing::debug!("non-echo icmp from client dropped");
                        continue;
                    };
                    last_id = Some(echo.id);
                    if let Some(tb) = &limits.up { tb.consume(b.len() as u64).await; }
                    let _ = icmp.send(&b).await;
                    store.add_usage(&short_id, b.len() as u64, 0);
                }
                Err(_) => break,
            },
            r = icmp.recv(&mut buf) => match r {             // target → client = DOWN
                Ok(n) => {
                    let mut msg = buf[..n].to_vec();
                    // Put the user's identifier back so their ping correlates the reply.
                    if let Some(id) = last_id
                        && leshiy_core::icmp::set_id(&mut msg, id)
                        && !v6
                    {
                        // v6 is left checksum-zeroed for the client to complete.
                        let _ = leshiy_core::icmp::set_v4_checksum(&mut msg);
                    }
                    if let Some(tb) = &limits.down { tb.consume(n as u64).await; }
                    stream
                        .send(msg.into())
                        .await
                        .map_err(|e| crate::RealityError::Malformed(e.to_string()))?;
                    store.add_usage(&short_id, 0, n as u64);
                }
                Err(_) => break,
            },
            _ = tokio::time::sleep(IDLE) => break,
        }
    }
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Accept loop: spawn `serve_connection` per connection with the current wall-clock seconds.
pub async fn run_reality_server(
    listener: tokio::net::TcpListener,
    cfg: Arc<ServerAuthConfig>,
    store: Arc<dyn UserStore>,
    egress: Arc<dyn Egress>,
    cert: Arc<ServerCert>,
) -> crate::Result<()> {
    // One replay guard for the whole listener; TTL covers the full acceptance
    // window (±max_time_diff each side) so a replayed authed CH is caught for as
    // long as it would still classify as Authed.
    let replay = Arc::new(crate::replay::ReplayGuard::new(
        cfg.max_time_diff.saturating_mul(2),
    ));
    // Pre-auth admission control (H3): bound total + per-IP concurrent
    // connections so an unauthenticated flood can neither exhaust the server
    // nor reflect onto dest.
    let limiter = crate::connlimit::ConnLimiter::new(MAX_TOTAL_CONNS, MAX_CONNS_PER_IP);
    loop {
        // A per-connection accept() error (EMFILE/ENFILE under FD pressure, or a peer that
        // RSTs while still in the accept queue) must never terminate the listener: propagating
        // it here would exit run_reality_server and, with no supervisor above, kill the whole
        // daemon for every current and future user (C1). Log and carry on. A brief yield avoids
        // a tight spin if the condition (e.g. FD exhaustion) persists.
        let (sock, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed; continuing");
                tokio::task::yield_now().await;
                continue;
            }
        };
        // Admit before doing any work (including the dial to dest). On rejection
        // the socket is dropped immediately. Normalize a v4-mapped peer (dual-stack
        // listener) so a v4 client isn't limited separately from its `::ffff:` form.
        let Some(guard) = limiter.try_acquire(crate::netguard::canonical_ip(peer.ip())) else {
            continue;
        };
        sock.set_nodelay(true).ok();
        let (c, st, eg, ce, rp) = (
            cfg.clone(),
            store.clone(),
            egress.clone(),
            cert.clone(),
            replay.clone(),
        );
        tokio::spawn(async move {
            let _guard = guard; // released when the connection finishes
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let _ = serve_connection(sock, c, st, eg, ce, rp, now).await;
        });
    }
}

/// Total concurrent connections the listener will service at once (H3).
const MAX_TOTAL_CONNS: usize = 4096;
/// Concurrent connections allowed from a single source IP (H3).
const MAX_CONNS_PER_IP: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::build_authed_client_hello;
    use crate::config::{ClientAuthConfig, ServerAuthConfig};
    use crate::user::InMemoryUserStore;
    use std::collections::HashSet;
    use std::time::Duration;
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::Zeroizing;

    fn server_cfg(secret: [u8; 32]) -> ServerAuthConfig {
        ServerAuthConfig {
            static_secret: Zeroizing::new(secret),
            server_names: HashSet::from(["www.example.com".to_string()]),
            short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
            max_time_diff: Duration::from_secs(120),
            dest: "www.example.com:443".into(),
            dest_by_sni: Default::default(),
        }
    }

    fn authed_ch(server_secret: [u8; 32], short_id: [u8; 8], sni: &str, now: u32) -> Vec<u8> {
        let server_public = PublicKey::from(&StaticSecret::from(server_secret)).to_bytes();
        let cfg = ClientAuthConfig {
            server_public,
            short_id,
            sni: sni.into(),
        };
        build_authed_client_hello(&leshiy_tls::fingerprint::Profile::yandex(), &cfg, now).0
    }

    #[test]
    fn classifies_authed() {
        let ch = authed_ch(
            [0x55; 32],
            [1, 2, 3, 4, 0, 0, 0, 0],
            "www.example.com",
            1000,
        );
        match classify(&ch, &server_cfg([0x55; 32]), 1000) {
            Classification::Authed {
                short_id,
                client_time,
            } => {
                assert_eq!(short_id, [1, 2, 3, 4, 0, 0, 0, 0]);
                assert_eq!(client_time, 1000);
            }
            Classification::Unauthed => panic!("should be authed"),
        }
    }

    #[test]
    fn unauthed_wrong_server_key() {
        let ch = authed_ch(
            [0x55; 32],
            [1, 2, 3, 4, 0, 0, 0, 0],
            "www.example.com",
            1000,
        );
        assert!(matches!(
            classify(&ch, &server_cfg([0x66; 32]), 1000),
            Classification::Unauthed
        ));
    }

    /// Previously "unknown short_id → Unauthed" (when classify_full did membership checks).
    /// Now classify_full returns Authed for any crypto-valid client; the UserStore decides
    /// whether the connection proceeds. Assert: crypto-valid but absent short_id is Authed
    /// at classify level, and store.authorize returns None for the absent id.
    #[test]
    fn unknown_short_id_is_authed_by_classify_store_rejects() {
        let ch = authed_ch(
            [0x55; 32],
            [9, 9, 9, 9, 0, 0, 0, 0], // not in server_cfg's short_ids
            "www.example.com",
            1000,
        );
        // classify_full now returns Authed (membership no longer checked here)
        match classify_full(&ch, &server_cfg([0x55; 32]), 1000) {
            ClassificationFull::Authed { short_id, .. } => {
                assert_eq!(short_id, [9, 9, 9, 9, 0, 0, 0, 0]);
                // The store (seeded with known ids only) rejects the absent id
                let store = InMemoryUserStore::from_short_ids([[1u8, 2, 3, 4, 0, 0, 0, 0]]);
                assert!(store.authorize(&short_id, 1000).is_none());
            }
            ClassificationFull::Unauthed => {
                panic!("classify_full should return Authed for crypto-valid client")
            }
        }
    }

    #[test]
    fn replay_of_authed_clienthello_is_detected() {
        // Mirrors serve_connection's anti-replay path: extract the CH fields,
        // derive the replay key, and confirm the guard flags an exact replay.
        use crate::replay::{ReplayGuard, replay_key};
        let ch = authed_ch(
            [0x55; 32],
            [1, 2, 3, 4, 0, 0, 0, 0],
            "www.example.com",
            1000,
        );
        let f = leshiy_tls::ja::extract_client_hello_fields(&ch).unwrap();
        let key = replay_key(&f.random, &f.session_id).expect("32-byte fields");
        let guard = ReplayGuard::new(Duration::from_secs(240));
        assert!(
            !guard.check_and_record(key, 1000),
            "first sight is not a replay"
        );
        assert!(
            guard.check_and_record(key, 1001),
            "identical CH within window is a replay"
        );
    }

    #[test]
    fn unauthed_stale_timestamp() {
        let ch = authed_ch(
            [0x55; 32],
            [1, 2, 3, 4, 0, 0, 0, 0],
            "www.example.com",
            1000,
        );
        // now is 1000 + 200s > 120s window
        assert!(matches!(
            classify(&ch, &server_cfg([0x55; 32]), 1200),
            Classification::Unauthed
        ));
    }

    #[test]
    fn unauthed_bad_sni() {
        let ch = authed_ch(
            [0x55; 32],
            [1, 2, 3, 4, 0, 0, 0, 0],
            "not-allowed.com",
            1000,
        );
        assert!(matches!(
            classify(&ch, &server_cfg([0x55; 32]), 1000),
            Classification::Unauthed
        ));
    }

    #[test]
    fn unauthed_plain_clienthello() {
        // a plain (non-auth) ClientHello: random session_id
        let ch = leshiy_tls::client_hello::build_client_hello(
            &leshiy_tls::fingerprint::Profile::yandex(),
            "www.example.com",
            &[3u8; 32],
            &[0u8; 1184],
            [4u8; 32],
        );
        assert!(matches!(
            classify(&ch, &server_cfg([0x55; 32]), 1000),
            Classification::Unauthed
        ));
    }

    #[tokio::test]
    async fn connect_dest_returns_some_on_live_listener() {
        // A reachable dest connects well within the timeout → Some(stream).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let got = connect_dest(&addr, Duration::from_secs(2)).await;
        assert!(got.is_some(), "live listener must connect");
    }

    #[tokio::test]
    async fn connect_dest_returns_none_on_refused() {
        // Bind then drop a listener so the port is closed → connect is refused
        // fast. Refusal and timeout share the None branch (→ stall_then_drop).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let got = connect_dest(&addr, Duration::from_secs(2)).await;
        assert!(got.is_none(), "refused dest must map to None");
    }

    #[tokio::test(start_paused = true)]
    async fn dest_dial_timeout_maps_to_none() {
        // Deterministically exercise connect_dest's timeout arm: a connect that
        // never completes within the budget must yield None (→ stall_then_drop),
        // NOT hang. A real black-holed socket can't be simulated reliably in a
        // unit test, so mirror the exact arm with a never-completing future.
        // `start_paused` auto-advances the clock, so the 5s budget elapses
        // instantly rather than blocking the test.
        let never = std::future::pending::<std::io::Result<TcpStream>>();
        let out: Option<TcpStream> = match tokio::time::timeout(DEST_CONNECT_TIMEOUT, never).await {
            Ok(Ok(s)) => Some(s),
            _ => None,
        };
        assert!(out.is_none(), "an unfinishable dial must time out to None");
    }

    #[test]
    fn classify_full_returns_auth_key() {
        let ch = authed_ch(
            [0x55; 32],
            [1, 2, 3, 4, 0, 0, 0, 0],
            "www.example.com",
            1000,
        );
        match classify_full(&ch, &server_cfg([0x55; 32]), 1000) {
            ClassificationFull::Authed {
                short_id, auth_key, ..
            } => {
                assert_eq!(short_id, [1, 2, 3, 4, 0, 0, 0, 0]);
                assert_eq!(auth_key.len(), 32);
            }
            ClassificationFull::Unauthed => panic!("should be authed"),
        }
    }

    /// H1: a client that completes the TCP handshake and then stays silent must be dropped by
    /// the first-read timeout, not pin its admission slot forever. `start_paused` auto-advances
    /// the virtual clock so the 10s `INITIAL_READ_TIMEOUT` elapses instantly; the outer 30s guard
    /// only fails the test if `serve_connection` hangs.
    #[tokio::test(start_paused = true)]
    async fn first_read_times_out_on_a_stalled_client() {
        use crate::handshake::ServerCert;
        use crate::replay::ReplayGuard;

        // Keep `client_side` alive but silent so the server's read pends (not EOF).
        let (client_side, server_side) = tokio::io::duplex(4096);
        let cfg = Arc::new(server_cfg([0x55; 32]));
        let store: Arc<dyn UserStore> = Arc::new(InMemoryUserStore::from_short_ids([[
            1u8, 2, 3, 4, 0, 0, 0, 0,
        ]]));
        let egress: Arc<dyn Egress> = Arc::new(crate::DirectEgress::new());
        let cert = Arc::new(ServerCert::generate());
        let replay = Arc::new(ReplayGuard::new(Duration::from_secs(240)));

        let res = tokio::time::timeout(
            Duration::from_secs(30),
            serve_connection(server_side, cfg, store, egress, cert, replay, 1000),
        )
        .await;

        assert!(
            res.is_ok(),
            "serve_connection must return after the first-read timeout, not hang on a silent peer"
        );
        drop(client_side);
    }
}
