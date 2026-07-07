//! QUIC/HTTP3 server: h3 dispatch, CONNECT auth tunnel + web masquerade (ADR-0019, ADR-0023).
use crate::masquerade::Masquerade;
use crate::{QuicError, Result};
use bytes::{Buf, Bytes};
use http::{Method, StatusCode};
use leshiy_reality::egress::Egress;
use leshiy_reality::user::{UserLimits, UserStore};
use std::net::SocketAddr;
use std::sync::Arc;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn run_quic_server(
    listen: SocketAddr,
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    store: Arc<dyn UserStore>,
    masquerade: Masquerade,
    egress: Arc<dyn Egress>,
) -> Result<()> {
    let ep = crate::endpoint::server_endpoint(listen, certs, key)?;
    serve_quic_on_endpoint(ep, store, masquerade, egress).await
}

/// Run the accept loop on an already-built [`quinn::Endpoint`], spawning a detached
/// per-connection handler for each incoming connection.
///
/// Exposed so callers (e.g. tests) can own the `Endpoint` and call
/// `endpoint.close(..)` to immediately tear down ALL of its live connections — which
/// `run_quic_server` cannot offer because it owns the endpoint internally.
pub async fn serve_quic_on_endpoint(
    endpoint: quinn::Endpoint,
    store: Arc<dyn UserStore>,
    masquerade: Masquerade,
    egress: Arc<dyn Egress>,
) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let (store, masq, egress) = (store.clone(), masquerade.clone(), egress.clone());
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                let _ = serve_h3_conn(conn, store, masq, egress).await;
            }
        });
    }
    Ok(())
}

async fn serve_h3_conn(
    conn: quinn::Connection,
    store: Arc<dyn UserStore>,
    masq: Masquerade,
    egress: Arc<dyn Egress>,
) -> Result<()> {
    // Keep a clone of the raw QUIC connection for connection-level datagram I/O (CONNECT-UDP);
    // the h3 driver owns the wrapped one. Enable extended CONNECT (so `:protocol=connect-udp` is
    // accepted) and H3 datagrams in the SETTINGS.
    let dgram_conn = conn.clone();
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let mut h3 = builder
        .build(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    // One demux task per connection fans inbound datagrams out to their CONNECT-UDP handlers.
    let registry = crate::dgram::new_registry();
    tokio::spawn(crate::dgram::demux_loop(dgram_conn.clone(), registry.clone()));
    while let Ok(Some(resolver)) = h3.accept().await {
        let (req, stream) = match resolver.resolve_request().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let (store, masq, egress) = (store.clone(), masq.clone(), egress.clone());
        let (dgram_conn, registry) = (dgram_conn.clone(), registry.clone());
        tokio::spawn(async move {
            let _ = handle_request(req, stream, store, masq, egress, dgram_conn, registry).await;
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: http::Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    store: Arc<dyn UserStore>,
    masq: Masquerade,
    egress: Arc<dyn Egress>,
    dgram_conn: quinn::Connection,
    registry: crate::dgram::DatagramRegistry,
) -> Result<()> {
    if *req.method() == Method::CONNECT
        && let Some(sid) = auth_short_id(&req)
        && let Some(limits) = store.authorize(&sid, now_secs())
        && let Some(target) = req.uri().authority().map(|a| a.as_str().to_string())
    {
        // Extended CONNECT with `:protocol = connect-udp` (RFC 9298) → UDP datagram tunnel;
        // a plain CONNECT → TCP stream tunnel.
        let is_udp = req.extensions().get::<h3::ext::Protocol>()
            == Some(&h3::ext::Protocol::CONNECT_UDP);
        if is_udp {
            return tunnel_udp(stream, &target, sid, limits, store, egress, dgram_conn, registry)
                .await;
        }
        return tunnel(stream, &target, sid, limits, store, egress).await;
    }
    serve_masquerade(req, stream, masq).await
}

fn auth_short_id(req: &http::Request<()>) -> Option<[u8; 8]> {
    let v = req.headers().get("leshiy-auth")?.to_str().ok()?;
    let bytes = hex::decode(v).ok()?;
    bytes.as_slice().try_into().ok()
}

async fn serve_masquerade(
    req: http::Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    masq: Masquerade,
) -> Result<()> {
    match masq {
        Masquerade::Page(html) => serve_masquerade_page(req, stream, html).await,
        Masquerade::Reverse(origin) => serve_masquerade_reverse(req, stream, &origin).await,
    }
}

/// Static-page masquerade: 200 + `html` for GET/HEAD "/", else 404.
async fn serve_masquerade_page(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    html: String,
) -> Result<()> {
    let is_head = *req.method() == Method::HEAD;
    // Serve 200 only for GET or HEAD "/"; unauthorized CONNECT and everything else gets 404.
    // HEAD gets the correct status but NO body (RFC 9110 §9.3.2).
    let path_root = req.uri().path() == "/" && *req.method() != Method::CONNECT;
    let (status, body) = if (*req.method() == Method::GET || is_head) && path_root {
        (StatusCode::OK, html)
    } else {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    };
    let resp = http::Response::builder().status(status).body(()).unwrap();
    stream
        .send_response(resp)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    if !is_head {
        stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    Ok(())
}

/// Reverse-proxy masquerade: fetch the request's method+path from the operator's real HTTP origin
/// and relay its status + body, so a prober sees a credible site. A HEAD gets the origin's status
/// with no body; an unreachable origin yields a 502.
async fn serve_masquerade_reverse(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    origin: &str,
) -> Result<()> {
    let is_head = *req.method() == Method::HEAD;
    // CONNECT never reverse-proxies (an unauthorized CONNECT is a probe): map it to a 404 fetch by
    // requesting a path that the origin will 404 — but simplest is to only proxy GET/HEAD and 404
    // everything else, matching the static path's behavior.
    let proxied = *req.method() == Method::GET || is_head;
    let (status, body) = if proxied {
        match crate::masquerade::fetch_origin(origin, req.method().as_str(), req.uri().path()).await
        {
            Some(r) => (
                StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY),
                r.body,
            ),
            None => (StatusCode::BAD_GATEWAY, b"Bad Gateway".to_vec()),
        }
    } else {
        (StatusCode::NOT_FOUND, b"Not Found".to_vec())
    };
    let resp = http::Response::builder().status(status).body(()).unwrap();
    stream
        .send_response(resp)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    if !is_head {
        stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    Ok(())
}

async fn tunnel(
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    target: &str,
    sid: [u8; 8],
    limits: UserLimits,
    store: Arc<dyn UserStore>,
    egress: Arc<dyn Egress>,
) -> Result<()> {
    let mut stream = stream;

    // Open egress connection. Netguard is enforced inside DirectEgress / the egress impl.
    // On failure send 502 so the legitimate client gets a clean proxy error.
    let (mut er, mut ew) = match egress.open(target).await {
        Ok(halves) => halves,
        Err(_) => {
            let _ = stream
                .send_response(http::Response::builder().status(502).body(()).unwrap())
                .await;
            let _ = stream.finish().await;
            return Ok(());
        }
    };

    // Send 200, then bidirectional relay over the split h3 stream.
    stream
        .send_response(http::Response::builder().status(200).body(()).unwrap())
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;

    // split() -> (RequestStream<SendStream<Bytes>, Bytes>, RequestStream<RecvStream, Bytes>)
    let (mut send, mut recv) = stream.split();

    const FLUSH: u64 = 64 * 1024;

    // DOWN: target -> client (send_data).
    let down = {
        let store = store.clone();
        async move {
            let mut acc = 0u64;
            let mut buf = vec![0u8; 16384];
            loop {
                let n = er.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                if let Some(tb) = &limits.down {
                    tb.consume(n as u64).await;
                }
                send.send_data(Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .map_err(|e| QuicError::Conn(e.to_string()))?;
                acc += n as u64;
                if acc >= FLUSH {
                    store.add_usage(&sid, 0, acc);
                    acc = 0;
                    if !store.still_allowed(&sid, now_secs()) {
                        break;
                    }
                }
            }
            store.add_usage(&sid, 0, acc);
            let _ = send.finish().await;
            Ok::<(), QuicError>(())
        }
    };

    // UP: client (recv_data) -> target.
    let up = async move {
        let mut acc = 0u64;
        'up: while let Some(mut chunk) = recv
            .recv_data()
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?
        {
            while chunk.has_remaining() {
                let c = chunk.chunk();
                let n = c.len();
                // Rate-gate BEFORE forwarding (matches DOWN direction).
                if let Some(tb) = &limits.up {
                    tb.consume(n as u64).await;
                }
                ew.write_all(c)
                    .await
                    .map_err(|e| QuicError::Io(std::io::Error::other(e.to_string())))?;
                chunk.advance(n);
                acc += n as u64;
                if acc >= FLUSH {
                    store.add_usage(&sid, acc, 0);
                    acc = 0;
                    if !store.still_allowed(&sid, now_secs()) {
                        break 'up;
                    }
                }
            }
        }
        store.add_usage(&sid, acc, 0);
        ew.shutdown().await.ok();
        Ok::<(), QuicError>(())
    };

    let _ = tokio::join!(down, up);
    Ok(())
}

/// Relay a CONNECT-UDP association (RFC 9298): HTTP datagrams on this request stream ↔ a UDP
/// egress socket. Inbound datagrams arrive via the connection demux (`registry`); outbound go out
/// as connection-level QUIC datagrams framed for this stream. The association ends when the client
/// closes the request stream, the UDP socket errors, or the user is revoked.
#[allow(clippy::too_many_arguments)]
async fn tunnel_udp(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    target: &str,
    sid: [u8; 8],
    limits: UserLimits,
    store: Arc<dyn UserStore>,
    egress: Arc<dyn Egress>,
    dgram_conn: quinn::Connection,
    registry: crate::dgram::DatagramRegistry,
) -> Result<()> {
    let stream_id = stream.id();
    // Open the UDP egress; on failure reply 502 so the client sees a clean proxy error.
    let mut udp = match egress.open_udp(target).await {
        Ok(u) => u,
        Err(_) => {
            let _ = stream
                .send_response(http::Response::builder().status(502).body(()).unwrap())
                .await;
            let _ = stream.finish().await;
            return Ok(());
        }
    };
    stream
        .send_response(http::Response::builder().status(200).body(()).unwrap())
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;

    let mut inbound = crate::dgram::register(&registry, stream_id).await;
    let mut buf = vec![0u8; 65535];
    // Re-check authorization on a timer (a revoked/over-cap user must stop, like the TCP relay).
    let mut revoke = tokio::time::interval(std::time::Duration::from_secs(2));
    revoke.tick().await;
    loop {
        tokio::select! {
            _ = revoke.tick() => {
                if !store.still_allowed(&sid, now_secs()) { break; }
            }
            // UP: client datagram → target.
            up = inbound.recv() => match up {
                Some(payload) => {
                    if let Some(tb) = &limits.up { tb.consume(payload.len() as u64).await; }
                    let _ = udp.send(&payload).await;
                    store.add_usage(&sid, payload.len() as u64, 0);
                }
                None => break,
            },
            // DOWN: target → client datagram.
            r = udp.recv(&mut buf) => match r {
                Ok(n) => {
                    if let Some(tb) = &limits.down { tb.consume(n as u64).await; }
                    let dg = crate::dgram::encode(stream_id, Bytes::copy_from_slice(&buf[..n]));
                    if dgram_conn.send_datagram(dg).is_err() { break; }
                    store.add_usage(&sid, 0, n as u64);
                }
                Err(_) => break,
            },
            // The client closing the request stream ends the association (UDP has no FIN).
            done = stream.recv_data() => match done {
                Ok(Some(_)) => {} // connect-udp carries no stream body; ignore stray data
                Ok(None) | Err(_) => break,
            },
        }
    }
    crate::dgram::deregister(&registry, stream_id).await;
    Ok(())
}
