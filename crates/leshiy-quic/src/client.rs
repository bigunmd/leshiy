use crate::{QuicError, Result};
use bytes::{Buf, Bytes};
use http::Method;
use leshiy_reality::client::socks5_accept;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A live QUIC connection, ready to issue HTTP/3 CONNECT tunnels.
/// The embedded driver task lives as long as this value is alive.
/// Dropping `QuicConn` lets the connection close gracefully.
pub struct QuicConn {
    pub(crate) send_req: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(crate) short_id: [u8; 8],
    pub(crate) closed: tokio::sync::watch::Receiver<bool>,
    /// Raw QUIC connection for CONNECT-UDP datagram I/O (the h3 driver owns the wrapped one).
    pub(crate) dgram_conn: quinn::Connection,
    /// Demux table routing inbound datagrams to their per-target association channels.
    pub(crate) registry: crate::dgram::DatagramRegistry,
}

impl QuicConn {
    /// Resolves once the QUIC connection has closed (its h3 driver finished).
    /// Used by the supervisor to trigger reconnect.
    pub async fn closed(&self) {
        let mut rx = self.closed.clone();
        let _ = rx.wait_for(|v| *v).await;
    }

    /// Open a CONNECT-UDP association (RFC 9298) to `target` ("host:port") and return a
    /// [`QuicDatagramFlow`] carrying UDP datagrams both ways over HTTP/3 datagrams.
    pub async fn open_datagram(&self, target: &str) -> Result<QuicDatagramFlow> {
        let auth = hex::encode(self.short_id);
        let mut send_req = self.send_req.clone();
        // Extended CONNECT: method CONNECT + `:protocol = connect-udp` (carried in extensions).
        let req = http::Request::builder()
            .method(Method::CONNECT)
            .uri(target)
            .header("leshiy-auth", &auth)
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .body(())
            .map_err(|e| QuicError::Conn(e.to_string()))?;
        let mut stream = send_req
            .send_request(req)
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?;
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?;
        if resp.status() != 200 {
            return Err(QuicError::ConnectStatus(resp.status().as_u16()));
        }
        let stream_id = stream.id();
        let inbound = crate::dgram::register(&self.registry, stream_id).await;
        Ok(QuicDatagramFlow {
            dgram_conn: self.dgram_conn.clone(),
            registry: self.registry.clone(),
            stream_id,
            inbound,
            _stream: stream,
        })
    }
}

/// A live CONNECT-UDP association: `send` puts a UDP datagram to the target, `recv` yields one
/// back. Holds the request stream open for the association's lifetime — dropping this ends it.
pub struct QuicDatagramFlow {
    dgram_conn: quinn::Connection,
    registry: crate::dgram::DatagramRegistry,
    stream_id: h3::quic::StreamId,
    inbound: tokio::sync::mpsc::Receiver<Bytes>,
    /// Kept alive so the server keeps the association open; closing it tears the association down.
    _stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

impl QuicDatagramFlow {
    /// Send one UDP datagram to the association's target.
    pub async fn send(&self, payload: Bytes) -> Result<()> {
        let dg = crate::dgram::encode(self.stream_id, payload);
        self.dgram_conn
            .send_datagram(dg)
            .map_err(|e| QuicError::Conn(e.to_string()))
    }

    /// Receive the next UDP datagram from the target. `None` once the connection/association ends.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.inbound.recv().await
    }
}

impl Drop for QuicDatagramFlow {
    fn drop(&mut self) {
        // Remove our demux entry so the table doesn't accumulate stale associations over a
        // long-lived connection. Deregistration is async; do it detached (best-effort).
        let (registry, stream_id) = (self.registry.clone(), self.stream_id);
        tokio::spawn(async move {
            crate::dgram::deregister(&registry, stream_id).await;
        });
    }
}

/// Establish a QUIC connection to `server_addr` and return a [`QuicConn`].
/// The HTTP/3 connection driver is spawned onto the Tokio runtime and runs
/// for the lifetime of the returned handle.
pub async fn connect_quic(
    server_addr: SocketAddr,
    server_name: &str,
    short_id: [u8; 8],
    verification: crate::endpoint::CertVerification,
) -> Result<QuicConn> {
    let ep = crate::endpoint::client_endpoint(verification, server_addr)?;
    let conn = ep
        .connect(server_addr, server_name)
        .map_err(|e| QuicError::Conn(e.to_string()))?
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    // Keep a clone of the raw QUIC connection for CONNECT-UDP datagram I/O; the h3 driver owns the
    // wrapped one. Enable extended CONNECT (to send `:protocol=connect-udp`) and H3 datagrams.
    let dgram_conn = conn.clone();
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (mut driver, send_req): (
        h3::client::Connection<h3_quinn::Connection, Bytes>,
        _,
    ) = builder
        .build(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    // The driver MUST stay alive for the whole connection — poll it forever.
    // When it completes, the connection has closed: flip the `closed` signal.
    let (closed_tx, closed_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        let _ = closed_tx.send(true);
    });
    // One demux task per connection fans inbound datagrams out to their per-target associations.
    let registry = crate::dgram::new_registry();
    tokio::spawn(crate::dgram::demux_loop(dgram_conn.clone(), registry.clone()));
    Ok(QuicConn {
        send_req,
        short_id,
        closed: closed_rx,
        dgram_conn,
        registry,
    })
}

/// Try each resolved address in turn (e.g. AAAA then A), returning the first QUIC connection
/// that establishes. A leading unreachable address — an AAAA on an IPv4-only host — then falls
/// through to the next instead of failing the whole dial.
pub async fn connect_quic_multi(
    addrs: &[SocketAddr],
    server_name: &str,
    short_id: [u8; 8],
    verification: crate::endpoint::CertVerification,
) -> Result<QuicConn> {
    let mut last: Option<QuicError> = None;
    for &addr in addrs {
        match connect_quic(addr, server_name, short_id, verification.clone()).await {
            Ok(c) => return Ok(c),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| QuicError::Conn("no address resolved".into())))
}

/// Bind a SOCKS5 listener on `socks_addr` and forward every CONNECT request
/// over the established QUIC connection.
pub async fn serve_socks5(conn: QuicConn, socks_addr: SocketAddr) -> Result<()> {
    let auth = hex::encode(conn.short_id);
    let send_req = conn.send_req;
    let listener = TcpListener::bind(socks_addr).await?;
    loop {
        let (cli, _) = listener.accept().await?;
        cli.set_nodelay(true).ok();
        // Clone the sender — SendRequest<h3_quinn::OpenStreams, Bytes> is Clone.
        let send_req = send_req.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let Ok((target, cli)) = socks5_accept(cli).await.map_err(|_| ()) else {
                return;
            };
            let _ = tunnel_one(send_req, &auth, &target, cli).await;
        });
    }
}

/// Run the QUIC client: connect to `server_addr` using the given `verification` strategy,
/// then listen on `socks_addr` and proxy SOCKS5 CONNECT requests over the QUIC connection.
/// The `short_id` is sent as a hex `leshiy-auth` header on each tunnel request.
///
/// This is a convenience compose of [`connect_quic`] + [`serve_socks5`].
pub async fn run_quic_client(
    server_addr: SocketAddr,
    server_name: &str,
    socks_addr: SocketAddr,
    short_id: [u8; 8],
    verification: crate::endpoint::CertVerification,
) -> Result<()> {
    serve_socks5(
        connect_quic(server_addr, server_name, short_id, verification).await?,
        socks_addr,
    )
    .await
}

/// Open an H3 CONNECT tunnel to `target` on the given [`QuicConn`] and return the
/// split send/recv halves.  This is the same CONNECT handshake as `tunnel_one` but
/// returns the stream halves instead of piping a TcpStream — used by `ConnectorEgress`.
pub async fn open_connect(
    conn: &QuicConn,
    target: &str,
) -> Result<(
    h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
)> {
    let auth = hex::encode(conn.short_id);
    let mut send_req = conn.send_req.clone();
    let req = http::Request::builder()
        .method(Method::CONNECT)
        .uri(target)
        .header("leshiy-auth", &auth)
        .body(())
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    let mut stream = send_req
        .send_request(req)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    if resp.status() != 200 {
        // Per-stream failure on a HEALTHY connection (e.g. the Exit's egress replied
        // 502 because netguard blocked the target). Typed so the caller does NOT tear
        // down the whole connector connection over a single bad target.
        return Err(QuicError::ConnectStatus(resp.status().as_u16()));
    }
    Ok(stream.split())
}

async fn tunnel_one(
    mut send_req: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    auth: &str,
    target: &str,
    cli: tokio::net::TcpStream,
) -> Result<()> {
    let req = http::Request::builder()
        .method(Method::CONNECT)
        .uri(target)
        .header("leshiy-auth", auth)
        .body(())
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    let mut stream = send_req
        .send_request(req)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    if resp.status() != 200 {
        return Err(QuicError::Conn(format!("connect status {}", resp.status())));
    }
    let (mut send, mut recv) = stream.split();
    let (mut cr, mut cw) = cli.into_split();
    let c2q = async move {
        let mut b = vec![0u8; 16384];
        loop {
            let n = cr.read(&mut b).await?;
            if n == 0 {
                break;
            }
            send.send_data(Bytes::copy_from_slice(&b[..n]))
                .await
                .map_err(|e| QuicError::Conn(e.to_string()))?;
        }
        let _ = send.finish().await;
        Ok::<(), QuicError>(())
    };
    let q2c = async move {
        while let Some(mut chunk) = recv
            .recv_data()
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?
        {
            while chunk.has_remaining() {
                let c = chunk.chunk();
                let n = c.len();
                cw.write_all(c).await?;
                chunk.advance(n);
            }
        }
        Ok::<(), QuicError>(())
    };
    let _ = tokio::join!(c2q, q2c);
    Ok(())
}
