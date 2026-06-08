//! QUIC/HTTP3 server: h3 dispatch, CONNECT auth tunnel + web masquerade (ADR-0019, ADR-0023).
use crate::masquerade::Masquerade;
use crate::{QuicError, Result};
use bytes::{Buf, Bytes};
use http::{Method, StatusCode};
use leshiy_reality::netguard::resolve_checked;
use leshiy_reality::user::{UserLimits, UserStore};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
) -> Result<()> {
    let ep = crate::endpoint::server_endpoint(listen, certs, key)?;
    while let Some(incoming) = ep.accept().await {
        let (store, masq) = (store.clone(), masquerade.clone());
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                let _ = serve_h3_conn(conn, store, masq).await;
            }
        });
    }
    Ok(())
}

async fn serve_h3_conn(
    conn: quinn::Connection,
    store: Arc<dyn UserStore>,
    masq: Masquerade,
) -> Result<()> {
    let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    while let Ok(Some(resolver)) = h3.accept().await {
        let (req, stream) = match resolver.resolve_request().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let (store, masq) = (store.clone(), masq.clone());
        tokio::spawn(async move {
            let _ = handle_request(req, stream, store, masq).await;
        });
    }
    Ok(())
}

async fn handle_request(
    req: http::Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    store: Arc<dyn UserStore>,
    masq: Masquerade,
) -> Result<()> {
    if *req.method() == Method::CONNECT
        && let Some(sid) = auth_short_id(&req)
        && let Some(limits) = store.authorize(&sid, now_secs())
        && let Some(target) = req.uri().authority().map(|a| a.as_str().to_string())
    {
        return tunnel(stream, &target, sid, limits, store).await;
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
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    masq: Masquerade,
) -> Result<()> {
    let Masquerade::Page(html) = masq;
    let (status, body) = if req.uri().path() == "/" {
        (StatusCode::OK, html)
    } else {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    };
    let resp = http::Response::builder().status(status).body(()).unwrap();
    stream
        .send_response(resp)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    stream
        .send_data(Bytes::from(body))
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
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
) -> Result<()> {
    // SSRF guard + dial.
    let addr: SocketAddr = resolve_checked(target)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    let upstream = TcpStream::connect(addr).await?;
    upstream.set_nodelay(true).ok();

    // Send 200, then bidirectional relay over the split h3 stream.
    let mut stream = stream;
    stream
        .send_response(http::Response::builder().status(200).body(()).unwrap())
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;

    // split() -> (RequestStream<SendStream<Bytes>, Bytes>, RequestStream<RecvStream, Bytes>)
    let (mut send, mut recv) = stream.split();
    let (mut ur, mut uw) = upstream.into_split();

    const FLUSH: u64 = 64 * 1024;

    // DOWN: target -> client (send_data).
    let down = {
        let store = store.clone();
        async move {
            let mut acc = 0u64;
            let mut buf = vec![0u8; 16384];
            loop {
                let n = ur.read(&mut buf).await?;
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
        while let Some(mut chunk) = recv
            .recv_data()
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?
        {
            while chunk.has_remaining() {
                let c = chunk.chunk();
                let n = c.len();
                uw.write_all(c).await?;
                if let Some(tb) = &limits.up {
                    tb.consume(n as u64).await;
                }
                chunk.advance(n);
                acc += n as u64;
                if acc >= FLUSH {
                    store.add_usage(&sid, acc, 0);
                    acc = 0;
                    if !store.still_allowed(&sid, now_secs()) {
                        break;
                    }
                }
            }
        }
        store.add_usage(&sid, acc, 0);
        Ok::<(), QuicError>(())
    };

    let _ = tokio::join!(down, up);
    Ok(())
}
