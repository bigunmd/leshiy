//! QUIC server: accept loop, short_id auth, per-user enforced stream relay (ADR-0019, ADR-0022).
use crate::codec::read_target;
use crate::{QuicError, Result};
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
) -> Result<()> {
    let ep = crate::endpoint::server_endpoint(listen, certs, key)?;
    while let Some(incoming) = ep.accept().await {
        let store = store.clone();
        tokio::spawn(async move {
            // Incoming implements IntoFuture -> Result<Connection, ConnectionError>
            if let Ok(conn) = incoming.await {
                let _ = serve_quic_conn(conn, store).await;
            }
        });
    }
    Ok(())
}

async fn serve_quic_conn(conn: quinn::Connection, store: Arc<dyn UserStore>) -> Result<()> {
    // M2a auth: client opens a uni stream carrying its 8-byte short_id.
    // Bounded by a timeout so half-open connections (never sending auth) can't pile up tasks.
    let mut sid = [0u8; 8];
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        // RecvStream implements AsyncRead, so AsyncReadExt::read_exact works.
        let mut auth = conn
            .accept_uni()
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?;
        auth.read_exact(&mut sid)
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?;
        Ok::<(), QuicError>(())
    })
    .await
    .map_err(|_| QuicError::Conn("auth timeout".into()))??;
    let limits = match store.authorize(&sid, now_secs()) {
        Some(l) => l,
        None => {
            // M2b: masquerade instead of bare close
            conn.close(1u32.into(), b"unauthorized");
            return Ok(());
        }
    };
    while let Ok((send, recv)) = conn.accept_bi().await {
        let (store, limits) = (store.clone(), limits.clone());
        tokio::spawn(async move {
            let _ = relay_quic_stream(send, recv, sid, limits, store).await;
        });
    }
    Ok(())
}

async fn relay_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    sid: [u8; 8],
    limits: UserLimits,
    store: Arc<dyn UserStore>,
) -> Result<()> {
    let target = read_target(&mut recv).await?;
    let addr = leshiy_reality::netguard::resolve_checked(&target)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    let upstream = TcpStream::connect(addr).await?;
    upstream.set_nodelay(true).ok();
    let (mut ur, mut uw) = upstream.into_split();
    const FLUSH: u64 = 64 * 1024;

    // DOWN: target -> QUIC client (send). UP: QUIC client (recv) -> target.
    let down = async {
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
            send.write_all(&buf[..n])
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
        let _ = send.finish();
        Ok::<(), QuicError>(())
    };

    let up = async {
        let mut acc = 0u64;
        let mut buf = vec![0u8; 16384];
        loop {
            // RecvStream::read returns Result<Option<usize>, ReadError>; None = stream end.
            let n = match recv
                .read(&mut buf)
                .await
                .map_err(|e| QuicError::Conn(e.to_string()))?
            {
                Some(n) => n,
                None => break,
            };
            if let Some(tb) = &limits.up {
                tb.consume(n as u64).await;
            }
            uw.write_all(&buf[..n]).await?;
            acc += n as u64;
            if acc >= FLUSH {
                store.add_usage(&sid, acc, 0);
                acc = 0;
                if !store.still_allowed(&sid, now_secs()) {
                    break;
                }
            }
        }
        store.add_usage(&sid, acc, 0);
        Ok::<(), QuicError>(())
    };

    let _ = tokio::try_join!(down, up);
    Ok(())
}
