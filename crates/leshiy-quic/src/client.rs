//! QUIC client: SOCKS5 inbound proxy forwarded over QUIC bi-streams.
use crate::codec::encode_target;
use crate::{QuicError, Result};
use leshiy_reality::client::socks5_accept;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn run_quic_client(
    server_addr: SocketAddr,
    server_name: &str,
    socks_addr: SocketAddr,
    short_id: [u8; 8],
    insecure_skip_verify: bool,
) -> Result<()> {
    let ep = crate::endpoint::client_endpoint(insecure_skip_verify)?;
    let conn = ep
        .connect(server_addr, server_name)
        .map_err(|e| QuicError::Conn(e.to_string()))?
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;

    // auth: send our short_id on a uni stream
    let mut auth = conn
        .open_uni()
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    auth.write_all(&short_id)
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    // finish() is NOT async in quinn 0.11 — returns Result<(), ClosedStream>
    let _ = auth.finish();

    let listener = TcpListener::bind(socks_addr).await?;
    let conn = Arc::new(conn);
    loop {
        let (cli, _) = listener.accept().await?;
        cli.set_nodelay(true).ok();
        let conn = conn.clone();
        tokio::spawn(async move {
            let Ok((target, cli)) = socks5_accept(cli).await.map_err(|_| ()) else {
                return;
            };
            let Ok((mut send, mut recv)) = conn.open_bi().await.map_err(|_| ()) else {
                return;
            };
            if send.write_all(&encode_target(&target)).await.is_err() {
                return;
            }
            let _ = pipe(cli, &mut send, &mut recv).await;
        });
    }
}

async fn pipe(
    cli: tokio::net::TcpStream,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<()> {
    let (mut cr, mut cw) = cli.into_split();

    let c2q = async {
        let mut b = vec![0u8; 16384];
        loop {
            let n = cr.read(&mut b).await?;
            if n == 0 {
                break;
            }
            send.write_all(&b[..n])
                .await
                .map_err(|e| QuicError::Conn(e.to_string()))?;
        }
        let _ = send.finish();
        Ok::<(), QuicError>(())
    };

    let q2c = async {
        let mut b = vec![0u8; 16384];
        while let Some(n) = recv
            .read(&mut b)
            .await
            .map_err(|e| QuicError::Conn(e.to_string()))?
        {
            cw.write_all(&b[..n]).await?;
        }
        Ok::<(), QuicError>(())
    };

    let _ = tokio::try_join!(c2q, q2c);
    Ok(())
}
