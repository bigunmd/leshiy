use crate::{QuicError, Result};
use bytes::{Buf, Bytes};
use http::Method;
use leshiy_reality::client::socks5_accept;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Run the QUIC client: connect to `server_addr` using the given `verification` strategy,
/// then listen on `socks_addr` and proxy SOCKS5 CONNECT requests over the QUIC connection.
/// The `short_id` is sent as a hex `leshiy-auth` header on each tunnel request.
pub async fn run_quic_client(
    server_addr: SocketAddr,
    server_name: &str,
    socks_addr: SocketAddr,
    short_id: [u8; 8],
    verification: crate::endpoint::CertVerification,
) -> Result<()> {
    let ep = crate::endpoint::client_endpoint(verification)?;
    let conn = ep
        .connect(server_addr, server_name)
        .map_err(|e| QuicError::Conn(e.to_string()))?
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    let (mut driver, send_req) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| QuicError::Conn(e.to_string()))?;
    // The driver MUST stay alive for the whole connection — poll it forever.
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let auth = hex::encode(short_id);

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
