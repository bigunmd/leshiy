//! One MTProxy session: answer the fake-TLS handshake, open the DC, pump bytes both ways.
use super::{Authenticated, faketls, obfs2};
use crate::egress::Egress;
use crate::error::{RealityError, Result};
use ctr::cipher::StreamCipher;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Bound on each handshake read (dest flight, client obfuscated2 header), matching the REALITY
/// path: a stalled peer must not pin a connection slot forever.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve an authenticated Telegram client. `dest` is the borrowed site that already received
/// the ClientHello; its answer shapes ours and it is then dropped, as on the REALITY path.
pub(crate) async fn serve<S, D>(
    mut client: S,
    mut dest: D,
    auth: Authenticated,
    egress: Arc<dyn Egress>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let flight = tokio::time::timeout(HANDSHAKE_TIMEOUT, faketls::read_dest_flight(&mut dest))
        .await
        .ok()
        .flatten();
    let _ = dest.shutdown().await;
    drop(dest);
    let Some(flight) = flight else {
        return Ok(());
    };
    let secret = auth.secret.bytes();
    let response = faketls::server_response(&auth.digest, &flight, secret, &mut rand::rngs::OsRng)
        .ok_or_else(|| RealityError::Malformed("mtproxy server hello".into()))?;
    client.write_all(&response).await?;
    client.flush().await?;

    let (mut cr, mut cw) = tokio::io::split(client);
    let Ok(Some((hs, mut early))) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, read_obfs2_header(&mut cr)).await
    else {
        return Ok(());
    };
    // Past the MAC check only a holder of the secret gets here, so failures just end the session.
    let Some(session) = obfs2::accept_client(&hs, secret) else {
        return Ok(());
    };
    let Some(dc) = obfs2::dc_addr(session.dc) else {
        tracing::debug!(dc = session.dc, "mtproxy: unsupported dc");
        return Ok(());
    };
    let (mut tr, mut tw) = egress.open(dc).await?;
    let upstream = obfs2::upstream(&mut rand::rngs::OsRng);
    let (mut cli, mut tg) = (session.ciphers, upstream.ciphers);
    tw.write_all(&upstream.hello).await?;
    if !early.is_empty() {
        cli.dec.apply_keystream(&mut early);
        tg.enc.apply_keystream(&mut early);
        tw.write_all(&early).await?;
    }

    let to_telegram = async {
        while let Some(mut b) = faketls::read_app_data(&mut cr).await {
            cli.dec.apply_keystream(&mut b);
            tg.enc.apply_keystream(&mut b);
            if tw.write_all(&b).await.is_err() {
                break;
            }
        }
        let _ = tw.shutdown().await;
    };
    let to_client = async {
        let mut buf = vec![0u8; leshiy_tls::record::MAX_RECORD_PAYLOAD];
        loop {
            let n = match tr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];
            tg.dec.apply_keystream(chunk);
            cli.enc.apply_keystream(chunk);
            if faketls::write_app_data(&mut cw, chunk).await.is_err() {
                break;
            }
        }
    };
    // Either side finishing ends the session; there is no half-close in MTProto.
    tokio::select! {
        _ = to_telegram => {}
        _ = to_client => {}
    }
    Ok(())
}

/// The 64-byte obfuscated2 header plus whatever the client sent after it in the same records.
async fn read_obfs2_header<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Option<([u8; obfs2::HANDSHAKE_LEN], Vec<u8>)> {
    let mut buf = Vec::new();
    while buf.len() < obfs2::HANDSHAKE_LEN {
        buf.extend_from_slice(&faketls::read_app_data(r).await?);
    }
    let rest = buf.split_off(obfs2::HANDSHAKE_LEN);
    Some((buf.try_into().ok()?, rest))
}
