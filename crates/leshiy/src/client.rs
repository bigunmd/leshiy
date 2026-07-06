//! REALITY client CLI: parse the URI and run the SOCKS5-fronted tunnel.
use anyhow::{Context, Result, anyhow};
use leshiy_reality::config::{QuicEndpoint, RealityUri};
use std::time::Duration;

const HEAD_START: Duration = Duration::from_millis(200);
const QUIC_TIMEOUT: Duration = Duration::from_secs(3);
const REALITY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run(uri: &str, socks: &str, transport: crate::cli::Transport) -> Result<()> {
    use crate::cli::Transport;
    let parsed = RealityUri::parse(uri).map_err(|e| anyhow!("bad uri: {e}"))?;
    crate::ui::ok(&format!(
        "local SOCKS5 proxy on {}",
        crate::ui::value(socks)
    ));
    crate::ui::hint(&format!(
        "point your browser/app at socks5://{socks} (Ctrl-C to stop)"
    ));
    match transport {
        Transport::Quic => serve_quic(&parsed, socks).await,
        Transport::Tcp => serve_reality(&parsed, socks).await,
        Transport::Auto => {
            let Some(q) = parsed.quic.clone() else {
                return serve_reality(&parsed, socks).await;
            };
            // Pre-warm REALITY after a head start; prefer QUIC.
            let (raddr, rcfg, rsocks) = (
                parsed.server_addr.clone(),
                parsed.client.clone(),
                socks.to_string(),
            );
            let reality = tokio::spawn(async move {
                tokio::time::sleep(HEAD_START).await;
                match tokio::time::timeout(
                    REALITY_CONNECT_TIMEOUT,
                    leshiy_reality::client::connect_reality(&raddr, rcfg),
                )
                .await
                {
                    Ok(r) => r.map_err(|e| anyhow::anyhow!("reality connect: {e}")),
                    Err(_) => Err(anyhow::anyhow!("reality connect timed out")),
                }
            });
            let qconn =
                tokio::time::timeout(QUIC_TIMEOUT, connect_quic_from(&q, parsed.client.short_id))
                    .await;
            match qconn {
                Ok(Ok(c)) => {
                    // QUIC reachable → use it
                    reality.abort();
                    tracing::info!("transport=auto: using QUIC");
                    let socks_a: std::net::SocketAddr = socks.parse().context("socks addr")?;
                    leshiy_quic::client::serve_socks5(c, socks_a)
                        .await
                        .map_err(|e| anyhow!("quic: {e}"))
                }
                _ => {
                    // QUIC blocked/failed → REALITY (pre-warmed)
                    tracing::info!("transport=auto: QUIC unavailable, falling back to REALITY");
                    let conn = reality.await.context("reality task")??;
                    leshiy_reality::client::serve_socks5(conn, &rsocks)
                        .await
                        .map_err(|e| anyhow!("reality: {e}"))
                }
            }
        }
    }
}

async fn connect_quic_from(
    q: &QuicEndpoint,
    short_id: [u8; 8],
) -> Result<leshiy_quic::client::QuicConn> {
    // M2: refuse to fall back to public-CA validation — the cert pin (qcert=) is
    // the QUIC transport's only strong server binding. Without it, surface a clear
    // error instead of silently downgrading.
    let verification = match q.cert_sha256 {
        Some(p) => leshiy_quic::endpoint::CertVerification::Pinned(p),
        None => {
            return Err(anyhow!(
                "QUIC endpoint has no qcert= pin; refusing public-CA fallback (add qcert= or use the REALITY transport)"
            ));
        }
    };
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&q.addr).await?.collect();
    if addrs.is_empty() {
        return Err(anyhow!("resolve quic addr {}", q.addr));
    }
    leshiy_quic::client::connect_quic_multi(&addrs, &q.sni, short_id, verification)
        .await
        .map_err(|e| anyhow!("quic connect: {e}"))
}

async fn serve_quic(parsed: &RealityUri, socks: &str) -> Result<()> {
    let q = parsed
        .quic
        .clone()
        .ok_or_else(|| anyhow!("--transport quic but the URI has no quic= endpoint"))?;
    let c = connect_quic_from(&q, parsed.client.short_id).await?;
    let socks_a: std::net::SocketAddr = socks.parse().context("socks addr")?;
    leshiy_quic::client::serve_socks5(c, socks_a)
        .await
        .map_err(|e| anyhow!("quic: {e}"))
}

async fn serve_reality(parsed: &RealityUri, socks: &str) -> Result<()> {
    let conn = leshiy_reality::client::connect_reality(&parsed.server_addr, parsed.client.clone())
        .await
        .map_err(|e| anyhow!("reality connect: {e}"))?;
    leshiy_reality::client::serve_socks5(conn, socks)
        .await
        .map_err(|e| anyhow!("reality: {e}"))
}
