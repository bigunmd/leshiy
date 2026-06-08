//! REALITY client CLI: parse the URI and run the SOCKS5-fronted tunnel.
use crate::cli::Transport;
use anyhow::{Result, anyhow};
use leshiy_reality::client::run_reality_client;
use leshiy_reality::config::RealityUri;

pub async fn run(uri: &str, socks: &str, transport: Transport) -> Result<()> {
    let parsed = RealityUri::parse(uri).map_err(|e| anyhow!("bad uri: {e}"))?;
    match transport {
        Transport::Quic => {
            let q = parsed
                .quic
                .ok_or_else(|| anyhow!("--transport quic but the URI has no quic= endpoint"))?;
            let verification = match q.cert_sha256 {
                Some(pin) => leshiy_quic::endpoint::CertVerification::Pinned(pin),
                None => leshiy_quic::endpoint::CertVerification::Roots {
                    server_name: q.sni.clone(),
                },
            };
            let addr: std::net::SocketAddr = tokio::net::lookup_host(&q.addr)
                .await
                .map_err(|e| anyhow!("resolve quic addr {}: {e}", q.addr))?
                .next()
                .ok_or_else(|| anyhow!("resolve quic addr: no addresses for {}", q.addr))?;
            let socks_a: std::net::SocketAddr =
                socks.parse().map_err(|e| anyhow!("bad socks addr: {e}"))?;
            tracing::info!(server = %addr, quic_sni = %q.sni, %socks_a, "leshiy QUIC client up");
            leshiy_quic::client::run_quic_client(
                addr,
                &q.sni,
                socks_a,
                parsed.client.short_id,
                verification,
            )
            .await
            .map_err(|e| anyhow!("quic client: {e}"))
        }
        Transport::Tcp | Transport::Auto => {
            tracing::info!(server = %parsed.server_addr, %socks, "leshiy REALITY client up");
            run_reality_client(&parsed.server_addr, parsed.client, socks)
                .await
                .map_err(|e| anyhow!("client: {e}"))
        }
    }
}
