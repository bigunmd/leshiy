//! REALITY client CLI: parse the URI and run the SOCKS5-fronted tunnel.
use anyhow::{Context, Result};
use leshiy_reality::client::run_reality_client;
use leshiy_reality::config::RealityUri;

pub async fn run(uri: &str, socks: &str) -> Result<()> {
    let parsed = RealityUri::parse(uri).map_err(|e| anyhow::anyhow!("bad uri: {e}"))?;
    tracing::info!(server = %parsed.server_addr, %socks, "leshiy REALITY client up");
    run_reality_client(&parsed.server_addr, parsed.client, socks)
        .await
        .context("client error")
}
