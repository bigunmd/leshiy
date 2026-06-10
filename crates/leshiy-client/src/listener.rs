//! Local SOCKS5 listener that forwards each CONNECT over a `Tunnel`, metering bytes.
use crate::error::Result;
use crate::pump::pump;
use crate::stats::ByteCounters;
use crate::transport::Tunnel;
use leshiy_reality::client::socks5_accept;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Bind a SOCKS5 listener on `socks_addr` and forward every CONNECT over `tunnel`,
/// tallying bytes both directions into `counters`. Runs until the listener errors
/// (or the task is aborted by the supervisor on disconnect).
pub async fn serve_metered(
    tunnel: Arc<dyn Tunnel>,
    socks_addr: SocketAddr,
    counters: Arc<ByteCounters>,
) -> Result<()> {
    let listener = TcpListener::bind(socks_addr).await?;
    loop {
        let (cli, _) = listener.accept().await?;
        cli.set_nodelay(true).ok();
        let tunnel = tunnel.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            if let Ok((target, cli)) = socks5_accept(cli).await
                && let Ok(mut stream) = tunnel.open(&target).await
            {
                let _ = pump(cli, &mut *stream, counters).await;
            }
        });
    }
}
