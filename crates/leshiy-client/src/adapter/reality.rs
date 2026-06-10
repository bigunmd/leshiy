//! REALITY transport adapter: wraps `RealityConn` and its mux `Stream`.
use crate::error::{ClientError, Result};
use crate::stream::ProxyStream;
use crate::transport::Tunnel;
use async_trait::async_trait;
use leshiy_reality::client::RealityConn;

/// `ProxyStream` over a REALITY mux stream.
struct MuxProxyStream(leshiy_core::mux::Stream);

#[async_trait]
impl ProxyStream for MuxProxyStream {
    async fn send(&mut self, data: Vec<u8>) -> Result<()> {
        self.0
            .send(data)
            .await
            .map_err(|_| ClientError::ConnectFailed)
    }
    async fn recv(&mut self) -> Result<Vec<u8>> {
        self.0.recv().await.map_err(|_| ClientError::ConnectFailed)
    }
    async fn close(&mut self) -> Result<()> {
        self.0.close().await.map_err(|_| ClientError::ConnectFailed)
    }
}

/// A live REALITY tunnel.
pub struct RealityTunnel {
    pub(crate) conn: RealityConn,
}

#[async_trait]
impl Tunnel for RealityTunnel {
    async fn open(&self, target: &str) -> Result<Box<dyn ProxyStream>> {
        let stream = self
            .conn
            .open(target)
            .await
            .map_err(|_| ClientError::ConnectFailed)?;
        Ok(Box::new(MuxProxyStream(stream)))
    }
    async fn closed(&self) {
        self.conn.closed().await;
    }
}
