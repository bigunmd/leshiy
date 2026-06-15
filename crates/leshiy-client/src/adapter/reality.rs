//! REALITY transport adapter: wraps `RealityConn` and its mux `Stream`.
use crate::error::{ClientError, Result};
use crate::stream::{DatagramFlow, ProxyStream};
use crate::transport::Tunnel;
use async_trait::async_trait;
use leshiy_reality::client::RealityConn;

/// `ProxyStream` over a REALITY mux stream.
struct MuxProxyStream(leshiy_core::mux::Stream);

/// `DatagramFlow` over a REALITY mux datagram stream.
struct MuxDatagramFlow(leshiy_core::mux::Stream);

#[async_trait]
impl DatagramFlow for MuxDatagramFlow {
    async fn send(&mut self, data: bytes::Bytes) -> Result<()> {
        self.0
            .send(data)
            .await
            .map_err(|_| ClientError::ConnectFailed)
    }
    async fn recv(&mut self) -> Result<bytes::Bytes> {
        self.0.recv().await.map_err(|_| ClientError::ConnectFailed)
    }
    async fn close(&mut self) -> Result<()> {
        self.0.close().await.map_err(|_| ClientError::ConnectFailed)
    }
}

#[async_trait]
impl ProxyStream for MuxProxyStream {
    async fn send(&mut self, data: bytes::Bytes) -> Result<()> {
        self.0
            .send(data)
            .await
            .map_err(|_| ClientError::ConnectFailed)
    }
    async fn recv(&mut self) -> Result<bytes::Bytes> {
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
    async fn open_datagram(&self, target: &str) -> Result<Box<dyn DatagramFlow>> {
        let stream = self
            .conn
            .open_datagram(target)
            .await
            .map_err(|_| ClientError::ConnectFailed)?;
        Ok(Box::new(MuxDatagramFlow(stream)))
    }
    async fn closed(&self) {
        self.conn.closed().await;
    }
}
