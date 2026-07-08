//! QUIC transport adapter: wraps `QuicConn` and its h3 CONNECT streams.
use crate::error::{ClientError, Result};
use crate::stream::{DatagramFlow, ProxyStream};
use crate::transport::Tunnel;
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use leshiy_quic::client::{QuicConn, QuicDatagramFlow, open_connect};

/// `ProxyStream` over an h3 CONNECT stream pair.
struct QuicProxyStream {
    send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
}

#[async_trait]
impl ProxyStream for QuicProxyStream {
    async fn send(&mut self, data: Bytes) -> Result<()> {
        self.send
            .send_data(data)
            .await
            .map_err(|_| ClientError::ConnectFailed)
    }

    async fn recv(&mut self) -> Result<Bytes> {
        match self.recv.recv_data().await {
            Ok(Some(mut chunk)) => {
                // h3 yields a `Buf`; the common single-chunk case returns its
                // backing `Bytes` without an extra copy.
                let n = chunk.remaining();
                Ok(chunk.copy_to_bytes(n))
            }
            Ok(None) => Ok(Bytes::new()), // graceful EOF
            Err(_) => Err(ClientError::ConnectFailed),
        }
    }

    async fn close(&mut self) -> Result<()> {
        let _ = self.send.finish().await;
        Ok(())
    }
}

/// A live QUIC tunnel.
pub struct QuicTunnel {
    pub(crate) conn: QuicConn,
}

#[async_trait]
impl Tunnel for QuicTunnel {
    async fn open(&self, target: &str) -> Result<Box<dyn ProxyStream>> {
        let (send, recv) = open_connect(&self.conn, target)
            .await
            .map_err(|_| ClientError::ConnectFailed)?;
        Ok(Box::new(QuicProxyStream { send, recv }))
    }
    async fn open_datagram(&self, target: &str) -> Result<Box<dyn DatagramFlow>> {
        let flow = self
            .conn
            .open_datagram(target)
            .await
            .map_err(|_| ClientError::ConnectFailed)?;
        Ok(Box::new(QuicDatagram { flow }))
    }
    async fn closed(&self) {
        self.conn.closed().await;
    }
}

/// `DatagramFlow` over a QUIC CONNECT-UDP association.
struct QuicDatagram {
    flow: QuicDatagramFlow,
}

#[async_trait]
impl DatagramFlow for QuicDatagram {
    async fn send(&mut self, data: Bytes) -> Result<()> {
        self.flow
            .send(data)
            .await
            .map_err(|_| ClientError::ConnectFailed)
    }
    async fn recv(&mut self) -> Result<Bytes> {
        match self.flow.recv().await {
            Some(b) => Ok(b),
            None => Ok(Bytes::new()), // association/connection closed
        }
    }
    async fn close(&mut self) -> Result<()> {
        // Dropping `QuicDatagramFlow` closes the underlying request stream and deregisters the
        // association; there's no separate graceful-close step.
        Ok(())
    }
}
