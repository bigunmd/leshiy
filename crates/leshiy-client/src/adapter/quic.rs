//! QUIC transport adapter: wraps `QuicConn` and its h3 CONNECT streams.
use crate::error::{ClientError, Result};
use crate::stream::ProxyStream;
use crate::transport::Tunnel;
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use leshiy_quic::client::{QuicConn, open_connect};

/// `ProxyStream` over an h3 CONNECT stream pair.
struct QuicProxyStream {
    send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
}

#[async_trait]
impl ProxyStream for QuicProxyStream {
    async fn send(&mut self, data: Vec<u8>) -> Result<()> {
        self.send
            .send_data(Bytes::from(data))
            .await
            .map_err(|_| ClientError::ConnectFailed)
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        match self.recv.recv_data().await {
            Ok(Some(mut chunk)) => {
                let mut out = Vec::with_capacity(chunk.remaining());
                while chunk.has_remaining() {
                    let c = chunk.chunk();
                    out.extend_from_slice(c);
                    let n = c.len();
                    chunk.advance(n);
                }
                Ok(out)
            }
            Ok(None) => Ok(Vec::new()), // graceful EOF
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
    async fn closed(&self) {
        self.conn.closed().await;
    }
}
