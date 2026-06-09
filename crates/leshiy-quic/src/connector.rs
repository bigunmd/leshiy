//! ConnectorEgress: forward a target to an Exit B over a warm leshiy-quic (H3 CONNECT) connection.
//!
//! An Entry A instantiates [`ConnectorEgress`] with a pre-established QUIC connection to Exit B.
//! Every `egress.open(target)` call issues an H3 CONNECT on that connection and returns split
//! read/write halves backed by the h3 stream.  Enforcement (rate-limit, data-cap) stays at A.
use crate::client::{QuicConn, open_connect};
use bytes::{Buf, Bytes};
use leshiy_reality::egress::{Egress, EgressRead, EgressWrite};
use std::sync::Arc;

/// Egress that forwards to an Exit B over a warm H3 CONNECT connection.
pub struct ConnectorEgress {
    conn: Arc<QuicConn>,
}

impl ConnectorEgress {
    /// Establish the warm QUIC connection to Exit B.
    /// `connector_short_id` is A's credential on B.
    pub async fn connect(
        b_addr: std::net::SocketAddr,
        b_sni: &str,
        connector_short_id: [u8; 8],
        verification: crate::endpoint::CertVerification,
    ) -> crate::Result<Self> {
        let conn =
            crate::client::connect_quic(b_addr, b_sni, connector_short_id, verification).await?;
        Ok(ConnectorEgress {
            conn: Arc::new(conn),
        })
    }
}

#[async_trait::async_trait]
impl Egress for ConnectorEgress {
    async fn open(
        &self,
        target: &str,
    ) -> leshiy_reality::Result<(Box<dyn EgressRead>, Box<dyn EgressWrite>)> {
        let (send, recv) = open_connect(&self.conn, target)
            .await
            .map_err(|e| leshiy_reality::RealityError::Malformed(format!("connector: {e}")))?;
        Ok((
            Box::new(H3EgressRead {
                recv,
                buf: Bytes::new(),
            }),
            Box::new(H3EgressWrite { send }),
        ))
    }
}

// ---------------------------------------------------------------------------
// H3EgressRead — wraps the recv half; buffers leftover bytes across read calls.
// ---------------------------------------------------------------------------

struct H3EgressRead {
    recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    /// Buffered bytes from the last DATA frame not yet consumed by a read call.
    buf: Bytes,
}

#[async_trait::async_trait]
impl EgressRead for H3EgressRead {
    async fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // Refill buffer if empty.
        if !self.buf.has_remaining() {
            match self
                .recv
                .recv_data()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?
            {
                Some(chunk) => {
                    // Copy the chunk bytes into an owned Bytes so we can advance independently.
                    self.buf = Bytes::copy_from_slice(chunk.chunk());
                }
                None => return Ok(0), // EOF
            }
        }
        // Drain up to out.len() bytes from the buffer.
        let n = out.len().min(self.buf.remaining());
        self.buf.copy_to_slice(&mut out[..n]);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// H3EgressWrite — wraps the send half.
// ---------------------------------------------------------------------------

struct H3EgressWrite {
    send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
}

#[async_trait::async_trait]
impl EgressWrite for H3EgressWrite {
    async fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.send
            .send_data(Bytes::copy_from_slice(b))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.send
            .finish()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}
