//! ConnectorEgress: forward a target to an Exit B over a lazy-reconnectable leshiy-quic (H3 CONNECT) connection.
//!
//! An Entry A instantiates [`ConnectorEgress`] with an eagerly-established QUIC connection to
//! Exit B.  Every `egress.open(target)` call issues an H3 CONNECT on that connection and returns
//! split read/write halves backed by the h3 stream.  If the connection is dead, `open` silently
//! re-establishes it (mutex-serialized to avoid a stampede) and retries once.  Enforcement
//! (rate-limit, data-cap) stays at A.
use crate::client::{QuicConn, open_connect};
use bytes::{Buf, Bytes};
use leshiy_reality::egress::{Egress, EgressRead, EgressWrite};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Egress that forwards to an Exit B over a lazy-reconnectable H3 CONNECT connection.
pub struct ConnectorEgress {
    b_addr: std::net::SocketAddr,
    b_sni: String,
    short_id: [u8; 8],
    verification: crate::endpoint::CertVerification,
    /// Mutex-guarded live connection.  `None` means "needs reconnect".
    conn: Mutex<Option<Arc<QuicConn>>>,
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
        let c = Arc::new(
            crate::client::connect_quic(b_addr, b_sni, connector_short_id, verification.clone())
                .await?,
        );
        Ok(ConnectorEgress {
            b_addr,
            b_sni: b_sni.to_string(),
            short_id: connector_short_id,
            verification,
            conn: Mutex::new(Some(c)),
        })
    }

    /// Return the live connection, or establish a new one if `conn` is `None`.
    /// Holding the mutex across `connect_quic` serializes reconnects (no stampede).
    async fn get_or_connect(&self) -> crate::Result<Arc<QuicConn>> {
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let c = Arc::new(
            crate::client::connect_quic(
                self.b_addr,
                &self.b_sni,
                self.short_id,
                self.verification.clone(),
            )
            .await?,
        );
        *g = Some(c.clone());
        Ok(c)
    }

    /// Mark the connection as dead so the next `get_or_connect` will re-establish.
    async fn invalidate(&self) {
        *self.conn.lock().await = None;
    }
}

/// Wrap the raw `(send, recv)` halves into boxed egress trait objects.
fn wrap_halves(
    halves: (
        h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
        h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    ),
) -> (Box<dyn EgressRead>, Box<dyn EgressWrite>) {
    let (send, recv) = halves;
    (
        Box::new(H3EgressRead {
            recv,
            buf: Bytes::new(),
        }),
        Box::new(H3EgressWrite { send }),
    )
}

#[async_trait::async_trait]
impl Egress for ConnectorEgress {
    async fn open(
        &self,
        target: &str,
    ) -> leshiy_reality::Result<(Box<dyn EgressRead>, Box<dyn EgressWrite>)> {
        let conn = self.get_or_connect().await.map_err(|e| {
            leshiy_reality::RealityError::Malformed(format!("connector connect: {e}"))
        })?;
        match open_connect(&conn, target).await {
            Ok(halves) => Ok(wrap_halves(halves)),
            Err(_) => {
                // Connection is dead — invalidate and reconnect once (mutex-serialized).
                self.invalidate().await;
                let conn = self.get_or_connect().await.map_err(|e| {
                    leshiy_reality::RealityError::Malformed(format!("connector reconnect: {e}"))
                })?;
                let halves = open_connect(&conn, target).await.map_err(|e| {
                    leshiy_reality::RealityError::Malformed(format!("connector: {e}"))
                })?;
                Ok(wrap_halves(halves))
            }
        }
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
