//! Transport-agnostic tunneled byte stream.
//!
//! Plan 3 implements this for the REALITY mux `Stream` and the QUIC h3 CONNECT
//! stream; the metered pump and tests depend only on this trait.
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;

/// A bidirectional byte stream to one target ("host:port") inside a tunnel.
#[async_trait]
pub trait ProxyStream: Send {
    /// Send payload bytes toward the target.
    async fn send(&mut self, data: Bytes) -> Result<()>;
    /// Receive the next chunk from the target. An empty chunk **or** an `Err`
    /// is treated by callers as end-of-stream.
    async fn recv(&mut self) -> Result<Bytes>;
    /// Close the stream (best effort).
    async fn close(&mut self) -> Result<()>;
}

/// A bidirectional UDP datagram association to one target inside a tunnel.
/// Each `send`/`recv` carries exactly one datagram. `recv` returning an `Err`
/// is treated as end-of-association by callers.
#[async_trait]
pub trait DatagramFlow: Send {
    async fn send(&mut self, data: Bytes) -> Result<()>;
    async fn recv(&mut self) -> Result<Bytes>;
    async fn close(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ClientError;

    use bytes::Bytes;

    /// Minimal fake: yields queued chunks, then errors (EOF). Records what was sent.
    struct EchoOnce {
        outgoing_recorded: Vec<u8>,
        to_return: Option<Bytes>,
    }

    #[async_trait]
    impl ProxyStream for EchoOnce {
        async fn send(&mut self, data: Bytes) -> Result<()> {
            self.outgoing_recorded.extend_from_slice(&data);
            Ok(())
        }
        async fn recv(&mut self) -> Result<Bytes> {
            self.to_return.take().ok_or(ClientError::ConnectFailed)
        }
        async fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn datagram_flow_roundtrip() {
        struct Fake {
            last: Vec<u8>,
            ret: Option<Bytes>,
        }
        #[async_trait]
        impl DatagramFlow for Fake {
            async fn send(&mut self, d: Bytes) -> Result<()> {
                self.last = d.to_vec();
                Ok(())
            }
            async fn recv(&mut self) -> Result<Bytes> {
                self.ret.take().ok_or(ClientError::ConnectFailed)
            }
            async fn close(&mut self) -> Result<()> {
                Ok(())
            }
        }
        let mut f = Fake {
            last: vec![],
            ret: Some(Bytes::from_static(b"down")),
        };
        f.send(Bytes::from_static(b"up")).await.unwrap();
        assert_eq!(f.last, b"up");
        assert_eq!(f.recv().await.unwrap().as_ref(), b"down");
        assert!(f.recv().await.is_err());
    }

    #[tokio::test]
    async fn proxy_stream_roundtrip() {
        let mut s = EchoOnce {
            outgoing_recorded: Vec::new(),
            to_return: Some(Bytes::from_static(b"down")),
        };
        s.send(Bytes::from_static(b"up")).await.unwrap();
        assert_eq!(s.outgoing_recorded, b"up");
        assert_eq!(s.recv().await.unwrap().as_ref(), b"down");
        // Second recv => EOF (Err).
        assert!(s.recv().await.is_err());
        s.close().await.unwrap();
    }
}
