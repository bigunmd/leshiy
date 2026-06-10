//! Transport-agnostic tunneled byte stream.
//!
//! Plan 3 implements this for the REALITY mux `Stream` and the QUIC h3 CONNECT
//! stream; the metered pump and tests depend only on this trait.
use crate::error::Result;
use async_trait::async_trait;

/// A bidirectional byte stream to one target ("host:port") inside a tunnel.
#[async_trait]
pub trait ProxyStream: Send {
    /// Send payload bytes toward the target.
    async fn send(&mut self, data: Vec<u8>) -> Result<()>;
    /// Receive the next chunk from the target. An empty `Vec` **or** an `Err`
    /// is treated by callers as end-of-stream.
    async fn recv(&mut self) -> Result<Vec<u8>>;
    /// Close the stream (best effort).
    async fn close(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ClientError;

    /// Minimal fake: yields queued chunks, then errors (EOF). Records what was sent.
    struct EchoOnce {
        outgoing_recorded: Vec<u8>,
        to_return: Option<Vec<u8>>,
    }

    #[async_trait]
    impl ProxyStream for EchoOnce {
        async fn send(&mut self, data: Vec<u8>) -> Result<()> {
            self.outgoing_recorded.extend_from_slice(&data);
            Ok(())
        }
        async fn recv(&mut self) -> Result<Vec<u8>> {
            self.to_return.take().ok_or(ClientError::ConnectFailed)
        }
        async fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn proxy_stream_roundtrip() {
        let mut s = EchoOnce {
            outgoing_recorded: Vec::new(),
            to_return: Some(b"down".to_vec()),
        };
        s.send(b"up".to_vec()).await.unwrap();
        assert_eq!(s.outgoing_recorded, b"up");
        assert_eq!(s.recv().await.unwrap(), b"down");
        // Second recv => EOF (Err).
        assert!(s.recv().await.is_err());
        s.close().await.unwrap();
    }
}
