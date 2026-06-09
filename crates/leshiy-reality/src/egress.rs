//! Egress abstraction: A's relays open a bidirectional byte stream to a target via an `Egress`.
//! `DirectEgress` dials the target (the exit); `leshiy-quic::ConnectorEgress` forwards to an Exit B.
//!
//! `Egress::open` returns a split `(Box<dyn EgressRead>, Box<dyn EgressWrite>)` pair so the relay
//! can own the read half and write half independently in concurrent tasks without borrow conflicts.
use crate::Result;

/// The read half of an egress connection. Returns 0 on EOF.
#[async_trait::async_trait]
pub trait EgressRead: Send {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>; // 0 = EOF
}

/// The write half of an egress connection.
#[async_trait::async_trait]
pub trait EgressWrite: Send {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
    async fn shutdown(&mut self) -> std::io::Result<()>;
}

#[async_trait::async_trait]
pub trait Egress: Send + Sync {
    /// Open a connection to `target` and return split read/write halves.
    async fn open(&self, target: &str) -> Result<(Box<dyn EgressRead>, Box<dyn EgressWrite>)>;
}

/// Dial the target directly (the exit / today's behavior), netguard-gated.
pub struct DirectEgress;

#[async_trait::async_trait]
impl Egress for DirectEgress {
    async fn open(&self, target: &str) -> Result<(Box<dyn EgressRead>, Box<dyn EgressWrite>)> {
        let addr = crate::netguard::resolve_checked(target).await?;
        let s = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(crate::RealityError::Io)?;
        s.set_nodelay(true).ok();
        let (r, w) = s.into_split();
        Ok((Box::new(TcpEgressRead(r)), Box::new(TcpEgressWrite(w))))
    }
}

struct TcpEgressRead(tokio::net::tcp::OwnedReadHalf);

#[async_trait::async_trait]
impl EgressRead for TcpEgressRead {
    async fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        self.0.read(b).await
    }
}

struct TcpEgressWrite(tokio::net::tcp::OwnedWriteHalf);

#[async_trait::async_trait]
impl EgressWrite for TcpEgressWrite {
    async fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.0.write_all(b).await
    }
    async fn shutdown(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.0.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn direct_egress_roundtrips() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let (mut er, mut ew) = DirectEgress.open(&addr.to_string()).await.unwrap();
        ew.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        let mut n = 0;
        while n < 5 {
            n += er.read(&mut got[n..]).await.unwrap();
        }
        assert_eq!(&got, b"hello");
    }

    #[tokio::test]
    async fn direct_egress_blocks_metadata() {
        assert!(DirectEgress.open("169.254.169.254:80").await.is_err()); // netguard
    }
}
