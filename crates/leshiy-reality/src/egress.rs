//! Egress abstraction: A's relays open a bidirectional byte stream to a target via an `Egress`.
//! `DirectEgress` dials the target (the exit); `leshiy-quic::ConnectorEgress` forwards to an Exit B.
use crate::Result;

#[async_trait::async_trait]
pub trait EgressStream: Send {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>; // 0 = EOF
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
    async fn shutdown(&mut self) -> std::io::Result<()>;
}

#[async_trait::async_trait]
pub trait Egress: Send + Sync {
    async fn open(&self, target: &str) -> Result<Box<dyn EgressStream>>;
}

/// Dial the target directly (the exit / today's behavior), netguard-gated.
pub struct DirectEgress;

#[async_trait::async_trait]
impl Egress for DirectEgress {
    async fn open(&self, target: &str) -> Result<Box<dyn EgressStream>> {
        let addr = crate::netguard::resolve_checked(target).await?;
        let s = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(crate::RealityError::Io)?;
        s.set_nodelay(true).ok();
        Ok(Box::new(TcpEgress(s)))
    }
}

struct TcpEgress(tokio::net::TcpStream);

#[async_trait::async_trait]
impl EgressStream for TcpEgress {
    async fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        self.0.read(b).await
    }
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
        let mut e = DirectEgress.open(&addr.to_string()).await.unwrap();
        e.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        let mut n = 0;
        while n < 5 {
            n += e.read(&mut got[n..]).await.unwrap();
        }
        assert_eq!(&got, b"hello");
    }

    #[tokio::test]
    async fn direct_egress_blocks_metadata() {
        assert!(DirectEgress.open("169.254.169.254:80").await.is_err()); // netguard
    }
}
