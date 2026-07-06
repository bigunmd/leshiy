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

/// A connected UDP egress association: `send`/`recv` discrete datagrams to one target.
#[async_trait::async_trait]
pub trait UdpEgress: Send {
    async fn send(&mut self, buf: &[u8]) -> std::io::Result<usize>;
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[async_trait::async_trait]
pub trait Egress: Send + Sync {
    /// Open a connection to `target` and return split read/write halves.
    async fn open(&self, target: &str) -> Result<(Box<dyn EgressRead>, Box<dyn EgressWrite>)>;

    /// Open a UDP datagram association to `target`. Default: unsupported.
    async fn open_udp(&self, _target: &str) -> Result<Box<dyn UdpEgress>> {
        Err(crate::RealityError::Malformed(
            "udp egress unsupported".into(),
        ))
    }
}

/// Dial the target directly (the exit / today's behavior), netguard-gated.
///
/// By default loopback / private targets are refused (SSRF guard). Construct
/// with [`DirectEgress::allowing_private`] to permit them — used by in-process
/// tests (which dial loopback echo servers) and by operators who deliberately
/// run an exit on an internal network.
#[derive(Debug, Clone, Copy)]
pub struct DirectEgress {
    allow_private: bool,
}

impl DirectEgress {
    /// Secure default: refuse loopback / RFC 1918 / unique-local targets.
    pub fn new() -> Self {
        Self {
            allow_private: false,
        }
    }

    /// Permit loopback / private targets (explicit opt-in).
    pub fn allowing_private() -> Self {
        Self {
            allow_private: true,
        }
    }
}

impl Default for DirectEgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Wildcard bind address matching the family of a resolved target. A UDP egress
/// socket must be the same address family as its `connect` peer — a `0.0.0.0`
/// socket cannot reach an IPv6 dest (`EAFNOSUPPORT`) and vice versa.
fn udp_bind_wildcard(target: &std::net::SocketAddr) -> std::net::SocketAddr {
    if target.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    }
}

#[async_trait::async_trait]
impl Egress for DirectEgress {
    async fn open(&self, target: &str) -> Result<(Box<dyn EgressRead>, Box<dyn EgressWrite>)> {
        let addrs = crate::netguard::resolve_all_checked(target, self.allow_private).await?;
        // Try each resolved address so a leading unreachable one (e.g. an AAAA on
        // an IPv4-only host) falls through to the next instead of failing the dial.
        let mut last_err = None;
        for addr in addrs {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    let (r, w) = s.into_split();
                    return Ok((Box::new(TcpEgressRead(r)), Box::new(TcpEgressWrite(w))));
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(crate::RealityError::Io(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no reachable address")
        })))
    }

    async fn open_udp(&self, target: &str) -> Result<Box<dyn UdpEgress>> {
        let addrs = crate::netguard::resolve_all_checked(target, self.allow_private).await?;
        let mut last_err = None;
        for addr in addrs {
            // Bind the wildcard of the target's family: an IPv4 `0.0.0.0` socket
            // cannot `connect` an IPv6 dest (and vice versa).
            match tokio::net::UdpSocket::bind(udp_bind_wildcard(&addr)).await {
                Ok(sock) => match sock.connect(addr).await {
                    Ok(()) => return Ok(Box::new(UdpEgressSock(sock))),
                    Err(e) => last_err = Some(e),
                },
                Err(e) => last_err = Some(e),
            }
        }
        Err(crate::RealityError::Io(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no reachable address")
        })))
    }
}

struct UdpEgressSock(tokio::net::UdpSocket);

#[async_trait::async_trait]
impl UdpEgress for UdpEgressSock {
    async fn send(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf).await
    }
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buf).await
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
        let (mut er, mut ew) = DirectEgress::allowing_private()
            .open(&addr.to_string())
            .await
            .unwrap();
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
        // Blocked even with the private opt-in (link-local is always forbidden).
        assert!(
            DirectEgress::allowing_private()
                .open("169.254.169.254:80")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn direct_egress_blocks_loopback_by_default() {
        // Default (secure) policy refuses loopback — SSRF guard.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        assert!(DirectEgress::new().open(&addr.to_string()).await.is_err());
    }

    #[tokio::test]
    async fn direct_udp_egress_roundtrips() {
        use tokio::net::UdpSocket;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            let (n, from) = server.recv_from(&mut b).await.unwrap();
            server.send_to(&b[..n], from).await.unwrap(); // echo
        });
        let mut eg = DirectEgress::allowing_private()
            .open_udp(&saddr.to_string())
            .await
            .unwrap();
        eg.send(b"ping-udp").await.unwrap();
        let mut buf = [0u8; 64];
        let n = eg.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping-udp");
    }

    #[tokio::test]
    async fn udp_egress_blocks_metadata() {
        assert!(
            DirectEgress::allowing_private()
                .open_udp("169.254.169.254:53")
                .await
                .is_err()
        ); // netguard: link-local always blocked
    }

    #[test]
    fn udp_bind_wildcard_matches_target_family() {
        // The exact fix for the v4-socket-cannot-reach-v6-dest bug, tested without
        // needing IPv6 routing in the environment.
        let v4: std::net::SocketAddr = "1.2.3.4:53".parse().unwrap();
        let v6: std::net::SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        assert_eq!(udp_bind_wildcard(&v4), "0.0.0.0:0".parse().unwrap());
        assert_eq!(udp_bind_wildcard(&v6), "[::]:0".parse().unwrap());
    }

    /// True when the environment has a usable IPv6 loopback. WSL2 and some CI
    /// sandboxes can create `[::]` sockets but have no `::1`, so v6 roundtrip
    /// tests must skip there rather than false-fail.
    async fn v6_loopback_available() -> bool {
        tokio::net::TcpListener::bind("[::1]:0").await.is_ok()
    }

    #[tokio::test]
    async fn direct_egress_roundtrips_ipv6() {
        // TCP egress to an IPv6 target (regression guard for the resolve-all refactor).
        if !v6_loopback_available().await {
            eprintln!("skipping direct_egress_roundtrips_ipv6: no IPv6 loopback");
            return;
        }
        let l = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let (mut er, mut ew) = DirectEgress::allowing_private()
            .open(&addr.to_string()) // "[::1]:PORT"
            .await
            .unwrap();
        ew.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        let mut n = 0;
        while n < 5 {
            n += er.read(&mut got[n..]).await.unwrap();
        }
        assert_eq!(&got, b"hello");
    }

    #[tokio::test]
    async fn direct_udp_egress_roundtrips_ipv6() {
        // The UDP egress socket must bind the family of the resolved target:
        // an IPv4 `0.0.0.0` socket cannot `connect` an IPv6 dest.
        use tokio::net::UdpSocket;
        if !v6_loopback_available().await {
            eprintln!("skipping direct_udp_egress_roundtrips_ipv6: no IPv6 loopback");
            return;
        }
        let server = UdpSocket::bind("[::1]:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            let (n, from) = server.recv_from(&mut b).await.unwrap();
            server.send_to(&b[..n], from).await.unwrap(); // echo
        });
        let mut eg = DirectEgress::allowing_private()
            .open_udp(&saddr.to_string()) // "[::1]:PORT"
            .await
            .unwrap();
        eg.send(b"ping-udp6").await.unwrap();
        let mut buf = [0u8; 64];
        let n = eg.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping-udp6");
    }
}
