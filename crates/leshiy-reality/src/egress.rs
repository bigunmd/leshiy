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

/// A connected ICMP **echo** egress: `send`/`recv` one ICMP message at a time to one target.
/// Datagram-shaped like [`UdpEgress`], but there is no port and each message is an echo
/// request/reply carrying no IP header (ADR-0030).
#[async_trait::async_trait]
pub trait IcmpEgress: Send {
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

    /// Open an ICMP echo association to `target` — a bare IP, no port. Default: unsupported,
    /// so an egress that can't do ICMP (e.g. a connector hop) declines and the client falls
    /// back to dropping it, exactly as an un-upgraded server does.
    async fn open_icmp(&self, _target: &str) -> Result<Box<dyn IcmpEgress>> {
        Err(crate::RealityError::Malformed(
            "icmp egress unsupported".into(),
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

/// Per-attempt bound on dialing a user-chosen target. The exit dials arbitrary destinations, so a
/// black-holed target would otherwise pin a relay task on the OS connect timeout (tens of seconds)
/// — a cheap resource-exhaustion lever. Generous enough for a genuinely distant/slow host, while
/// bounding a dead one; a timed-out address falls through to the next resolved address.
const TARGET_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `io::Error` for a dial attempt that exceeded [`TARGET_CONNECT_TIMEOUT`].
fn timed_out(addr: std::net::SocketAddr) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("connect to {addr} timed out"),
    )
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
            match tokio::time::timeout(TARGET_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
                .await
            {
                Ok(Ok(s)) => {
                    s.set_nodelay(true).ok();
                    let (r, w) = s.into_split();
                    return Ok((Box::new(TcpEgressRead(r)), Box::new(TcpEgressWrite(w))));
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(timed_out(addr)),
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
                Ok(sock) => {
                    match tokio::time::timeout(TARGET_CONNECT_TIMEOUT, sock.connect(addr)).await {
                        Ok(Ok(())) => return Ok(Box::new(UdpEgressSock(sock))),
                        Ok(Err(e)) => last_err = Some(e),
                        Err(_) => last_err = Some(timed_out(addr)),
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(crate::RealityError::Io(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no reachable address")
        })))
    }

    async fn open_icmp(&self, target: &str) -> Result<Box<dyn IcmpEgress>> {
        // A bare IP, never a hostname: the client lifts the destination straight off the packet
        // it is relaying, so no name resolution is involved and accepting one would only widen
        // the surface. Rejecting non-IPs also keeps the netguard check total — there is no
        // resolve step here that could return an address we failed to screen.
        let ip: std::net::IpAddr = target.parse().map_err(|_| {
            crate::RealityError::Malformed(format!("icmp target must be a bare IP, got {target}"))
        })?;
        crate::netguard::check_ip_allowed(ip, self.allow_private)?;
        Ok(Box::new(IcmpEgressSock(icmp_socket(ip)?)))
    }
}

/// An unprivileged ICMP datagram socket connected to `ip`.
///
/// `SOCK_DGRAM`/`IPPROTO_ICMP` rather than `SOCK_RAW`: it needs no `CAP_NET_RAW`, and the kernel
/// constrains it to echo — it *cannot* emit arbitrary ICMP types — which is the confinement we
/// want, not merely a convenience (ADR-0030). The kernel also owns the echo identifier, stamping
/// the socket's local port over whatever we send, which is why the caller must restore the
/// client's original id on the reply.
///
/// Requires the process GID to fall inside `net.ipv4.ping_group_range`; the container sets it.
/// Without it this fails `EACCES`, the association is declined, and the client keeps dropping
/// ICMP — the same degradation as talking to a server that never advertised `CAP_ICMP`.
fn icmp_socket(ip: std::net::IpAddr) -> Result<tokio::net::UdpSocket> {
    let (domain, protocol) = match ip {
        std::net::IpAddr::V4(_) => (socket2::Domain::IPV4, socket2::Protocol::ICMPV4),
        std::net::IpAddr::V6(_) => (socket2::Domain::IPV6, socket2::Protocol::ICMPV6),
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(protocol))
        .map_err(crate::RealityError::Io)?;
    // `from_std` below requires a non-blocking socket, and connect on a datagram socket is
    // immediate, so there is no in-progress state to handle.
    sock.set_nonblocking(true)
        .map_err(crate::RealityError::Io)?;
    // ICMP has no ports; the kernel ignores this one and uses the socket's local port as the
    // echo id instead.
    sock.connect(&std::net::SocketAddr::new(ip, 0).into())
        .map_err(crate::RealityError::Io)?;
    // socket2 → std → tokio. Both conversions are safe `From`/`from_std` impls; this crate is
    // `#![forbid(unsafe_code)]`, so `from_raw_fd` is not an option.
    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock).map_err(crate::RealityError::Io)
}

struct IcmpEgressSock(tokio::net::UdpSocket);

#[async_trait::async_trait]
impl IcmpEgress for IcmpEgressSock {
    async fn send(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf).await
    }
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buf).await
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

    /// True when this host permits unprivileged ICMP sockets. `net.ipv4.ping_group_range` is
    /// `1 0` — an empty range — on most distros by default, so the roundtrip tests below must
    /// skip rather than false-fail. The container sets the sysctl; a dev box usually has not.
    /// Mirrors `v6_loopback_available`.
    async fn ping_socket_available() -> bool {
        icmp_socket("127.0.0.1".parse().unwrap()).is_ok()
    }

    /// The SSRF guard must cover ICMP too. This one is not theoretical: an exit that will ping
    /// arbitrary addresses on command is a network scanner, and metadata endpoints answer echo.
    #[tokio::test]
    async fn icmp_egress_blocks_metadata() {
        assert!(
            DirectEgress::allowing_private()
                .open_icmp("169.254.169.254")
                .await
                .is_err(),
            "link-local must be refused even with the private opt-in"
        );
    }

    #[tokio::test]
    async fn icmp_egress_blocks_private_by_default() {
        assert!(DirectEgress::new().open_icmp("127.0.0.1").await.is_err());
        assert!(DirectEgress::new().open_icmp("10.0.0.1").await.is_err());
    }

    /// ICMP has no ports, so a `host:port` target is a caller bug — and accepting one would mean
    /// parsing an address we then never screened.
    #[tokio::test]
    async fn icmp_egress_rejects_anything_that_is_not_a_bare_ip() {
        for bad in ["1.1.1.1:0", "example.com", "[2001:db8::1]:443", ""] {
            assert!(
                DirectEgress::allowing_private()
                    .open_icmp(bad)
                    .await
                    .is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// Ping ourselves through the egress and read the reply back. Proves the socket is genuinely
    /// usable — that `SOCK_DGRAM`/`IPPROTO_ICMP` accepts an echo request we built and returns a
    /// reply — rather than only that it opens.
    #[tokio::test]
    async fn icmp_egress_roundtrips_an_echo_to_loopback() {
        use leshiy_core::icmp;
        if !ping_socket_available().await {
            eprintln!(
                "skipping icmp_egress_roundtrips_an_echo_to_loopback: no unprivileged ICMP \
                 socket (net.ipv4.ping_group_range is {:?})",
                std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range")
                    .unwrap_or_default()
                    .trim()
            );
            return;
        }
        let mut eg = DirectEgress::allowing_private()
            .open_icmp("127.0.0.1")
            .await
            .unwrap();

        let mut req = vec![icmp::V4_ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        req.extend_from_slice(b"leshiy");
        assert!(icmp::set_v4_checksum(&mut req));
        eg.send(&req).await.unwrap();

        let mut buf = [0u8; 1500];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), eg.recv(&mut buf))
            .await
            .expect("echo reply timed out")
            .unwrap();
        let reply = &buf[..n];
        assert!(icmp::is_echo_reply(reply, false), "expected an echo reply");
        // A ping socket delivers the ICMP message with no IP header — the assumption the whole
        // relay is built on. If that were wrong, the type byte would be an IPv4 version nibble.
        assert_eq!(reply[0], icmp::V4_ECHO_REPLY);
        assert_eq!(
            &reply[icmp::HEADER_LEN..n],
            b"leshiy",
            "payload echoed back"
        );
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
