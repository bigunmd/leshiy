//! Resolve split-tunnel domain rules **through the tunnel**.
//!
//! The host app is excluded from its own VPN, so the system resolver would send every rule's
//! domain in plaintext over the censored network — handing the observer the user's blocklist
//! and taking back whatever poisoned answer it cares to inject for exactly those domains. Instead
//! the queries ride a tunnel stream as DNS-over-TCP (RFC 1035 §4.2.2) to a public resolver, so
//! the censor sees neither the names nor the answers.
use bytes::Bytes;
use leshiy_client::Tunnel;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// The same resolver the VPN interface hands to apps.
const RESOLVER: &str = "1.1.1.1:53";
const PER_HOST_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on one [`resolve_all`] pass; hosts still pending are dropped.
pub(crate) const OVERALL_TIMEOUT: Duration = Duration::from_secs(30);
const CONCURRENCY: usize = 16;
/// Two length-prefixed responses at most; anything past this is a misbehaving peer.
const MAX_BUFFERED: usize = 2 * (2 + u16::MAX as usize);

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Resolve every host's A + AAAA records through `tunnel`, at most `max_per_host` addresses each.
/// Best-effort: a host that fails or times out contributes nothing.
pub(crate) async fn resolve_all(
    tunnel: Arc<dyn Tunnel>,
    hosts: Vec<String>,
    max_per_host: usize,
) -> Vec<IpAddr> {
    let permits = Arc::new(Semaphore::new(CONCURRENCY));
    let mut set = JoinSet::new();
    for (i, host) in hosts.into_iter().enumerate() {
        let (tunnel, permits) = (tunnel.clone(), permits.clone());
        let id = (i as u16).wrapping_mul(2);
        set.spawn(async move {
            let _permit = permits.acquire_owned().await.ok()?;
            let addrs = tokio::time::timeout(PER_HOST_TIMEOUT, resolve_host(&*tunnel, &host, id))
                .await
                .ok()?;
            Some(addrs.into_iter().take(max_per_host).collect::<Vec<_>>())
        });
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(OVERALL_TIMEOUT, async {
        while let Some(joined) = set.join_next().await {
            if let Ok(Some(addrs)) = joined {
                out.extend(addrs);
            }
        }
    })
    .await;
    out
}

/// A + AAAA for one host over a single tunnel stream (both queries pipelined).
async fn resolve_host(tunnel: &dyn Tunnel, host: &str, id: u16) -> Vec<IpAddr> {
    let ids = [id, id.wrapping_add(1)];
    let (Some(a), Some(aaaa)) = (
        build_query(ids[0], host, TYPE_A),
        build_query(ids[1], host, TYPE_AAAA),
    ) else {
        return Vec::new();
    };
    exchange(tunnel, &[a, aaaa], &ids).await.unwrap_or_default()
}

async fn exchange(
    tunnel: &dyn Tunnel,
    queries: &[Vec<u8>],
    ids: &[u16],
) -> leshiy_client::Result<Vec<IpAddr>> {
    let mut stream = tunnel.open(RESOLVER).await?;
    let mut wire = Vec::new();
    for q in queries {
        wire.extend_from_slice(&(q.len() as u16).to_be_bytes());
        wire.extend_from_slice(q);
    }
    stream.send(Bytes::from(wire)).await?;

    let mut pending = ids.to_vec();
    let mut buf = Vec::new();
    let mut out = Vec::new();
    while !pending.is_empty() {
        let chunk = stream.recv().await?;
        if chunk.is_empty() || buf.len() + chunk.len() > MAX_BUFFERED {
            break;
        }
        buf.extend_from_slice(&chunk);
        while let Some(len) = u16_at(&buf, 0).map(usize::from)
            && buf.len() >= 2 + len
        {
            let msg: Vec<u8> = buf.drain(..2 + len).skip(2).collect();
            if let Some(id) = u16_at(&msg, 0)
                && let Some(pos) = pending.iter().position(|&p| p == id)
            {
                pending.swap_remove(pos);
                out.extend(parse_answers(&msg, id).unwrap_or_default());
            }
        }
    }
    let _ = stream.close().await;
    Ok(out)
}

/// A recursive query for `host`, or `None` if it is not a valid hostname.
fn build_query(id: u16, host: &str, qtype: u16) -> Option<Vec<u8>> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let mut q = Vec::with_capacity(18 + host.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT = 1
    for label in host.split('.') {
        let valid = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(q)
}

/// Usable A/AAAA records from a response to query `id`. `None` for a malformed message, a
/// mismatched id, or an error RCODE. Never panics on hostile input.
fn parse_answers(msg: &[u8], id: u16) -> Option<Vec<IpAddr>> {
    let flags = u16_at(msg, 2)?;
    if u16_at(msg, 0)? != id || flags & 0x8000 == 0 || flags & 0x000F != 0 {
        return None;
    }
    let (questions, answers) = (u16_at(msg, 4)?, u16_at(msg, 6)?);
    let mut i = 12;
    for _ in 0..questions {
        i = skip_name(msg, i)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..answers {
        i = skip_name(msg, i)?;
        let (rtype, class) = (u16_at(msg, i)?, u16_at(msg, i + 2)?);
        let len = usize::from(u16_at(msg, i + 8)?);
        let rdata = msg.get(i + 10..i + 10 + len)?;
        i += 10 + len;
        let ip = match (class, rtype) {
            (CLASS_IN, TYPE_A) => IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?),
            (CLASS_IN, TYPE_AAAA) => IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?),
            _ => continue, // CNAME chain links, etc.
        };
        if !ip.is_unspecified() && !ip.is_loopback() {
            out.push(ip);
        }
    }
    Some(out)
}

/// Offset just past the (possibly compressed) name starting at `i`.
fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = usize::from(*msg.get(i)?);
        match len & 0xC0 {
            0xC0 => return (i + 2 <= msg.len()).then_some(i + 2),
            0x00 if len == 0 => return Some(i + 1),
            0x00 => i += 1 + len,
            _ => return None,
        }
    }
}

fn u16_at(buf: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use leshiy_client::{ClientError, ProxyStream};
    use std::collections::VecDeque;

    /// A response to `query` carrying `rdata` records of the queried type, the owner name
    /// compressed to a pointer at the question — the shape real resolvers send.
    fn answer(query: &[u8], rdata: &[&[u8]]) -> Vec<u8> {
        let qtype = u16_at(query, query.len() - 4).unwrap();
        let mut m = query[..2].to_vec();
        m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, rdata.len() as u8, 0, 0, 0, 0]);
        m.extend_from_slice(&query[12..]);
        for r in rdata {
            m.extend_from_slice(&[0xC0, 0x0C]);
            m.extend_from_slice(&qtype.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0x0E, 0x10, 0, r.len() as u8]);
            m.extend_from_slice(r);
        }
        m
    }

    #[test]
    fn query_encodes_labels_and_rejects_bad_names() {
        let q = build_query(0x1234, "a.example.com", TYPE_AAAA).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..], b"\x01a\x07example\x03com\x00\x00\x1c\x00\x01");
        assert!(build_query(1, "", TYPE_A).is_none());
        assert!(build_query(1, "a..b", TYPE_A).is_none());
        assert!(build_query(1, "bad host.com", TYPE_A).is_none());
        assert!(build_query(1, &format!("{}.com", "a".repeat(64)), TYPE_A).is_none());
    }

    #[test]
    fn parses_records_after_a_cname() {
        let q = build_query(7, "example.com", TYPE_A).unwrap();
        let mut m = q[..2].to_vec();
        m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
        m.extend_from_slice(&q[12..]);
        // CNAME example.com -> x.example.com (compressed), then its A record.
        m.extend_from_slice(&[
            0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'x', 0xC0, 0x0C,
        ]);
        m.extend_from_slice(&[0xC0, 0x29, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        assert_eq!(
            parse_answers(&m, 7).unwrap(),
            vec![IpAddr::from([93, 184, 216, 34])]
        );
    }

    #[test]
    fn rejects_mismatched_id_error_rcode_and_junk_addresses() {
        let q = build_query(9, "example.com", TYPE_A).unwrap();
        let ok = answer(&q, &[&[1, 2, 3, 4], &[0, 0, 0, 0], &[127, 0, 0, 1]]);
        assert_eq!(
            parse_answers(&ok, 9).unwrap(),
            vec![IpAddr::from([1, 2, 3, 4])]
        );
        assert!(parse_answers(&ok, 10).is_none());
        let mut nxdomain = ok.clone();
        nxdomain[3] |= 0x03;
        assert!(parse_answers(&nxdomain, 9).is_none());
    }

    #[test]
    fn truncated_input_never_panics() {
        let q = build_query(3, "example.com", TYPE_AAAA).unwrap();
        let m = answer(
            &q,
            &[&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
        );
        assert_eq!(parse_answers(&m, 3).unwrap().len(), 1);
        for cut in 0..m.len() {
            let _ = parse_answers(&m[..cut], 3);
        }
        // A pointer loop must terminate too.
        let mut looped = m.clone();
        looped[12] = 0xC0;
        looped[13] = 0x0C;
        let _ = parse_answers(&looped, 3);
    }

    /// Answers each pipelined query with a fixed record, delivering the bytes in small chunks.
    struct FakeResolver {
        v4: [u8; 4],
        v6: [u8; 16],
    }

    struct FakeStream {
        v4: [u8; 4],
        v6: [u8; 16],
        out: VecDeque<Bytes>,
    }

    #[async_trait]
    impl ProxyStream for FakeStream {
        async fn send(&mut self, data: Bytes) -> leshiy_client::Result<()> {
            let mut wire = Vec::new();
            let mut rest = &data[..];
            while let Some(len) = u16_at(rest, 0).map(usize::from) {
                let q = &rest[2..2 + len];
                let rec: &[u8] = if u16_at(q, q.len() - 4) == Some(TYPE_A) {
                    &self.v4
                } else {
                    &self.v6
                };
                let a = answer(q, &[rec]);
                wire.extend_from_slice(&(a.len() as u16).to_be_bytes());
                wire.extend_from_slice(&a);
                rest = &rest[2 + len..];
            }
            self.out = wire.chunks(7).map(Bytes::copy_from_slice).collect();
            Ok(())
        }
        async fn recv(&mut self) -> leshiy_client::Result<Bytes> {
            self.out.pop_front().ok_or(ClientError::ConnectFailed)
        }
        async fn close(&mut self) -> leshiy_client::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Tunnel for FakeResolver {
        async fn open(&self, target: &str) -> leshiy_client::Result<Box<dyn ProxyStream>> {
            assert_eq!(target, RESOLVER);
            Ok(Box::new(FakeStream {
                v4: self.v4,
                v6: self.v6,
                out: VecDeque::new(),
            }))
        }
        async fn closed(&self) {
            std::future::pending::<()>().await
        }
    }

    #[tokio::test]
    async fn resolves_hosts_through_the_tunnel() {
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let tunnel: Arc<dyn Tunnel> = Arc::new(FakeResolver {
            v4: [1, 2, 3, 4],
            v6,
        });
        let hosts = vec!["a.example.com".to_string(), "not a host".to_string()];
        let mut got = resolve_all(tunnel.clone(), hosts, 8).await;
        got.sort();
        assert_eq!(got, vec![IpAddr::from([1, 2, 3, 4]), IpAddr::from(v6)]);

        let capped = resolve_all(tunnel, vec!["a.example.com".into()], 1).await;
        assert_eq!(capped.len(), 1);
    }

    struct DeadTunnel;

    #[async_trait]
    impl Tunnel for DeadTunnel {
        async fn open(&self, _: &str) -> leshiy_client::Result<Box<dyn ProxyStream>> {
            Err(ClientError::ConnectFailed)
        }
        async fn closed(&self) {}
    }

    #[tokio::test]
    async fn a_dead_tunnel_yields_nothing() {
        let got = resolve_all(Arc::new(DeadTunnel), vec!["example.com".into()], 8).await;
        assert!(got.is_empty());
    }
}
