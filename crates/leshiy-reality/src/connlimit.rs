//! Pre-auth connection admission control.
//!
//! Every accepted socket triggers an outbound dial to `dest` *before* any
//! authentication, so an unauthenticated flood both exhausts the server (FDs,
//! memory, tasks) and reflects onto the masqueraded site. This limiter bounds
//! the total number of in-flight connections and the number per source IP. A
//! rejected connection is simply dropped — a flooding attacker is not doing
//! TLS-fingerprint comparison, so this is not the active-probe path.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

/// Collapse an address to its per-source rate-limiting bucket: an IPv4 /32 (the
/// address itself), or an IPv6 /64 network (interface-id bits zeroed).
///
/// A single IPv6 end-user allocation is routinely a whole /64 (2^64 addresses)
/// or larger, so keying the per-source cap on the bare address would let one
/// actor mint effectively unlimited distinct sources and bypass it entirely (H2).
/// Bucketing IPv6 to the /64 makes the cap meaningful against a single allocation.
fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in &mut octets[8..] {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

struct Inner {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Admission controller: caps total and per-IP concurrent connections.
#[derive(Clone)]
pub struct ConnLimiter {
    max_total: usize,
    max_per_ip: usize,
    inner: Arc<Mutex<Inner>>,
}

/// RAII guard; releases the slot (total + per-IP) on drop.
pub struct ConnGuard {
    ip: IpAddr,
    inner: Arc<Mutex<Inner>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut g = self.inner.lock().unwrap();
        g.total = g.total.saturating_sub(1);
        if let Some(c) = g.per_ip.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                g.per_ip.remove(&self.ip);
            }
        }
    }
}

impl ConnLimiter {
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            max_total,
            max_per_ip,
            inner: Arc::new(Mutex::new(Inner {
                total: 0,
                per_ip: HashMap::new(),
            })),
        }
    }

    /// Try to admit a connection from `ip`. Returns a guard on success, or
    /// `None` if the total or per-IP cap is already reached.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnGuard> {
        // Bucket to a /32 (v4) or /64 (v6) so the per-source cap can't be bypassed
        // by rotating addresses within one IPv6 allocation (H2).
        let key = bucket(ip);
        let mut g = self.inner.lock().unwrap();
        if g.total >= self.max_total {
            return None;
        }
        let cur = g.per_ip.get(&key).copied().unwrap_or(0);
        if cur >= self.max_per_ip {
            return None;
        }
        g.total += 1;
        g.per_ip.insert(key, cur + 1);
        Some(ConnGuard {
            ip: key,
            inner: self.inner.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn admits_up_to_per_ip_cap_then_rejects() {
        let l = ConnLimiter::new(100, 2);
        let a = ip("1.2.3.4");
        let _g1 = l.try_acquire(a).expect("1st admitted");
        let _g2 = l.try_acquire(a).expect("2nd admitted");
        assert!(l.try_acquire(a).is_none(), "3rd over per-IP cap rejected");
    }

    #[test]
    fn releasing_a_guard_frees_a_slot() {
        let l = ConnLimiter::new(100, 1);
        let a = ip("1.2.3.4");
        let g = l.try_acquire(a).unwrap();
        assert!(l.try_acquire(a).is_none());
        drop(g);
        assert!(l.try_acquire(a).is_some(), "slot freed after drop");
    }

    #[test]
    fn per_ip_is_independent_across_ips() {
        let l = ConnLimiter::new(100, 1);
        let _a = l.try_acquire(ip("1.1.1.1")).unwrap();
        assert!(l.try_acquire(ip("2.2.2.2")).is_some(), "different IP ok");
    }

    #[test]
    fn total_cap_rejects_even_new_ips() {
        let l = ConnLimiter::new(2, 10);
        let _a = l.try_acquire(ip("1.1.1.1")).unwrap();
        let _b = l.try_acquire(ip("2.2.2.2")).unwrap();
        assert!(l.try_acquire(ip("3.3.3.3")).is_none(), "total cap hit");
    }

    /// H2: distinct IPv6 addresses within the same /64 share one per-source
    /// bucket, so an attacker can't rotate the interface-id to bypass the cap.
    #[test]
    fn ipv6_addresses_in_the_same_slash64_share_a_bucket() {
        let l = ConnLimiter::new(100, 2);
        let _g1 = l
            .try_acquire(ip("2001:db8:abcd:1234::1"))
            .expect("1st admitted");
        let _g2 = l
            .try_acquire(ip("2001:db8:abcd:1234::2"))
            .expect("2nd admitted");
        assert!(
            l.try_acquire(ip("2001:db8:abcd:1234:ffff:ffff:ffff:ffff"))
                .is_none(),
            "3rd address in the same /64 must hit the per-source cap"
        );
    }

    /// Addresses in different /64s are still independent.
    #[test]
    fn ipv6_addresses_in_different_slash64s_are_independent() {
        let l = ConnLimiter::new(100, 1);
        let _a = l.try_acquire(ip("2001:db8:abcd:1111::1")).unwrap();
        assert!(
            l.try_acquire(ip("2001:db8:abcd:2222::1")).is_some(),
            "a different /64 must not share the bucket"
        );
    }
}
