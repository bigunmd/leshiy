//! Pre-auth connection admission control.
//!
//! Every accepted socket triggers an outbound dial to `dest` *before* any
//! authentication, so an unauthenticated flood both exhausts the server (FDs,
//! memory, tasks) and reflects onto the masqueraded site. This limiter bounds
//! the total number of in-flight connections and the number per source IP. A
//! rejected connection is simply dropped — a flooding attacker is not doing
//! TLS-fingerprint comparison, so this is not the active-probe path.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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
        let mut g = self.inner.lock().unwrap();
        if g.total >= self.max_total {
            return None;
        }
        let cur = g.per_ip.get(&ip).copied().unwrap_or(0);
        if cur >= self.max_per_ip {
            return None;
        }
        g.total += 1;
        g.per_ip.insert(ip, cur + 1);
        Some(ConnGuard {
            ip,
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
}
