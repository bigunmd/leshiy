//! Domain-rule resolution for split-tunnel. Domain rules name hostnames; we resolve them to
//! IPs (via the system resolver) and install one host route per IP — a `bypass` route in
//! Exclude mode, a `via_tun` route in Include mode — refreshing periodically while the
//! session is up.
//!
//! **Known limitation (v1):** resolved IPs only capture what the resolver returns at refresh
//! time. CDN / geo-balanced domains (e.g. `netflix.com`, `*.cloudflare.com`) may resolve to a
//! small or location-specific subset, so traffic to other edge/anycast IPs of the same service
//! is NOT split-routed; resolved IPs can also be stale between refreshes (up to [`REFRESH`]).
//! Precise per-flow domain routing would need DNS-packet sniffing, which is out of scope here.
use crate::route_plan::Cidr;
use crate::sys::RouteController;
use leshiy_client::SplitMode;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// How often domain rules are re-resolved while a session is up.
pub(crate) const REFRESH: Duration = Duration::from_secs(300);

/// The CIDRs added / removed between two resolution snapshots.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CidrDiff {
    pub added: Vec<Cidr>,
    pub removed: Vec<Cidr>,
}

/// Set difference both ways: what's newly present, and what's gone.
pub fn diff(old: &BTreeSet<Cidr>, new: &BTreeSet<Cidr>) -> CidrDiff {
    CidrDiff {
        added: new.difference(old).cloned().collect(),
        removed: old.difference(new).cloned().collect(),
    }
}

/// Remembers the currently-installed resolved CIDRs across refreshes (the diff baseline).
#[derive(Default)]
pub struct ResolverState {
    current: BTreeSet<Cidr>,
}

impl ResolverState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Apply one resolution snapshot: install newly-resolved CIDRs and remove stale ones via the
/// controller, then remember the new set. Exclude mutates `bypass` routes; Include mutates
/// `via_tun` routes. Best-effort — a controller error is logged, not fatal.
pub async fn apply_resolution(
    ctrl: &dyn RouteController,
    mode: SplitMode,
    state: &mut ResolverState,
    resolved: BTreeSet<Cidr>,
) {
    let d = diff(&state.current, &resolved);
    for c in &d.added {
        let r = match mode {
            SplitMode::Exclude => ctrl.add_bypass(c).await,
            SplitMode::Include => ctrl.add_via_tun(c).await,
        };
        if let Err(e) = r {
            tracing::warn!(cidr = %c, "split-tunnel: add resolved route failed: {e}");
        }
    }
    for c in &d.removed {
        let r = match mode {
            SplitMode::Exclude => ctrl.remove_bypass(c).await,
            SplitMode::Include => ctrl.remove_via_tun(c).await,
        };
        if let Err(e) = r {
            tracing::warn!(cidr = %c, "split-tunnel: remove resolved route failed: {e}");
        }
    }
    state.current = resolved;
}

/// Resolve `domains` to host CIDRs (`/32`) via the system resolver. IPv6 results are filtered
/// out this phase (IPv6 is not tunnelled). Unresolvable domains are skipped (logged).
pub async fn resolve_domains(domains: &[String]) -> BTreeSet<Cidr> {
    let mut out = BTreeSet::new();
    for d in domains {
        // `lookup_host` needs a port; 0 is fine since we only use the addresses.
        match tokio::net::lookup_host((d.as_str(), 0)).await {
            Ok(addrs) => {
                for a in addrs {
                    if let IpAddr::V4(v4) = a.ip() {
                        out.insert(Cidr {
                            addr: v4.into(),
                            prefix: 32,
                        });
                    }
                    // IPv6 is out of scope this phase (kill-switched / untunnelled).
                }
            }
            Err(e) => tracing::warn!(domain = %d, "split-tunnel: resolve failed: {e}"),
        }
    }
    out
}

/// Periodically resolve `domains` and apply the route changes via `ctrl`, forever (the engine
/// aborts this task when the session ends). The dynamic routes it installs are cleaned up by
/// the session teardown guard, so abort is safe.
pub async fn run_resolver(
    ctrl: Arc<dyn RouteController>,
    mode: SplitMode,
    domains: Vec<String>,
    mut state: ResolverState,
    interval: Duration,
) {
    loop {
        let resolved = resolve_domains(&domains).await;
        apply_resolution(&*ctrl, mode, &mut state, resolved).await;
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn host(s: &str) -> Cidr {
        Cidr {
            addr: s.parse().unwrap(),
            prefix: 32,
        }
    }

    #[test]
    fn diff_reports_added_and_removed_cidrs() {
        let old: BTreeSet<Cidr> = [host("1.1.1.1"), host("2.2.2.2")].into();
        let new: BTreeSet<Cidr> = [host("2.2.2.2"), host("3.3.3.3")].into();
        let d = diff(&old, &new);
        assert_eq!(d.added, vec![host("3.3.3.3")]);
        assert_eq!(d.removed, vec![host("1.1.1.1")]);
    }

    #[test]
    fn empty_diff_when_unchanged() {
        let s: BTreeSet<Cidr> = [host("1.1.1.1")].into();
        let d = diff(&s, &s);
        assert!(d.added.is_empty() && d.removed.is_empty());
    }

    /// Records the controller calls so the apply loop can be tested without real routing.
    #[derive(Default)]
    struct RecordingController {
        bypass_added: Mutex<Vec<Cidr>>,
        bypass_removed: Mutex<Vec<Cidr>>,
        via_tun_added: Mutex<Vec<Cidr>>,
        via_tun_removed: Mutex<Vec<Cidr>>,
    }

    #[async_trait]
    impl RouteController for RecordingController {
        async fn add_bypass(&self, c: &Cidr) -> std::io::Result<()> {
            self.bypass_added.lock().unwrap().push(c.clone());
            Ok(())
        }
        async fn remove_bypass(&self, c: &Cidr) -> std::io::Result<()> {
            self.bypass_removed.lock().unwrap().push(c.clone());
            Ok(())
        }
        async fn add_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
            self.via_tun_added.lock().unwrap().push(c.clone());
            Ok(())
        }
        async fn remove_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
            self.via_tun_removed.lock().unwrap().push(c.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn exclude_apply_adds_new_then_removes_stale_via_bypass() {
        let ctrl = RecordingController::default();
        let mut state = ResolverState::new();
        // First pass: example.com -> 1.1.1.1.
        apply_resolution(
            &ctrl,
            SplitMode::Exclude,
            &mut state,
            [host("1.1.1.1")].into(),
        )
        .await;
        assert_eq!(*ctrl.bypass_added.lock().unwrap(), vec![host("1.1.1.1")]);
        // Second pass: now 2.2.2.2 (1.1.1.1 dropped).
        apply_resolution(
            &ctrl,
            SplitMode::Exclude,
            &mut state,
            [host("2.2.2.2")].into(),
        )
        .await;
        assert!(ctrl.bypass_added.lock().unwrap().contains(&host("2.2.2.2")));
        assert_eq!(*ctrl.bypass_removed.lock().unwrap(), vec![host("1.1.1.1")]);
    }

    #[tokio::test]
    async fn include_apply_uses_via_tun_calls() {
        let ctrl = RecordingController::default();
        let mut state = ResolverState::new();
        apply_resolution(
            &ctrl,
            SplitMode::Include,
            &mut state,
            [host("3.3.3.3")].into(),
        )
        .await;
        assert_eq!(*ctrl.via_tun_added.lock().unwrap(), vec![host("3.3.3.3")]);
        assert!(ctrl.bypass_added.lock().unwrap().is_empty());
    }
}
