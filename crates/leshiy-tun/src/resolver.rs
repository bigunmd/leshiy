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

/// How often domain rules are re-resolved while a session is up. Larger than a manual-only
/// session would need, because subscription lists can hold thousands of domains.
pub(crate) const REFRESH: Duration = Duration::from_secs(1800);

/// Cap on the number of domains resolved per direction — guards against a pathological
/// subscription list. Excess is dropped (with a warning), never silently.
pub(crate) const MAX_DOMAINS: usize = 50_000;

/// Above this many resolved routes in one direction, warn about routing-table bloat. The engine's
/// static-plan `ROUTE_WARN_THRESHOLD` can't see these runtime, domain-driven routes (each domain
/// can fan out to many A/AAAA records), so the visibility has to live here (M12).
pub(crate) const RESOLVED_ROUTE_WARN_THRESHOLD: usize = 5000;

/// How many `getaddrinfo` lookups run concurrently (bounds the blocking-pool pressure while
/// still resolving thousands of domains in seconds rather than minutes).
const RESOLVE_CONCURRENCY: usize = 64;

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
    // Domain resolution can fan a modest domain list into a large route set; surface that here,
    // since the engine's static-plan route-count warning can't account for these routes (M12).
    if resolved.len() > RESOLVED_ROUTE_WARN_THRESHOLD {
        let dir = match mode {
            SplitMode::Include => "include",
            SplitMode::Exclude => "exclude",
        };
        tracing::warn!(
            count = resolved.len(),
            direction = dir,
            "split-tunnel: domain resolution produced a large route set; routing-table bloat / slow install"
        );
    }
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

/// Cap a domain list to [`MAX_DOMAINS`], returning the kept slice and whether it was truncated.
fn capped(domains: &[String]) -> (&[String], bool) {
    if domains.len() > MAX_DOMAINS {
        (&domains[..MAX_DOMAINS], true)
    } else {
        (domains, false)
    }
}

/// Resolve `domains` to host CIDRs (`/32` for IPv4, `/128` for IPv6) via the system resolver,
/// with bounded concurrency so large subscription lists resolve in seconds. Both families are
/// emitted; a v6 route is a no-op when the session doesn't carry IPv6. Unresolvable domains are
/// skipped (logged); the list is capped to [`MAX_DOMAINS`] (warned, never silent).
pub async fn resolve_domains(domains: &[String]) -> BTreeSet<Cidr> {
    let total = domains.len();
    let (domains, truncated) = capped(domains);
    if truncated {
        tracing::warn!(
            total,
            "split-tunnel: domain list exceeds {MAX_DOMAINS}; resolving only the first {MAX_DOMAINS}"
        );
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(RESOLVE_CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for d in domains {
        let d = d.clone();
        let sem = sem.clone();
        tasks.spawn(async move {
            // Permit is held for the lookup, bounding concurrent getaddrinfo calls.
            let _permit = sem.acquire().await;
            resolve_one(&d).await
        });
    }
    let mut out = BTreeSet::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(cidrs) = res {
            out.extend(cidrs);
        }
    }
    out
}

/// Resolve a single domain to its host CIDRs (`/32` for IPv4, `/128` for IPv6). Empty on
/// failure (logged). Both families are emitted; the per-OS backend decides whether a v6 route is
/// installable (it drops v6 when the session doesn't carry IPv6 — a safe no-op).
async fn resolve_one(domain: &str) -> Vec<Cidr> {
    // `lookup_host` needs a port; 0 is fine since we only use the addresses.
    match tokio::net::lookup_host((domain, 0)).await {
        Ok(addrs) => addrs
            .map(|a| match a.ip() {
                IpAddr::V4(v4) => Cidr {
                    addr: v4.into(),
                    prefix: 32,
                },
                IpAddr::V6(v6) => Cidr {
                    addr: v6.into(),
                    prefix: 128,
                },
            })
            .collect(),
        Err(e) => {
            tracing::warn!(domain = %domain, "split-tunnel: resolve failed: {e}");
            Vec::new()
        }
    }
}

/// Periodically resolve the plan's **include** and **exclude** domains and apply the route
/// changes via `ctrl`, forever (the engine aborts this task when the session ends). Include
/// domains become via-tun routes, exclude domains become bypass routes; each direction keeps
/// its own diff baseline. The dynamic routes are cleaned up by the session teardown guard, so
/// abort is safe.
pub async fn run_resolver(
    ctrl: Arc<dyn RouteController>,
    include_domains: Vec<String>,
    exclude_domains: Vec<String>,
    interval: Duration,
) {
    let mut inc_state = ResolverState::new();
    let mut exc_state = ResolverState::new();
    loop {
        if !include_domains.is_empty() {
            let resolved = resolve_domains(&include_domains).await;
            apply_resolution(&*ctrl, SplitMode::Include, &mut inc_state, resolved).await;
        }
        if !exclude_domains.is_empty() {
            let resolved = resolve_domains(&exclude_domains).await;
            apply_resolution(&*ctrl, SplitMode::Exclude, &mut exc_state, resolved).await;
        }
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

    fn host6(s: &str) -> Cidr {
        Cidr {
            addr: s.parse().unwrap(),
            prefix: 128,
        }
    }

    /// `lookup_host` returns IP literals verbatim (no DNS), so passing one exercises the
    /// address→CIDR mapping deterministically and offline.
    #[tokio::test]
    async fn resolve_one_maps_families_to_host_prefixes() {
        assert_eq!(resolve_one("127.0.0.1").await, vec![host("127.0.0.1")]);
        // v6 was previously dropped; it must now map to a /128 so v6 domain rules apply.
        assert_eq!(resolve_one("::1").await, vec![host6("::1")]);
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

    #[test]
    fn capped_truncates_past_the_limit() {
        let small: Vec<String> = (0..10).map(|i| format!("d{i}.example")).collect();
        let (kept, trunc) = capped(&small);
        assert_eq!(kept.len(), 10);
        assert!(!trunc);

        let big: Vec<String> = (0..MAX_DOMAINS + 5)
            .map(|i| format!("d{i}.example"))
            .collect();
        let (kept, trunc) = capped(&big);
        assert_eq!(kept.len(), MAX_DOMAINS);
        assert!(trunc);
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
