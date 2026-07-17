//! Linux privileged ops: TUN device (rust-tun), routes (net-route), DNS (resolv.conf),
//! and an IPv6 disable kill-switch — all restored on teardown.
use super::{PrivilegedOps, RouteController, TunSession};
use crate::route_plan::{Cidr, RoutePlan};
use net_route::{Handle, Route};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

pub struct LinuxOps;

const RESOLV: &str = "/etc/resolv.conf";
const IPV6_ALL: &str = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
const IPV6_DEFAULT: &str = "/proc/sys/net/ipv6/conf/default/disable_ipv6";
/// iproute2 binary, used only in teardown to remove `bypass` routes synchronously (Drop is
/// not async, and unlike the via-tun routes these don't auto-clear when the device drops).
const IP: &str = "ip";

/// Policy routing for the full-tunnel default override. Rather than blanket the *main* table
/// with `0.0.0.0/1`+`128.0.0.0/1` (which trips docker/IPAM's "candidate subnet overlaps a host
/// route" check → "all predefined address pools have been fully subnetted"), the override rides
/// a private table selected by two `ip rule`s, leaving the main table with only specific routes
/// plus the untouched real default (which docker ignores):
///   pref 32764: `table main suppress_prefixlength 0` — use main but NOT its default route, so
///               the server `/32`, LAN, docker bridges, and split includes/excludes still win.
///   pref 32765: `table 51821`                         — else fall through to the tunnel default.
/// Both priorities sit just above the main table's own rule (32766) so main's specific routes
/// are consulted first. The private-table routes point at the TUN and auto-clear when it drops;
/// the two rules do NOT, so teardown deletes them explicitly.
const RT_TABLE: &str = "51821";
const RULE_PREF_SUPPRESS: &str = "32764";
const RULE_PREF_TUN: &str = "32765";

#[async_trait::async_trait]
impl PrivilegedOps for LinuxOps {
    const CARRIES_V6: bool = true;

    async fn start(
        &self,
        tun_name: &str,
        mtu: u16,
        plan: &RoutePlan,
        dns: &[IpAddr],
        force_dns: bool,
        ipv6_killswitch: bool,
    ) -> std::io::Result<TunSession> {
        // The TUN interface always carries an IPv4 address; IPv6 is dual-stacked on top when
        // `plan.tun_addr6` is set (else it stays fail-closed via the kill-switch below).
        let IpAddr::V4(tun4) = plan.tun_addr else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tun_addr must be IPv4",
            ));
        };

        // 1. Create + bring up the TUN device.
        let mut cfg = tun::Configuration::default();
        cfg.tun_name(tun_name)
            .address(tun4)
            .netmask(Ipv4Addr::new(255, 255, 255, 0))
            .mtu(mtu)
            .up();
        cfg.platform_config(|p| {
            p.ensure_root_privileges(true);
        });
        let device = tun::create_as_async(&cfg).map_err(to_io)?;

        // 1b. Dual-stack: assign the IPv6 TUN address so IPv6 can ride the tunnel. Best-effort —
        //     if the host has IPv6 disabled the `ip -6 addr add` fails; we then fall closed to
        //     the kill-switch (below) rather than leave IPv6 leaking around a half-set-up tunnel.
        let carry_v6 = match plan.tun_addr6 {
            Some(IpAddr::V6(v6)) => match add_v6_addr(tun_name, v6).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!(%v6, "failed to assign IPv6 TUN address ({e}); failing closed to the IPv6 kill-switch");
                    false
                }
            },
            _ => false,
        };

        // 2. Routes — applied in ONE `ip -batch` process: the server-host exception (so
        //    encrypted packets to the server escape the tunnel), the specific include CIDRs
        //    (`dev tun`, main table), the bypass routes (excluded CIDRs via the original
        //    gateway), and — for the full-tunnel default override — a single `default`/`::/0` in
        //    the private [`RT_TABLE`] selected by policy `ip rule`s. The override is deliberately
        //    kept OUT of the main table so it can't blanket every candidate subnet docker's IPAM
        //    might pick (which yields "all predefined address pools have been fully subnetted").
        //    A subscription can carry thousands of CIDRs; batching keeps connect fast, and
        //    `-force` keeps going past a bad/duplicate line instead of failing the session.
        let ifindex = ifindex_of(tun_name)?;
        let batch = build_route_batch(plan, tun_name, carry_v6);
        let installed_bypass: Arc<Mutex<Vec<Cidr>>> = Arc::new(Mutex::new(batch.bypass));
        // Best-effort pre-clean of any policy rules a prior (hard-killed) session left behind.
        // Expected to no-op on a clean connect, so its stderr is ignored — counting it would fire
        // a spurious "traffic may not be routed" warning every time.
        ip_batch_quiet(&batch.preclean).await;
        ip_batch(&batch.install).await?;

        // 3. DNS: force the configured resolver(s) so queries ride the tunnel. Skipped in
        //    Include mode (most traffic is direct; the system resolver is left untouched).
        let resolv_backup = if force_dns && !dns.is_empty() {
            let prior = std::fs::read(RESOLV).ok();
            let body: String = dns.iter().map(|ip| format!("nameserver {ip}\n")).collect();
            std::fs::write(RESOLV, body)?;
            prior
        } else {
            None
        };

        // 4. IPv6 kill-switch (fail-closed): disable v6 so it can't leak around the tunnel.
        //    Applied when the caller asked for it (IPv4-only session) OR when we intended to
        //    carry v6 but couldn't assign the address (so v6 would otherwise leak). Skipped when
        //    v6 is genuinely carried, and in Include mode (the un-tunneled majority stays direct).
        let apply_killswitch = ipv6_killswitch || (plan.tun_addr6.is_some() && !carry_v6);
        let (ipv6_all_backup, ipv6_default_backup) = if apply_killswitch {
            let all = std::fs::read_to_string(IPV6_ALL).ok();
            let def = std::fs::read_to_string(IPV6_DEFAULT).ok();
            let _ = std::fs::write(IPV6_ALL, "1");
            let _ = std::fs::write(IPV6_DEFAULT, "1");
            (all, def)
        } else {
            (None, None)
        };

        let controller = Arc::new(LinuxController {
            handle: Handle::new()?,
            gateway: plan.server_exception.gateway,
            gateway6: plan.orig_gateway6,
            ifindex,
            carry_v6,
            installed_bypass: installed_bypass.clone(),
        });
        let guard = LinuxTeardown {
            resolv_backup,
            ipv6_all_backup,
            ipv6_default_backup,
            installed_bypass,
            policy_rules_teardown: batch.teardown_rules,
        };
        Ok(TunSession {
            device,
            guard: Box::new(guard),
            controller,
        })
    }
}

/// Live runtime route control for the Linux session: `net_route` add/delete for the resolved
/// domain routes. Bypass (Exclude) additions are tracked in `installed_bypass` so the teardown
/// guard can remove them even on a hard abort; via_tun (Include) routes auto-clear on device
/// drop and aren't tracked.
struct LinuxController {
    handle: Handle,
    gateway: IpAddr,
    /// Original IPv6 default gateway (from the plan), used to route resolved v6 bypass rules.
    /// `None` when v6 isn't carried or no v6 default route exists — a v6 bypass is then a no-op.
    gateway6: Option<IpAddr>,
    ifindex: u32,
    /// Whether IPv6 is carried through the tunnel this session. When false, resolved v6 domain
    /// routes are ignored (v6 is either fail-closed or out of scope).
    carry_v6: bool,
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

impl LinuxController {
    /// The original gateway to bypass a resolved CIDR through, by address family. `None` for a v6
    /// CIDR when v6 isn't carried or no v6 gateway is known — the caller then makes it a no-op
    /// (the CIDR rides the tunnel, which is safe: it never leaks around it).
    fn bypass_gateway(&self, c: &Cidr) -> Option<IpAddr> {
        if c.addr.is_ipv4() {
            self.gateway.is_ipv4().then_some(self.gateway)
        } else if self.carry_v6 {
            self.gateway6
        } else {
            None
        }
    }
}

#[async_trait::async_trait]
impl RouteController for LinuxController {
    async fn add_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let Some(gw) = self.bypass_gateway(c) else {
            tracing::debug!(cidr = %c, "split-tunnel: no gateway for this family; bypass rides the tunnel");
            return Ok(());
        };
        // Record BEFORE the OS call: if this task is aborted mid-syscall the kernel may already
        // have installed the route, so teardown must know to remove it — otherwise a bypass route
        // pointing at the original gateway leaks and survives disconnect (H7). A failed add leaves
        // a spurious entry, which teardown's best-effort delete simply no-ops.
        self.installed_bypass
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(c.clone());
        self.handle
            .add(&Route::new(c.addr, c.prefix).with_gateway(gw))
            .await?;
        Ok(())
    }
    async fn remove_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let Some(gw) = self.bypass_gateway(c) else {
            return Ok(());
        };
        let _ = self
            .handle
            .delete(&Route::new(c.addr, c.prefix).with_gateway(gw))
            .await;
        self.installed_bypass
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|x| x != c);
        Ok(())
    }
    async fn add_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        // A v6 via-tun route only makes sense when v6 is carried (the TUN has a v6 address).
        if c.addr.is_ipv6() && !self.carry_v6 {
            return Ok(());
        }
        self.handle
            .add(&Route::new(c.addr, c.prefix).with_ifindex(self.ifindex))
            .await
    }
    async fn remove_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        if c.addr.is_ipv6() && !self.carry_v6 {
            return Ok(());
        }
        let _ = self
            .handle
            .delete(&Route::new(c.addr, c.prefix).with_ifindex(self.ifindex))
            .await;
        Ok(())
    }
}

/// Assign an IPv6 address to the TUN interface (`ip -6 addr add <v6>/64 dev <name>`). The
/// interface's IPv4 address is set by rust-tun at creation; rust-tun's config carries only one
/// address, so the v6 one is added out-of-band here. Fails if the host has IPv6 disabled.
async fn add_v6_addr(tun_name: &str, v6: Ipv6Addr) -> std::io::Result<()> {
    let status = tokio::process::Command::new(IP)
        .args(["-6", "addr", "add", &format!("{v6}/64"), "dev", tun_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "ip -6 addr add {v6}/64 dev {tun_name} exited {status}"
        )))
    }
}

/// Restores DNS + IPv6 state on drop, removes any split-tunnel `bypass` routes, and deletes the
/// policy `ip rule`s that selected the private-table default override. The default-override /
/// via-tun routes auto-clear when the TUN device is dropped (the interface disappears); the
/// `bypass` routes point at the original gateway and the policy rules aren't tied to any device,
/// so both are removed here.
struct LinuxTeardown {
    resolv_backup: Option<Vec<u8>>,
    ipv6_all_backup: Option<String>,
    ipv6_default_backup: Option<String>,
    /// All bypass routes still installed (static + resolver-added) — removed on teardown.
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
    /// `ip -batch` `rule del` lines for the policy rules (empty when no override was installed).
    policy_rules_teardown: String,
}

impl Drop for LinuxTeardown {
    fn drop(&mut self) {
        // Best-effort; teardown must never panic. `Drop` is synchronous, so batch the deletes
        // through one `ip -batch` process (sync) rather than thousands of `ip route del` spawns.
        // The bypass route deletes and the policy-rule deletes share the one batch.
        // Poison-tolerant lock (matching the windows/macos teardowns): a panic elsewhere must not
        // make this teardown panic and skip the DNS/IPv6 kill-switch restore below (M11).
        let mut batch: String = self
            .installed_bypass
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|c| format!("route del {c}\n"))
            .collect();
        batch.push_str(&self.policy_rules_teardown);
        if !batch.is_empty() {
            use std::io::Write;
            if let Ok(mut child) = std::process::Command::new(IP)
                .args(["-force", "-batch", "-"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(batch.as_bytes());
                }
                let _ = child.wait();
            }
        }
        if let Some(b) = &self.resolv_backup {
            let _ = std::fs::write(RESOLV, b);
        }
        if let Some(v) = &self.ipv6_all_backup {
            let _ = std::fs::write(IPV6_ALL, v.trim());
        }
        if let Some(v) = &self.ipv6_default_backup {
            let _ = std::fs::write(IPV6_DEFAULT, v.trim());
        }
    }
}

/// The `ip -batch` scripts derived from a [`RoutePlan`], plus the bypass CIDRs to track.
struct RouteBatch {
    /// Best-effort `rule del`s run BEFORE `install`, uncounted, to clear any policy rules a
    /// prior session left behind (a hard kill skips teardown, and `ip rule add` doesn't dedupe).
    /// These are EXPECTED to fail when nothing matches, so they run in their own pass whose
    /// stderr is ignored — otherwise they'd inflate `install`'s failure count and fire a
    /// misleading "traffic may not be routed" warning on every clean connect.
    preclean: String,
    /// Route/rule commands to install (main-table specifics + the private-table default + the
    /// two policy `ip rule`s). One `ip -batch` line each. These SHOULD succeed, so their failures
    /// are counted and warned about.
    install: String,
    /// Commands run on teardown to delete the policy `ip rule`s (empty when no override was
    /// installed). The private-table routes auto-clear with the TUN, so only the rules are here.
    teardown_rules: String,
    /// Bypass CIDRs installed in the main table (via the original gateway) — tracked so teardown
    /// removes them (they point at the original gateway, so they don't auto-clear with the TUN).
    bypass: Vec<Cidr>,
}

/// Pure translation of a [`RoutePlan`] into `ip -batch` scripts. Kept side-effect-free (no
/// process spawns, no logging) so it's unit-testable on any host — the privileged `ip` calls
/// live in [`LinuxOps::start`]. `carry_v6` gates whether IPv6 entries are emitted (the TUN got a
/// v6 address); when false, v6 is fail-closed by the caller's kill-switch and skipped here.
///
/// The default-override halves (`0.0.0.0/1`+`128.0.0.0/1`, `::/1`+`8000::/1`) are pulled OUT of
/// the main table and expressed as a single `default`/`::/0` in the private [`RT_TABLE`] plus
/// the policy rules — this is what keeps the main table free of a covering route so docker's
/// IPAM can still auto-allocate a bridge subnet while the tunnel is up.
fn build_route_batch(plan: &RoutePlan, tun_name: &str, carry_v6: bool) -> RouteBatch {
    let mut install = String::new();
    let mut preclean = String::new();
    let mut bypass = Vec::new();

    // The server-host exception escapes the tunnel via the original gateway (main table), so
    // the encrypted packets to the server don't loop back in. Under policy routing it's a
    // specific `/32`|`/128` in main, honored ahead of the tunnel default by the suppress rule.
    let exc = &plan.server_exception;
    if exc.dest.addr.is_ipv4() || carry_v6 {
        install.push_str(&format!("route add {} via {}\n", exc.dest, exc.gateway));
    }

    // Partition `via_tun` into the default-override halves (→ private-table default, below) and
    // the specific include routes (→ main table, `dev tun`, as before). Includes stay in main so
    // the suppress rule lets them win over the tunnel default via longest-prefix-match.
    let mut v4_override = false;
    let mut v6_override = false;
    for c in &plan.via_tun {
        if c.is_default_override() {
            if c.addr.is_ipv4() {
                v4_override = true;
            } else if carry_v6 {
                v6_override = true;
            }
            continue;
        }
        if c.addr.is_ipv4() || carry_v6 {
            install.push_str(&format!("route add {} dev {}\n", c, tun_name));
        }
    }

    // Bypass (Exclude) routes escape via the family-appropriate original gateway (main table).
    for b in &plan.bypass {
        if b.dest.addr.is_ipv6() && !carry_v6 {
            continue;
        }
        install.push_str(&format!("route add {} via {}\n", b.dest, b.gateway));
        bypass.push(b.dest.clone());
    }

    // Policy routing for the default override(s): a single default in the private table plus the
    // two selector rules, per address family that carries an override.
    let mut teardown_rules = String::new();
    let mut emit_policy = |fam6: bool| {
        let p = if fam6 { "-6 " } else { "" };
        let dst = if fam6 { "::/0" } else { "default" };
        let suppress = format!("priority {RULE_PREF_SUPPRESS} table main suppress_prefixlength 0");
        let tun_rule = format!("priority {RULE_PREF_TUN} table {RT_TABLE}");
        // Pre-delete (in the uncounted `preclean` pass) makes install idempotent: a session
        // hard-killed before teardown leaves its rules behind, and `ip rule add` doesn't dedupe —
        // without the pre-delete each reconnect would stack another identical rule. These deletes
        // are expected to no-op on a clean connect, so they're kept OUT of the counted `install`.
        preclean.push_str(&format!("{p}rule del {suppress}\n"));
        preclean.push_str(&format!("{p}rule del {tun_rule}\n"));
        install.push_str(&format!(
            "{p}route add {dst} dev {tun_name} table {RT_TABLE}\n"
        ));
        install.push_str(&format!("{p}rule add {suppress}\n"));
        install.push_str(&format!("{p}rule add {tun_rule}\n"));
        teardown_rules.push_str(&format!("{p}rule del {suppress}\n"));
        teardown_rules.push_str(&format!("{p}rule del {tun_rule}\n"));
    };
    if v4_override {
        emit_policy(false);
    }
    if v6_override {
        emit_policy(true);
    }

    RouteBatch {
        preclean,
        install,
        teardown_rules,
        bypass,
    }
}

/// Apply many route changes in a SINGLE `ip -batch` process (commands one per line on stdin,
/// e.g. `route add 1.2.3.0/24 dev leshiy0`). `-force` keeps going past per-line errors so a
/// bad/duplicate entry in a large list can't fail the batch. One process for thousands of
/// routes — vs. a netlink round-trip each — is what keeps connect fast with big subscriptions.
async fn ip_batch(script: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    if script.is_empty() {
        return Ok(());
    }
    let mut child = tokio::process::Command::new(IP)
        .args(["-force", "-batch", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        // Capture stderr so we can surface per-line failures. `-force` keeps going past a bad line
        // and (without this) those errors vanished — a failed route install (e.g. an Include
        // via_tun) would silently not route, so count and warn instead of swallowing.
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
        // `stdin` is dropped at the end of this block → `ip` sees EOF and runs the batch.
    }
    let out = child.wait_with_output().await?;
    let errors = out
        .stderr
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .count();
    if errors > 0 {
        tracing::warn!(
            failures = errors,
            "some routes failed to install (ip -batch); matching traffic may not be routed as planned"
        );
    }
    Ok(())
}

/// Like [`ip_batch`] but for commands EXPECTED to fail harmlessly (the idempotency pre-clean
/// `rule del`s): stderr is discarded and no warning is emitted. A missing rule is the normal
/// case on a clean connect, so counting these would cry wolf about routing every time.
async fn ip_batch_quiet(script: &str) {
    use tokio::io::AsyncWriteExt;
    if script.is_empty() {
        return;
    }
    let Ok(mut child) = tokio::process::Command::new(IP)
        .args(["-force", "-batch", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes()).await;
    }
    let _ = child.wait().await;
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Read an interface's index from sysfs (Linux), avoiding any `unsafe` FFI.
fn ifindex_of(name: &str) -> std::io::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?;
    s.trim()
        .parse::<u32>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_plan::RoutePlan;
    use leshiy_client::SplitMode;

    fn v4_full_tunnel() -> RoutePlan {
        RoutePlan::full_tunnel(
            "203.0.113.7".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn full_tunnel_keeps_main_table_clear_of_the_override() {
        let b = build_route_batch(&v4_full_tunnel(), "leshiy0", false);
        // The default override rides a PRIVATE table + policy rules, never the main table — this
        // is what stops docker's IPAM seeing every candidate subnet as already routed.
        assert!(
            b.install
                .contains("route add default dev leshiy0 table 51821")
        );
        assert!(
            b.install
                .contains("rule add priority 32764 table main suppress_prefixlength 0")
        );
        assert!(b.install.contains("rule add priority 32765 table 51821"));
        // No blanket /1 halves anywhere (they'd trip the docker overlap check).
        assert!(
            !b.install.contains("0.0.0.0/1"),
            "no v4 override in the batch"
        );
        assert!(!b.install.contains("128.0.0.0/1"));
        // The server host still escapes via the original gateway (specific route, main table).
        assert!(
            b.install
                .contains("route add 203.0.113.7/32 via 192.168.1.1")
        );
        // v4-only: nothing v6.
        assert!(!b.install.contains("-6 "));
        // The counted install batch adds rules but never deletes — the idempotency pre-deletes
        // live in the uncounted `preclean` pass so they can't inflate the failure warning.
        assert!(
            !b.install.contains("rule del"),
            "install must not delete rules"
        );
        assert!(
            b.preclean
                .contains("rule del priority 32764 table main suppress_prefixlength 0")
        );
        assert!(b.preclean.contains("rule del priority 32765 table 51821"));
        // Teardown removes exactly the two policy rules; the private-table route auto-clears.
        assert!(
            b.teardown_rules
                .contains("rule del priority 32764 table main suppress_prefixlength 0")
        );
        assert!(
            b.teardown_rules
                .contains("rule del priority 32765 table 51821")
        );
        assert!(b.bypass.is_empty());
    }

    #[test]
    fn dual_stack_full_tunnel_adds_v6_policy_routing() {
        let plan = RoutePlan::with_split(
            SplitMode::Exclude,
            &[],
            "203.0.113.7".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "10.71.0.2".parse().unwrap(),
            Some("fd00:71::2".parse().unwrap()),
        )
        .unwrap();
        let b = build_route_batch(&plan, "leshiy0", true);
        assert!(
            b.install
                .contains("-6 route add ::/0 dev leshiy0 table 51821")
        );
        assert!(
            b.install
                .contains("-6 rule add priority 32764 table main suppress_prefixlength 0")
        );
        assert!(
            b.teardown_rules
                .contains("-6 rule del priority 32765 table 51821")
        );
        // No blanket v6 override halves in the batch.
        assert!(!b.install.contains("::/1"));
        assert!(!b.install.contains("8000::/1"));
    }

    #[test]
    fn include_mode_installs_no_policy_routing() {
        // Include mode has no default override → no private table, no rules, and it never had the
        // docker collision (the main table's default is untouched).
        let plan = RoutePlan::with_split(
            SplitMode::Include,
            &[Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            }],
            "203.0.113.7".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "10.71.0.2".parse().unwrap(),
            None,
        )
        .unwrap();
        let b = build_route_batch(&plan, "leshiy0", false);
        assert!(b.install.contains("route add 10.0.0.0/8 dev leshiy0"));
        assert!(!b.install.contains("table 51821"));
        assert!(!b.install.contains("rule add"));
        assert!(b.teardown_rules.is_empty());
    }

    #[test]
    fn exclude_bypass_is_tracked_for_teardown() {
        let plan = RoutePlan::with_split(
            SplitMode::Exclude,
            &[Cidr {
                addr: "198.51.100.0".parse().unwrap(),
                prefix: 24,
            }],
            "203.0.113.7".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "10.71.0.2".parse().unwrap(),
            None,
        )
        .unwrap();
        let b = build_route_batch(&plan, "leshiy0", false);
        // The excluded net bypasses via the original gateway (main table) and is tracked so the
        // teardown guard removes it (it doesn't auto-clear with the device).
        assert!(
            b.install
                .contains("route add 198.51.100.0/24 via 192.168.1.1")
        );
        assert_eq!(b.bypass.len(), 1);
        assert_eq!(b.bypass[0].to_string(), "198.51.100.0/24");
        // The default override still applies under an Exclude base.
        assert!(
            b.install
                .contains("route add default dev leshiy0 table 51821")
        );
    }

    // Needs root + CAP_NET_ADMIN to create a real TUN and install routes, so it can't run on
    // a sandboxed host. `#[ignore]`d; an operator opts in explicitly. The non-ignored value is
    // that it compiles (type-checks the split-tunnel `start` path) under `cargo test`.
    #[tokio::test]
    #[ignore = "requires root + CAP_NET_ADMIN; run: sudo -E cargo test -p leshiy-tun -- --ignored linux_split_exclude_up"]
    async fn linux_split_exclude_up() {
        let excl = Cidr {
            addr: "198.51.100.0".parse().unwrap(),
            prefix: 24,
        };
        let plan = RoutePlan::with_split(
            SplitMode::Exclude,
            &[excl],
            "203.0.113.7".parse().unwrap(),
            "127.0.0.1".parse().unwrap(), // harmless gateway for the smoke
            "10.71.0.2".parse().unwrap(),
            None,
        )
        .unwrap();
        let sess = LinuxOps
            .start(
                "leshiy9",
                1400,
                &plan,
                &["1.1.1.1".parse().unwrap()],
                true,
                true,
            )
            .await
            .expect("tun + split routes should come up");
        // `ip route` should now show 198.51.100.0/24 via 127.0.0.1 and 0/1+128/1 via leshiy9.
        drop(sess); // restores DNS/IPv6 and deletes the bypass route
    }

    // Exercises the live RouteController used for resolved domain rules: add a dynamic bypass
    // route, then remove it. Needs a real default gateway so `net_route add ... via gw`
    // succeeds. `#[ignore]`d; runtime-only.
    #[tokio::test]
    #[ignore = "requires root + CAP_NET_ADMIN + a real default gateway; run: sudo -E cargo test -p leshiy-tun -- --ignored linux_controller_bypass_add_remove"]
    async fn linux_controller_bypass_add_remove() {
        let gw = crate::discover::default_gateway_v4()
            .await
            .expect("a default gateway");
        let plan = RoutePlan::full_tunnel(
            "203.0.113.7".parse().unwrap(),
            gw,
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        let sess = LinuxOps
            .start(
                "leshiy8",
                1400,
                &plan,
                &["1.1.1.1".parse().unwrap()],
                true,
                true,
            )
            .await
            .expect("tun up");
        let c = Cidr {
            addr: "198.51.100.0".parse().unwrap(),
            prefix: 24,
        };
        sess.controller.add_bypass(&c).await.expect("add bypass");
        sess.controller
            .remove_bypass(&c)
            .await
            .expect("remove bypass");
        drop(sess); // teardown restores DNS/IPv6 and removes any remaining bypass routes
    }
}
