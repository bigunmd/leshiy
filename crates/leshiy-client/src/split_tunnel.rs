//! Global split-tunnel ruleset, shared by `Settings`, the helper control protocol, and (via
//! a boundary conversion) the TUN route planner. Pure and safe — no OS calls here.
//!
//! An **empty** ruleset means "plain full tunnel" (backward compatible): old settings/start
//! payloads without a `split_tunnel` field deserialize to `SplitTunnel::default()`.
//!
//! Two modes:
//! - **Exclude** (default): tunnel everything EXCEPT the listed CIDRs/domains (those bypass
//!   the tunnel via the original gateway).
//! - **Include**: the default route stays DIRECT; ONLY the listed CIDRs/domains ride the TUN.
//!
//! Rules are either IP **CIDRs** (a bare IP is promoted to a host route — `/32` v4, `/128`
//! v6) or **domains** (resolved to IPs at runtime by the engine; see `leshiy-tun::resolver`).
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Which direction the ruleset applies. Default = `Exclude`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitMode {
    /// Tunnel everything EXCEPT the listed nets (they bypass via the original gateway).
    #[default]
    Exclude,
    /// Default stays DIRECT; ONLY the listed nets go through the TUN.
    Include,
}

/// A parse-validated CIDR. Field-identical to `leshiy_tun::route_plan::Cidr`; converted at the
/// crate boundary (in `leshiy-tun`) to avoid a `leshiy-client -> leshiy-tun` dependency cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitCidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl std::fmt::Display for SplitCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl std::str::FromStr for SplitCidr {
    type Err = SplitParseError;
    /// Parse `addr/prefix`, or a bare IP (promoted to `/32` v4 / `/128` v6). Rejects a prefix
    /// wider than the address family allows.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some((a, p)) = s.split_once('/') {
            let addr: IpAddr = a
                .trim()
                .parse()
                .map_err(|_| SplitParseError::Cidr(s.into()))?;
            let prefix: u8 = p
                .trim()
                .parse()
                .map_err(|_| SplitParseError::Cidr(s.into()))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(SplitParseError::Cidr(s.into()));
            }
            Ok(SplitCidr { addr, prefix })
        } else {
            let addr: IpAddr = s.parse().map_err(|_| SplitParseError::Cidr(s.into()))?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Ok(SplitCidr { addr, prefix })
        }
    }
}

/// Errors from parsing a ruleset.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SplitParseError {
    #[error("invalid CIDR/IP: {0}")]
    Cidr(String),
}

/// A global split-tunnel ruleset (the **manual** rules edited in the GUI). Empty == plain full
/// tunnel. A single direction, given by `mode`. Subscriptions (each with their own direction)
/// are combined with this into a [`SplitPlan`] at connect time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SplitTunnel {
    #[serde(default)]
    pub mode: SplitMode,
    #[serde(default)]
    pub cidrs: Vec<SplitCidr>,
    #[serde(default)]
    pub domains: Vec<String>,
}

/// One direction's CIDRs + domains.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RuleSet {
    #[serde(default)]
    pub cidrs: Vec<SplitCidr>,
    #[serde(default)]
    pub domains: Vec<String>,
}

impl RuleSet {
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.domains.is_empty()
    }

    /// Append another set, de-duplicating CIDRs and domains.
    pub fn extend(&mut self, other: &RuleSet) {
        for c in &other.cidrs {
            if !self.cidrs.contains(c) {
                self.cidrs.push(*c);
            }
        }
        for d in &other.domains {
            if !self.domains.contains(d) {
                self.domains.push(d.clone());
            }
        }
    }
}

/// The **two-directional** plan the engine actually applies: a base policy (`base_mode`) plus
/// `include` rules (routed *into* the tunnel) and `exclude` rules (routed *out*, bypassing it),
/// which coexist — the OS routing table resolves overlaps by longest-prefix-match. Domains
/// resolve to host routes (`/32`), so a domain rule always wins over any CIDR.
///
/// - `base_mode == Exclude` (default): default route is tunneled; `exclude` bypasses.
/// - `base_mode == Include`: default route stays direct; only `include` is tunneled.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SplitPlan {
    #[serde(default)]
    pub base_mode: SplitMode,
    #[serde(default)]
    pub include: RuleSet,
    #[serde(default)]
    pub exclude: RuleSet,
}

impl SplitPlan {
    /// No rules → plain full tunnel (`base_mode` still selects the default policy).
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// Build from the manual ruleset: its `mode` is the base policy, and its rules go into the
    /// **primary** direction — `exclude` when base is Exclude, `include` when base is Include.
    pub fn from_manual(manual: &SplitTunnel) -> SplitPlan {
        let set = RuleSet {
            cidrs: manual.cidrs.clone(),
            domains: manual.domains.clone(),
        };
        match manual.mode {
            SplitMode::Exclude => SplitPlan {
                base_mode: SplitMode::Exclude,
                exclude: set,
                include: RuleSet::default(),
            },
            SplitMode::Include => SplitPlan {
                base_mode: SplitMode::Include,
                include: set,
                exclude: RuleSet::default(),
            },
        }
    }

    /// Merge a subscription's rules into the given direction (de-duplicated).
    pub fn merge(&mut self, mode: SplitMode, rules: &RuleSet) {
        match mode {
            SplitMode::Include => self.include.extend(rules),
            SplitMode::Exclude => self.exclude.extend(rules),
        }
    }
}

impl SplitTunnel {
    /// No rules at all (regardless of mode) — the engine treats this as plain full tunnel.
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.domains.is_empty()
    }

    /// Parse the native line format: one rule per line; `#` begins a comment; blank lines are
    /// skipped; the first whitespace token of each line is the rule. A token is a **domain**
    /// if it isn't an IP/CIDR but contains a dot and an ASCII letter; otherwise it's parsed as
    /// an IP/CIDR (and a parse failure is an error).
    pub fn parse_lines(mode: SplitMode, text: &str) -> Result<Self, SplitParseError> {
        let mut cidrs = Vec::new();
        let mut domains = Vec::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let tok = line.split_whitespace().next().unwrap_or(line);
            if looks_like_domain(tok) {
                domains.push(tok.to_string());
            } else {
                cidrs.push(tok.parse::<SplitCidr>()?);
            }
        }
        Ok(SplitTunnel {
            mode,
            cidrs,
            domains,
        })
    }

    /// Import a hosts-file list: `<sink-ip> <hostname...>`. The sink IP column (usually
    /// `0.0.0.0`/`127.0.0.1`) is discarded; each hostname that looks like a domain becomes a
    /// domain rule. Lines without a domain-shaped hostname are skipped (no CIDRs are added).
    pub fn parse_hosts(mode: SplitMode, text: &str) -> Result<Self, SplitParseError> {
        let mut domains = Vec::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            let _sink = it.next(); // discard the sink-IP column
            for host in it {
                if looks_like_domain(host) {
                    domains.push(host.to_string());
                }
            }
        }
        Ok(SplitTunnel {
            mode,
            cidrs: Vec::new(),
            domains,
        })
    }
}

/// Everything before the first `#` on a line (the comment marker).
fn strip_comment(line: &str) -> &str {
    match line.split_once('#') {
        Some((before, _)) => before,
        None => line,
    }
}

/// A token is a domain if it parses as neither an IP nor a CIDR and contains a dot plus at
/// least one ASCII letter (so `1.2.3.4` is an IP, `example.com` a domain, `localhost` neither).
fn looks_like_domain(tok: &str) -> bool {
    if tok.parse::<IpAddr>().is_ok() {
        return false;
    }
    if tok.contains('/') {
        return false; // CIDR-shaped → not a domain
    }
    tok.contains('.') && tok.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty_exclude() {
        let st = SplitTunnel::default();
        assert_eq!(st.mode, SplitMode::Exclude);
        assert!(st.cidrs.is_empty());
        assert!(st.domains.is_empty());
        assert!(st.is_empty());
    }

    #[test]
    fn parse_line_format_cidrs_and_domains_and_comments() {
        let text = "\
# comment line
10.0.0.0/8
192.168.1.5      # trailing comment, host -> /32
2001:db8::/32
example.com
  sub.example.org
";
        let st = SplitTunnel::parse_lines(SplitMode::Exclude, text).unwrap();
        assert_eq!(st.mode, SplitMode::Exclude);
        assert_eq!(st.cidrs.len(), 3);
        assert!(st.cidrs.iter().any(|c| c.to_string() == "10.0.0.0/8"));
        assert!(st.cidrs.iter().any(|c| c.to_string() == "192.168.1.5/32"));
        assert!(st.cidrs.iter().any(|c| c.to_string() == "2001:db8::/32"));
        assert_eq!(st.domains, vec!["example.com", "sub.example.org"]);
    }

    #[test]
    fn bare_ipv4_becomes_slash_32_and_ipv6_slash_128() {
        let st = SplitTunnel::parse_lines(SplitMode::Include, "1.2.3.4\n2001:db8::1\n").unwrap();
        assert!(st.cidrs.iter().any(|c| c.to_string() == "1.2.3.4/32"));
        assert!(st.cidrs.iter().any(|c| c.to_string() == "2001:db8::1/128"));
    }

    #[test]
    fn rejects_bad_prefix_and_bad_addr() {
        assert!(SplitTunnel::parse_lines(SplitMode::Exclude, "10.0.0.0/40").is_err());
        // No dot+letter and not an IP/CIDR → parsed as CIDR → error.
        assert!(SplitTunnel::parse_lines(SplitMode::Exclude, "not_an_ip_or_domain").is_err());
    }

    #[test]
    fn json_round_trips_and_missing_fields_default() {
        let st = SplitTunnel::parse_lines(SplitMode::Include, "10.0.0.0/8\nexample.com\n").unwrap();
        let json = serde_json::to_string(&st).unwrap();
        let back: SplitTunnel = serde_json::from_str(&json).unwrap();
        assert_eq!(st, back);
        // Backward/forward compat: an empty object yields the default ruleset.
        let empty: SplitTunnel = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, SplitTunnel::default());
    }

    #[test]
    fn mode_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&SplitMode::Include).unwrap(),
            "\"include\""
        );
    }

    #[test]
    fn parse_hosts_extracts_domains_ignoring_sink_ip() {
        let hosts = "\
127.0.0.1 localhost
0.0.0.0 ads.example.com
0.0.0.0  tracker.example.net # comment
::1 ip6-localhost
";
        let st = SplitTunnel::parse_hosts(SplitMode::Exclude, hosts).unwrap();
        // `localhost`/`ip6-localhost` have no dot → skipped; sink IPs are NOT added as CIDRs.
        assert_eq!(st.domains, vec!["ads.example.com", "tracker.example.net"]);
        assert!(st.cidrs.is_empty());
    }

    #[test]
    fn parse_plain_cidr_list_is_the_line_parser() {
        let st =
            SplitTunnel::parse_lines(SplitMode::Include, "10.0.0.0/8\n172.16.0.0/12\n").unwrap();
        assert_eq!(st.cidrs.len(), 2);
    }

    #[test]
    fn split_plan_from_manual_maps_mode_to_primary_direction() {
        let excl =
            SplitTunnel::parse_lines(SplitMode::Exclude, "10.0.0.0/8\nbank.example\n").unwrap();
        let pe = SplitPlan::from_manual(&excl);
        assert_eq!(pe.base_mode, SplitMode::Exclude);
        assert_eq!(pe.exclude.cidrs.len(), 1);
        assert_eq!(pe.exclude.domains, vec!["bank.example"]);
        assert!(pe.include.is_empty());

        let incl = SplitTunnel::parse_lines(SplitMode::Include, "1.2.3.0/24\n").unwrap();
        let pi = SplitPlan::from_manual(&incl);
        assert_eq!(pi.base_mode, SplitMode::Include);
        assert_eq!(pi.include.cidrs.len(), 1);
        assert!(pi.exclude.is_empty());
    }

    #[test]
    fn split_plan_default_is_empty_exclude() {
        let p = SplitPlan::default();
        assert!(p.is_empty());
        assert_eq!(p.base_mode, SplitMode::Exclude);
    }

    #[test]
    fn split_plan_merge_dedups_into_directions() {
        let mut p = SplitPlan::default();
        let host = |s: &str| SplitCidr {
            addr: s.parse().unwrap(),
            prefix: 32,
        };
        let rs = RuleSet {
            cidrs: vec![host("1.1.1.1")],
            domains: vec!["a.example".into()],
        };
        p.merge(SplitMode::Include, &rs);
        p.merge(SplitMode::Include, &rs); // duplicate — must not double
        assert_eq!(p.include.cidrs.len(), 1);
        assert_eq!(p.include.domains.len(), 1);
        p.merge(SplitMode::Exclude, &rs);
        assert_eq!(p.exclude.cidrs.len(), 1);
    }
}
