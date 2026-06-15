//! Rule **subscriptions**: remote community rule lists fetched and applied to split-tunnel.
//! Each subscription has its own direction ([`SplitMode`]) — Include ("route through the VPN")
//! or Exclude ("keep off the VPN") — independent of the manual ruleset's mode.
//!
//! The desktop app fetches each enabled subscription (conditional GET), parses it with the
//! `leshiy-client` parsers via [`parse_subscription`], caches the result ([`SubscriptionCache`]),
//! and merges manual rules + enabled subscriptions into the two-directional
//! [`SplitPlan`](crate::SplitPlan) passed to the helper. The privileged helper never fetches.
use crate::split_tunnel::{RuleSet, SplitMode, SplitParseError, SplitTunnel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Wire/text format of a subscription source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubFormat {
    /// One rule per line — CIDR/IP or domain (auto-detected). Covers plain CIDR lists too.
    Lines,
    /// Hosts file (`<sink-ip> <hostname...>`) — domains only.
    Hosts,
    /// v2ray/sing-box geosite domain-list (`domain:`/`full:` prefixes) — domains only.
    DomainList,
}

/// A configured remote rule list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// Stable id (also the cache key).
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: SubFormat,
    /// Which direction this subscription's rules apply to.
    pub mode: SplitMode,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// One subscription's last successful fetch: the parsed rules plus HTTP validators for a
/// conditional re-fetch and a timestamp for staleness checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionCacheEntry {
    #[serde(default)]
    pub rules: RuleSet,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    /// Unix seconds of the last successful fetch (0 = never).
    #[serde(default)]
    pub fetched_at: u64,
}

/// Persisted cache of all subscriptions' fetched rules, keyed by subscription id. Stored
/// separately from `Settings` so a settings write never drops fetched data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionCache {
    #[serde(default)]
    pub entries: BTreeMap<String, SubscriptionCacheEntry>,
}

impl SubscriptionCache {
    pub fn get(&self, id: &str) -> Option<&SubscriptionCacheEntry> {
        self.entries.get(id)
    }
    pub fn insert(&mut self, id: String, entry: SubscriptionCacheEntry) {
        self.entries.insert(id, entry);
    }
}

/// Validate a subscription URL before it is fetched (M3).
///
/// Only `https://` is permitted. A cleartext `http://` fetch lets an on-path
/// adversary — the exact threat this tool defends against — serve a malicious
/// rule list and force chosen traffic out of (or into) the tunnel. The scheme
/// check is case-insensitive and ignores surrounding whitespace.
pub fn validate_subscription_url(url: &str) -> Result<(), &'static str> {
    let u = url.trim();
    if u.len() >= 8 && u[..8].eq_ignore_ascii_case("https://") && u.len() > 8 {
        Ok(())
    } else {
        Err("subscription URL must use https://")
    }
}

/// Parse fetched subscription text into a [`RuleSet`] according to `format`. The mode is
/// irrelevant here (the subscription carries its own direction), so a placeholder is used.
pub fn parse_subscription(format: SubFormat, text: &str) -> Result<RuleSet, SplitParseError> {
    let st = match format {
        SubFormat::Lines => SplitTunnel::parse_lines(SplitMode::Exclude, text)?,
        SubFormat::Hosts => SplitTunnel::parse_hosts(SplitMode::Exclude, text)?,
        SubFormat::DomainList => SplitTunnel::parse_domain_list(SplitMode::Exclude, text)?,
    };
    Ok(RuleSet {
        cidrs: st.cidrs,
        domains: st.domains,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_subscription_urls() {
        assert!(validate_subscription_url("https://example.com/list.txt").is_ok());
        assert!(validate_subscription_url("HTTPS://EXAMPLE.com/x").is_ok());
        assert!(validate_subscription_url("  https://example.com/x  ").is_ok());
        assert!(validate_subscription_url("http://example.com/list.txt").is_err());
        assert!(validate_subscription_url("ftp://example.com/x").is_err());
        assert!(validate_subscription_url("file:///etc/passwd").is_err());
        assert!(validate_subscription_url("https://").is_err()); // scheme only, no host
        assert!(validate_subscription_url("example.com").is_err());
    }

    #[test]
    fn parse_subscription_dispatches_by_format() {
        let lines = parse_subscription(SubFormat::Lines, "10.0.0.0/8\nexample.com\n").unwrap();
        assert_eq!(lines.cidrs.len(), 1);
        assert_eq!(lines.domains, vec!["example.com"]);

        let hosts = parse_subscription(SubFormat::Hosts, "0.0.0.0 ads.example.com\n").unwrap();
        assert_eq!(hosts.domains, vec!["ads.example.com"]);
        assert!(hosts.cidrs.is_empty());

        let dl =
            parse_subscription(SubFormat::DomainList, "domain:google.com\nfull:x.y.z\n").unwrap();
        assert_eq!(dl.domains, vec!["google.com", "x.y.z"]);
    }

    #[test]
    fn subscription_serde_round_trip_and_enabled_default() {
        let s = Subscription {
            id: "refilter-ips".into(),
            name: "Re:filter IPs".into(),
            url: "https://example/ipsum.lst".into(),
            format: SubFormat::Lines,
            mode: SplitMode::Include,
            enabled: true,
        };
        let back: Subscription = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        // `enabled` defaults to true when omitted.
        let j = r#"{"id":"a","name":"A","url":"u","format":"hosts","mode":"exclude"}"#;
        let s2: Subscription = serde_json::from_str(j).unwrap();
        assert!(s2.enabled);
    }

    #[test]
    fn cache_round_trips() {
        let mut c = SubscriptionCache::default();
        c.insert(
            "x".into(),
            SubscriptionCacheEntry {
                rules: RuleSet {
                    cidrs: vec![],
                    domains: vec!["a.example".into()],
                },
                etag: Some("\"abc\"".into()),
                last_modified: None,
                fetched_at: 1700000000,
            },
        );
        let back: SubscriptionCache =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }
}
