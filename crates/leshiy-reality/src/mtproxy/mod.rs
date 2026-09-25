//! Telegram MTProxy (fake-TLS, `ee` secrets) served from the REALITY listener (ADR-0035).
//!
//! A Telegram client's ClientHello carries an HMAC keyed by the proxy secret. The front door
//! checks it alongside the REALITY auth; a match is answered as MTProxy and relayed to a
//! Telegram DC through the server's [`Egress`](crate::Egress), anything else keeps falling
//! through to the borrowed site exactly as before.
mod faketls;
mod obfs2;
mod relay;

use crate::error::{RealityError, Result};
use rand::RngCore;
use zeroize::Zeroizing;

pub(crate) use relay::serve;

/// The 16-byte secret shared with Telegram clients through the `tg://proxy` link.
#[derive(Clone)]
pub struct MtProxySecret(Zeroizing<[u8; 16]>);

impl MtProxySecret {
    pub fn generate() -> Self {
        let mut s = Zeroizing::new([0u8; 16]);
        rand::rngs::OsRng.fill_bytes(&mut *s);
        Self(s)
    }

    /// Parse the 32-hex-char form stored in the server config.
    pub fn from_hex(s: &str) -> Result<Self> {
        let mut out = Zeroizing::new([0u8; 16]);
        hex::decode_to_slice(s.trim(), &mut *out)
            .map_err(|_| RealityError::Malformed("mtproxy secret must be 32 hex chars".into()))?;
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(*self.0)
    }

    fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for MtProxySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MtProxySecret(..)")
    }
}

/// The `tg://proxy` link for a fake-TLS proxy at `host_port` fronting `sni`. The SNI is baked
/// into the secret (`ee` ‖ secret ‖ hex(sni)): it is what the Telegram client puts in its
/// ClientHello, so it must be one of the REALITY server names to reach the right borrowed site.
pub fn tg_link(host_port: &str, secret: &MtProxySecret, sni: &str) -> String {
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p),
        _ => (host_port, "443"),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    format!(
        "tg://proxy?server={host}&port={port}&secret=ee{}{}",
        secret.to_hex(),
        hex::encode(sni)
    )
}

/// A ClientHello that carried a valid MTProxy MAC, ready to be served.
pub(crate) struct Authenticated {
    digest: faketls::ClientDigest,
    secret: MtProxySecret,
}

impl Authenticated {
    /// The ClientHello random as sent — unique per genuine connection, so it keys the replay
    /// guard.
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Check a ClientHello record payload against the configured secret.
pub(crate) fn authenticate(
    ch_payload: &[u8],
    secret: &MtProxySecret,
    now_secs: u32,
    max_skew: std::time::Duration,
) -> Option<Authenticated> {
    let digest = faketls::authenticate(ch_payload, secret.bytes(), now_secs, max_skew)?;
    Some(Authenticated {
        digest,
        secret: secret.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hex_roundtrips() {
        let s = MtProxySecret::generate();
        let back = MtProxySecret::from_hex(&s.to_hex()).unwrap();
        assert_eq!(s.bytes(), back.bytes());
    }

    #[test]
    fn secret_rejects_wrong_length_and_non_hex() {
        assert!(MtProxySecret::from_hex("abcd").is_err());
        assert!(MtProxySecret::from_hex(&"zz".repeat(16)).is_err());
        assert!(MtProxySecret::from_hex(&"ab".repeat(17)).is_err());
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = MtProxySecret::from_hex(&"ab".repeat(16)).unwrap();
        assert!(!format!("{s:?}").contains("ab"));
    }

    #[test]
    fn tg_link_encodes_fake_tls_secret_with_sni() {
        let s = MtProxySecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(
            tg_link("203.0.113.7:443", &s, "ya.ru"),
            "tg://proxy?server=203.0.113.7&port=443&secret=ee00112233445566778899aabbccddeeff79612e7275"
        );
    }

    #[test]
    fn tg_link_strips_ipv6_brackets_and_defaults_port() {
        let s = MtProxySecret::from_hex(&"00".repeat(16)).unwrap();
        assert!(
            tg_link("[2001:db8::1]:8443", &s, "a")
                .starts_with("tg://proxy?server=2001:db8::1&port=8443&")
        );
        assert!(
            tg_link("vps.example", &s, "a").starts_with("tg://proxy?server=vps.example&port=443&")
        );
    }
}
