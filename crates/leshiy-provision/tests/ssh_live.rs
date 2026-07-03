//! Live SSH auth smoke test — `#[ignore]` by default so CI never needs a server.
//!
//! Verifies the RSA-SHA2 negotiation fix: an `id_rsa` (RSA) key that OpenSSH 8.8+
//! servers reject when signed with SHA-1 must authenticate via `RusshTransport`.
//! Read-only: it authenticates, runs `echo`, and disconnects — it provisions
//! nothing.
//!
//! Run against a real host:
//!   LESHIY_TEST_SSH_USER=mbigun \
//!   LESHIY_TEST_SSH_HOST=158.160.176.53 \
//!   LESHIY_TEST_SSH_KEY=$HOME/.ssh/id_rsa \
//!   cargo test -p leshiy-provision --test ssh_live -- --ignored --nocapture

use leshiy_provision::ssh::{RusshTransport, SshTarget, Transport};
use leshiy_provision::vault::SshSecret;
use zeroize::Zeroizing;

#[tokio::test]
#[ignore = "requires a live SSH host + key via LESHIY_TEST_SSH_* env vars"]
async fn rsa_key_authenticates_against_live_host() {
    let user = std::env::var("LESHIY_TEST_SSH_USER").expect("set LESHIY_TEST_SSH_USER");
    let host = std::env::var("LESHIY_TEST_SSH_HOST").expect("set LESHIY_TEST_SSH_HOST");
    let port = std::env::var("LESHIY_TEST_SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22u16);
    let key_path = std::env::var("LESHIY_TEST_SSH_KEY").expect("set LESHIY_TEST_SSH_KEY");
    let pem = Zeroizing::new(std::fs::read_to_string(&key_path).expect("read key"));

    let mut t = RusshTransport::new();
    let fp = t
        .connect(
            &SshTarget {
                host: host.clone(),
                port,
                user: user.clone(),
            },
            &SshSecret::PrivateKey {
                pem,
                passphrase: None,
            },
        )
        .await
        .expect("SSH publickey auth must succeed with the RSA key");
    assert!(fp.starts_with("SHA256:"), "got host-key fp: {fp}");
    eprintln!("authenticated {user}@{host}:{port}, host key {fp}");

    let out = t.run("echo leshiy-ssh-ok").await.expect("run echo");
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.trim(), "leshiy-ssh-ok");
}
