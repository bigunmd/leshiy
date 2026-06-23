//! Live integration test against a throwaway VPS. Run on demand:
//!   LESHIY_TEST_SSH=root@1.2.3.4 LESHIY_TEST_PW=... cargo test -p leshiy-provision --test live_ssh -- --ignored --nocapture
use leshiy_provision::ssh::{RusshTransport, SshTarget, Transport};
use leshiy_provision::vault::SshSecret;

#[tokio::test]
#[ignore = "requires a real VPS via LESHIY_TEST_SSH / LESHIY_TEST_PW"]
async fn connects_and_runs_echo() {
    let spec = std::env::var("LESHIY_TEST_SSH").expect("LESHIY_TEST_SSH=user@host[:port]");
    let pw = std::env::var("LESHIY_TEST_PW").expect("LESHIY_TEST_PW");
    let (user, rest) = spec.split_once('@').unwrap();
    let (host, port) = rest
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap()))
        .unwrap_or((rest.to_string(), 22));
    let mut t = RusshTransport::new();
    let fp = t
        .connect(
            &SshTarget {
                host,
                port,
                user: user.into(),
            },
            &SshSecret::Password(pw.into()),
        )
        .await
        .unwrap();
    assert!(fp.starts_with("SHA256:"));
    let out = t.run("echo hello").await.unwrap();
    assert_eq!(out.stdout.trim(), "hello");
}
