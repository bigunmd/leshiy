//! SSH transport abstraction. The engine talks only to the `Transport` trait,
//! so tests run against `FakeTransport` with no live server.

pub use crate::ssh_russh::RusshTransport;

use crate::error::{Error, Result};
use crate::vault::SshSecret;
use async_trait::async_trait;

/// True when the private key in `pem` cannot be decoded without a passphrase —
/// i.e. it is encrypted (or otherwise unreadable as-is). Callers use this to
/// decide whether to prompt for a key passphrase. It runs the same decoder as
/// the connect path, so detection and use stay consistent across key formats
/// (OpenSSH, PKCS#5, PuTTY).
pub fn key_needs_passphrase(pem: &str) -> bool {
    russh::keys::decode_secret_key(pem, None).is_err()
}

/// Format a raw SHA-256 digest as an OpenSSH-style `SHA256:<base64-nopad>` string.
pub fn format_fp_sha256(digest: &[u8; 32]) -> String {
    use base64::Engine;
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

#[derive(Clone, Debug)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
}

#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    /// Convenience: turn a non-zero exit into `Error::Command`.
    pub fn ok(self) -> Result<CommandOutput> {
        if self.code == 0 {
            Ok(self)
        } else {
            Err(Error::Command {
                code: self.code,
                stderr: self.stderr,
            })
        }
    }
}

#[async_trait]
pub trait Transport: Send {
    /// Connect + authenticate. Returns the server host-key fingerprint
    /// (`SHA256:...`) for TOFU pinning by the caller.
    async fn connect(&mut self, target: &SshTarget, secret: &SshSecret) -> Result<String>;
    /// Run a command to completion, capturing stdout/stderr and exit code.
    async fn run(&mut self, cmd: &str) -> Result<CommandOutput>;
    /// Upload bytes to `remote_path` with the given unix mode.
    async fn put_file(&mut self, remote_path: &str, bytes: &[u8], mode: u32) -> Result<()>;
}

/// In-memory transport for tests: returns canned output keyed by substring.
#[doc(hidden)]
#[derive(Default)]
pub struct FakeTransport {
    host_key_fp: String,
    rules: Vec<(String, CommandOutput)>,
    /// (needle, outputs, next_index): successive matches return successive
    /// outputs; the last one repeats. Used to model transient-then-OK sequences.
    seq_rules: Vec<(String, Vec<CommandOutput>, usize)>,
    calls: std::sync::Mutex<Vec<String>>,
    pub put_files: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

impl FakeTransport {
    pub fn new() -> Self {
        Self {
            host_key_fp: "SHA256:fake".into(),
            ..Default::default()
        }
    }
    pub fn host_key(&mut self, fp: &str) -> &mut Self {
        self.host_key_fp = fp.to_string();
        self
    }
    /// First matching substring wins; register most-specific rules first.
    pub fn on(&mut self, contains: &str, out: CommandOutput) -> &mut Self {
        self.rules.push((contains.to_string(), out));
        self
    }
    /// Register a sequence of outputs for commands matching `contains`: the first
    /// match returns `outs[0]`, the next `outs[1]`, …, and the last repeats.
    /// Checked before single-output rules, so it wins when both would match.
    pub fn on_seq(&mut self, contains: &str, outs: Vec<CommandOutput>) -> &mut Self {
        self.seq_rules.push((contains.to_string(), outs, 0));
        self
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn connect(&mut self, _t: &SshTarget, _s: &SshSecret) -> Result<String> {
        Ok(self.host_key_fp.clone())
    }
    async fn run(&mut self, cmd: &str) -> Result<CommandOutput> {
        self.calls.lock().unwrap().push(cmd.to_string());
        for (needle, outs, idx) in &mut self.seq_rules {
            if !outs.is_empty() && cmd.contains(needle.as_str()) {
                let i = (*idx).min(outs.len() - 1);
                *idx += 1;
                return Ok(outs[i].clone());
            }
        }
        for (needle, out) in &self.rules {
            if cmd.contains(needle.as_str()) {
                return Ok(out.clone());
            }
        }
        Ok(CommandOutput {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
    async fn put_file(&mut self, remote_path: &str, bytes: &[u8], _mode: u32) -> Result<()> {
        self.put_files
            .lock()
            .unwrap()
            .push((remote_path.to_string(), bytes.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway ed25519 keys generated with ssh-keygen (test-only; not used anywhere).
    // ENC is protected by the passphrase "testpass"; UNENC has none.
    const UNENC: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCHfQtthGgl0YI5RpdlF6WedpxTRszeHbx+zKRrlyxDDQAAAIix6z3Cses9\n\
wgAAAAtzc2gtZWQyNTUxOQAAACCHfQtthGgl0YI5RpdlF6WedpxTRszeHbx+zKRrlyxDDQ\n\
AAAEBcxI43IsG4/ySrTIUnXxBTx30NQJfsRqPEq3dyTImQMId9C22EaCXRgjlGl2UXpZ52\n\
nFNGzN4dvH7MpGuXLEMNAAAABHRlc3QB\n\
-----END OPENSSH PRIVATE KEY-----\n";

    const ENC: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBPJME7Ni\n\
VI98JGK/2Jrqw+AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJzox0Yy523PWLsa\n\
CB8kyN3R0GIrjEhcAiFevSmoTbplAAAAkBN4QKpoYEXnkocY9X1Yx3N8NOmglOSgQgiNiI\n\
NleEAFznDtKLf+gdceGjzxkUbcWTZmL6o1/xhq/a2aGdx6v179U6u9Af4kRYbuxYabvDNF\n\
sr91fZSqBMVzKYgwF8/R+z7gi4hnqNneeL8xXlc3ss8ZYipZXaceE9E8rHp6E5tEjHqGGX\n\
DVDe8dQbh7Yei35g==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn unencrypted_key_needs_no_passphrase() {
        assert!(!key_needs_passphrase(UNENC));
    }

    #[test]
    fn encrypted_key_needs_passphrase() {
        assert!(key_needs_passphrase(ENC));
    }

    #[test]
    fn garbage_reports_needs_passphrase() {
        assert!(key_needs_passphrase("not a key at all"));
    }

    #[test]
    fn encrypted_key_decodes_with_correct_passphrase() {
        assert!(russh::keys::decode_secret_key(ENC, Some("testpass")).is_ok());
        assert!(russh::keys::decode_secret_key(ENC, Some("wrong")).is_err());
    }

    #[test]
    fn fingerprint_has_sha256_prefix() {
        // Deterministic 32-byte digest -> stable formatting.
        let digest = [0u8; 32];
        let fp = crate::ssh::format_fp_sha256(&digest);
        assert!(fp.starts_with("SHA256:"));
        assert!(fp.len() > "SHA256:".len());
    }

    #[tokio::test]
    async fn fake_connect_returns_pinned_fp_and_matches_commands() {
        let mut t = FakeTransport::new();
        t.host_key("SHA256:deadbeef").on(
            "docker ps",
            CommandOutput {
                code: 0,
                stdout: "leshiy\n".into(),
                stderr: String::new(),
            },
        );

        let fp = t
            .connect(
                &SshTarget {
                    host: "h".into(),
                    port: 22,
                    user: "root".into(),
                },
                &crate::vault::SshSecret::Password("x".to_string().into()),
            )
            .await
            .unwrap();
        assert_eq!(fp, "SHA256:deadbeef");

        let out = t.run("sudo docker ps --format '{{.Names}}'").await.unwrap();
        assert_eq!(out.stdout.trim(), "leshiy");
        assert_eq!(t.calls(), vec!["sudo docker ps --format '{{.Names}}'"]);
    }
}
