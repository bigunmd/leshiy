//! Real SSH transport backed by `russh`. The handler captures the server's
//! host-key fingerprint for TOFU pinning by the caller.

use crate::error::{Error, Result};
use crate::ssh::{CommandOutput, SshTarget, Transport};
use crate::vault::SshSecret;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Rewrite a leading `sudo ` into a non-interactive `sudo -S -p ''` that reads
/// the password from stdin. Commands that don't start with `sudo ` (e.g. the
/// docker probe) are returned unchanged. Pure so it can be unit-tested.
fn sudoize(cmd: &str) -> String {
    match cmd.strip_prefix("sudo ") {
        Some(rest) => format!("sudo -S -p '' {rest}"),
        None => cmd.to_string(),
    }
}

/// russh client handler that captures the server's host-key fingerprint into a
/// shared `Arc<Mutex<Option<String>>>` so `RusshTransport` can read it after
/// `connect()` returns.
struct Handler {
    captured_fp: Arc<Mutex<Option<String>>>,
}

// russh 0.61's `Handler` uses native async-trait methods, so this impl must NOT
// carry `#[async_trait]` (unlike our own `Transport` trait below, which does).
impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // Compute the OpenSSH SHA-256 fingerprint through the unit-tested helper
        // so the tested seam is the live production path. `Fingerprint::sha256`
        // yields the raw 32-byte digest OpenSSH renders as "SHA256:…".
        let digest = server_public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .sha256()
            .unwrap_or([0u8; 32]);
        let fp = crate::ssh::format_fp_sha256(&digest);
        *self.captured_fp.lock().unwrap() = Some(fp);
        Ok(true) // TOFU: accept every key; the engine compares against the pinned value
    }
}

/// SSH transport that opens a real SSH connection via `russh`.
pub struct RusshTransport {
    handle: Option<russh::client::Handle<Handler>>,
    fp: Arc<Mutex<Option<String>>>,
    /// When set, privileged commands run via `sudo -S` with this password fed on
    /// stdin. `None` (default) runs `sudo` as-is — correct for root or a
    /// passwordless-sudo (NOPASSWD) user.
    sudo_password: Option<Zeroizing<String>>,
}

impl RusshTransport {
    pub fn new() -> Self {
        Self {
            handle: None,
            fp: Arc::new(Mutex::new(None)),
            sudo_password: None,
        }
    }

    /// Provide a sudo password so privileged commands escalate non-interactively.
    /// Pass `None` to disable (the default).
    pub fn set_sudo_password(&mut self, pw: Option<Zeroizing<String>>) {
        self.sudo_password = pw;
    }
}

impl Default for RusshTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for RusshTransport {
    async fn connect(&mut self, target: &SshTarget, secret: &SshSecret) -> Result<String> {
        let config = Arc::new(russh::client::Config::default());
        // Clone the Arc so the Handler writes into the same slot we'll read below.
        let shared_fp = Arc::clone(&self.fp);
        let handler = Handler {
            captured_fp: shared_fp,
        };

        let mut handle =
            russh::client::connect(config, (target.host.as_str(), target.port), handler)
                .await
                .map_err(|e| Error::Ssh(e.to_string()))?;

        let authed = match secret {
            SshSecret::Password(pw) => handle
                .authenticate_password(target.user.as_str(), pw.as_str())
                .await
                .map_err(|e| Error::Ssh(e.to_string()))?,
            SshSecret::PrivateKey { pem, passphrase } => {
                let key = russh::keys::decode_secret_key(
                    pem.as_str(),
                    passphrase.as_deref().map(|p| p.as_str()),
                )
                // Safety note: russh-keys errors do not embed credential bytes,
                // so surfacing e.to_string() is safe. Re-verify on upgrade.
                .map_err(|e| Error::Ssh(e.to_string()))?;
                // russh 0.61: publickey auth takes a `PrivateKeyWithHashAlg`
                // (None → SHA-1 for RSA, ignored for other key types).
                let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
                handle
                    .authenticate_publickey(target.user.as_str(), key)
                    .await
                    .map_err(|e| Error::Ssh(e.to_string()))?
            }
            SshSecret::None => return Err(Error::Ssh("no credential".into())),
        };

        // russh 0.61 returns an `AuthResult` rather than a bool.
        if !authed.success() {
            return Err(Error::Ssh("authentication failed".into()));
        }

        // Read the fingerprint the Handler captured during the key-exchange.
        let fp = self
            .fp
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "SHA256:unknown".into());

        self.handle = Some(handle);
        Ok(fp)
    }

    async fn run(&mut self, cmd: &str) -> Result<CommandOutput> {
        // In password-sudo mode, rewrite a leading `sudo` to read the password
        // from stdin and stage that password (with trailing newline) to feed in
        // after exec. Copy it out of `self` before borrowing `self.handle`.
        let feed_pw = self.sudo_password.is_some() && cmd.starts_with("sudo ");
        let final_cmd = if feed_pw {
            sudoize(cmd)
        } else {
            cmd.to_string()
        };
        let pw_line: Option<Zeroizing<Vec<u8>>> = if feed_pw {
            self.sudo_password.as_ref().map(|pw| {
                let mut v = Vec::with_capacity(pw.len() + 1);
                v.extend_from_slice(pw.as_bytes());
                v.push(b'\n');
                Zeroizing::new(v)
            })
        } else {
            None
        };

        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| Error::Ssh("not connected".into()))?;

        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(e.to_string()))?;

        channel
            .exec(true, final_cmd.as_str())
            .await
            .map_err(|e| Error::Ssh(e.to_string()))?;

        // Feed the sudo password on stdin, then EOF so the command can proceed.
        if let Some(line) = &pw_line {
            channel
                .data(&line[..])
                .await
                .map_err(|e| Error::Ssh(e.to_string()))?;
            channel.eof().await.map_err(|e| Error::Ssh(e.to_string()))?;
        }

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut code = 0i32;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                russh::ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => code = exit_status as i32,
                russh::ChannelMsg::Close => break,
                _ => {} // Eof and others: keep reading so a post-Eof ExitStatus is seen
            }
        }

        Ok(CommandOutput {
            code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    async fn put_file(&mut self, remote_path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        // Write via a base64 pipe to avoid an SFTP subsystem dependency.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        // POSIX-safe single-quote escaping: end the quoted string, emit a
        // backslash-quoted apostrophe, then reopen the quoted string.
        let safe_path = remote_path.replace('\'', "'\\''");
        let cmd = format!(
            "umask 077; printf %s '{b64}' | base64 -d > '{safe_path}' && chmod {mode:o} '{safe_path}'"
        );
        self.run(&cmd).await?.ok().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::sudoize;

    #[test]
    fn sudoize_rewrites_leading_sudo_for_stdin_password() {
        assert_eq!(
            sudoize("sudo docker pull img:1"),
            "sudo -S -p '' docker pull img:1"
        );
        // Only the leading token is touched; the rest is preserved verbatim.
        assert_eq!(
            sudoize("sudo sh -c 'set -e; systemctl enable --now docker'"),
            "sudo -S -p '' sh -c 'set -e; systemctl enable --now docker'"
        );
    }

    #[test]
    fn sudoize_leaves_non_sudo_commands_alone() {
        let probe = "command -v docker >/dev/null 2>&1 && echo yes || echo no";
        assert_eq!(sudoize(probe), probe);
    }
}
