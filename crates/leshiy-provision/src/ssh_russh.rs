//! Real SSH transport backed by `russh`. The handler captures the server's
//! host-key fingerprint for TOFU pinning by the caller.

use crate::error::{Error, Result};
use crate::ssh::{CommandOutput, SshTarget, Transport};
use crate::vault::SshSecret;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// russh client handler that captures the server's host-key fingerprint into a
/// shared `Arc<Mutex<Option<String>>>` so `RusshTransport` can read it after
/// `connect()` returns.
struct Handler {
    captured_fp: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // `PublicKey::fingerprint()` returns the BASE64_NOPAD SHA-256 of the
        // wire-format public key — identical to what `ssh-keygen -l -E sha256`
        // prints, minus the "SHA256:" prefix.
        let fp = format!("SHA256:{}", server_public_key.fingerprint());
        *self.captured_fp.lock().unwrap() = Some(fp);
        Ok(true) // TOFU: accept every key; the engine compares against the pinned value
    }
}

/// SSH transport that opens a real SSH connection via `russh`.
pub struct RusshTransport {
    handle: Option<russh::client::Handle<Handler>>,
    fp: Arc<Mutex<Option<String>>>,
}

impl RusshTransport {
    pub fn new() -> Self {
        Self {
            handle: None,
            fp: Arc::new(Mutex::new(None)),
        }
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
                .map_err(|e| Error::Ssh(e.to_string()))?;
                handle
                    .authenticate_publickey(target.user.as_str(), Arc::new(key))
                    .await
                    .map_err(|e| Error::Ssh(e.to_string()))?
            }
            SshSecret::None => return Err(Error::Ssh("no credential".into())),
        };

        if !authed {
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
        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| Error::Ssh("not connected".into()))?;

        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(e.to_string()))?;

        channel
            .exec(true, cmd)
            .await
            .map_err(|e| Error::Ssh(e.to_string()))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut code = 0i32;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                russh::ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => code = exit_status as i32,
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
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
        let cmd = format!(
            "umask 077; printf %s '{b64}' | base64 -d > '{remote_path}' && chmod {mode:o} '{remote_path}'"
        );
        self.run(&cmd).await?.ok().map(|_| ())
    }
}
