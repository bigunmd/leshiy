//! Host-mutation operations behind a trait, so lifecycle orchestration is unit-testable
//! without root, systemd, or the network. `RealHostOps` shells out; tests use `MockHostOps`.
use anyhow::{Context, Result};

pub trait HostOps {
    /// Is the systemd unit currently active?
    fn service_active(&self, unit: &str) -> bool;
    /// Run `systemctl <args>` and error on non-zero exit.
    fn systemctl(&self, args: &[&str]) -> Result<()>;
    /// Remove a file or directory; a missing path is success.
    fn remove_path(&self, path: &str) -> Result<()>;
    /// Best-effort revoke of the 443 tcp/udp firewall rule.
    fn firewall_revoke(&self) -> Result<()>;
    /// Download + verify (minisign + sha256) the release for `version` and atomically
    /// install the `leshiy` binary to `dest`.
    fn fetch_verified_binary(&self, repo: &str, version: &str, dest: &str) -> Result<()>;
}

pub struct RealHostOps;

impl HostOps for RealHostOps {
    fn service_active(&self, unit: &str) -> bool {
        std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    fn systemctl(&self, args: &[&str]) -> Result<()> {
        let st = std::process::Command::new("systemctl")
            .args(args)
            .status()
            .context("run systemctl")?;
        if !st.success() {
            anyhow::bail!("systemctl {args:?} failed");
        }
        Ok(())
    }
    fn remove_path(&self, path: &str) -> Result<()> {
        let p = std::path::Path::new(path);
        let res = if p.is_dir() {
            std::fs::remove_dir_all(p)
        } else {
            std::fs::remove_file(p)
        };
        match res {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("remove {path}")),
        }
    }
    fn firewall_revoke(&self) -> Result<()> {
        // Best effort across ufw/firewalld; ignore failures (the rule may not exist).
        let sh = |program: &str, args: &[&str]| {
            let _ = std::process::Command::new(program).args(args).status();
        };
        sh("ufw", &["delete", "allow", "443/tcp"]);
        sh("ufw", &["delete", "allow", "443/udp"]);
        sh("firewall-cmd", &["--remove-port=443/tcp", "--permanent"]);
        sh("firewall-cmd", &["--remove-port=443/udp", "--permanent"]);
        sh("firewall-cmd", &["--reload"]);
        Ok(())
    }
    fn fetch_verified_binary(&self, repo: &str, version: &str, dest: &str) -> Result<()> {
        let pubkey = MINISIGN_PUB
            .lines()
            .last()
            .ok_or_else(|| anyhow::anyhow!("embedded minisign pubkey missing"))?;
        let target = match std::env::consts::ARCH {
            "x86_64" => "x86_64-unknown-linux-musl",
            "aarch64" => "aarch64-unknown-linux-musl",
            other => anyhow::bail!("unsupported arch {other}"),
        };
        // All dynamic values are passed as positional args ($1..$5) so none is interpolated
        // into the shell program text — no command-injection surface.
        const SCRIPT: &str = r#"set -eu
repo="$1"; version="$2"; target="$3"; dest="$4"; pubkey="$5"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$repo/releases/download/$version"
curl -fsSL "$base/leshiy-$version-$target.tar.gz" -o "$tmp/p.tgz"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
curl -fsSL "$base/SHA256SUMS.minisig" -o "$tmp/SHA256SUMS.minisig"
printf '%s\n' "$pubkey" > "$tmp/k.pub"
minisign -Vm "$tmp/SHA256SUMS" -p "$tmp/k.pub" -x "$tmp/SHA256SUMS.minisig"
( cd "$tmp" && grep "leshiy-$version-$target.tar.gz" SHA256SUMS | sha256sum -c - )
tar -C "$tmp" -xzf "$tmp/p.tgz"
install -Dm755 "$tmp/leshiy" "$dest"
"#;
        let st = std::process::Command::new("sh")
            .arg("-c")
            .arg(SCRIPT)
            .arg("sh") // $0
            .arg(repo)
            .arg(version)
            .arg(target)
            .arg(dest)
            .arg(pubkey)
            .status()
            .context("run verified download")?;
        if !st.success() {
            anyhow::bail!("verified download/install failed (signature, checksum, or network)");
        }
        Ok(())
    }
}

/// The release signing public key, embedded at build time (last line is the key).
pub const MINISIGN_PUB: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/minisign.pub"
));

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::cell::RefCell;

    /// Records every host call so orchestration order can be asserted.
    pub struct MockHostOps {
        pub active: bool,
        pub calls: RefCell<Vec<String>>,
    }
    impl MockHostOps {
        pub fn new(active: bool) -> Self {
            Self {
                active,
                calls: RefCell::new(Vec::new()),
            }
        }
        pub fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }
    impl HostOps for MockHostOps {
        fn service_active(&self, unit: &str) -> bool {
            self.calls.borrow_mut().push(format!("active:{unit}"));
            self.active
        }
        fn systemctl(&self, args: &[&str]) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("systemctl:{}", args.join(" ")));
            Ok(())
        }
        fn remove_path(&self, path: &str) -> Result<()> {
            self.calls.borrow_mut().push(format!("remove:{path}"));
            Ok(())
        }
        fn firewall_revoke(&self) -> Result<()> {
            self.calls.borrow_mut().push("firewall_revoke".into());
            Ok(())
        }
        fn fetch_verified_binary(&self, repo: &str, version: &str, dest: &str) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("fetch:{repo}:{version}:{dest}"));
            Ok(())
        }
    }
}
