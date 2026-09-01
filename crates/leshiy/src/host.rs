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
        //
        // Two deliberate choices in the tail of this script:
        //   * `awk '$2==f'` selects the checksum line by *exact filename field*. An
        //     unanchored `grep` also matches sibling entries such as `<tarball>.minisig`,
        //     which makes `sha256sum -c` check a nonexistent file and fail confusingly.
        //   * The binary is staged inside the *destination* directory and moved with `mv`,
        //     so the final step is a same-filesystem `rename(2)` — atomic, and safe over a
        //     running executable. `install(1)` would unlink the destination first, leaving
        //     a window in which there is no binary at all; staging under `/tmp` instead
        //     would silently degrade `mv` to copy+unlink across filesystems and lose the
        //     atomicity. Creating the staging file first also fails fast, before any
        //     download, when the destination directory is not writable.
        //   * All three assets are fetched in ONE curl invocation so DNS and the TLS
        //     handshake are paid once, not three times. That is not micro-optimisation:
        //     on a resolver answering in ~10s (observed under WSL2, whose DNS is the
        //     Windows host) three separate calls added ~30s of pure lookup latency.
        //     `--retry` matters for the same reason — the target users are on hostile
        //     or degraded networks.
        const SCRIPT: &str = r#"set -eu
repo="$1"; version="$2"; target="$3"; dest="$4"; pubkey="$5"
command -v minisign >/dev/null 2>&1 || {
  echo "minisign is required to verify the release; install it and retry" >&2; exit 3; }
destdir="$(dirname "$dest")"
mkdir -p "$destdir"
# Sweep staging files orphaned by a kill that outran the EXIT trap (SIGKILL is untrappable),
# so a repeatedly-interrupted update cannot litter the install directory.
find "$destdir" -maxdepth 1 -name '.leshiy.new.*' -type f -mmin +5 -delete 2>/dev/null || true
tmp="$(mktemp -d)"
new="$(mktemp "$destdir/.leshiy.new.XXXXXX")"
trap 'rm -rf "$tmp"; rm -f "$new"' EXIT
base="https://github.com/$repo/releases/download/$version"
tarball="leshiy-$version-$target.tar.gz"
curl -fsSL --retry 3 --retry-connrefused --connect-timeout 30 \
  "$base/$tarball" -o "$tmp/$tarball" \
  "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" \
  "$base/SHA256SUMS.minisig" -o "$tmp/SHA256SUMS.minisig"
minisign -Vm "$tmp/SHA256SUMS" -P "$pubkey" -x "$tmp/SHA256SUMS.minisig"
( cd "$tmp" && awk -v f="$tarball" '$2==f' SHA256SUMS | sha256sum -c - )
tar -C "$tmp" -xzf "$tmp/$tarball"
dd if="$tmp/leshiy" of="$new" bs=1M conv=fsync 2>/dev/null
chmod 755 "$new"
mv -f "$new" "$dest"
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
