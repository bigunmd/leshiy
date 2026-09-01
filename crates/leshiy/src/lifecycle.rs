//! Day-2 lifecycle orchestration over a `HostOps`. Decisions/sequencing are unit-tested
//! against a mock; the real host effects live in `RealHostOps`.
use crate::host::HostOps;
use crate::reality_config::RealityServerConfig;
use crate::ui;
use anyhow::{Context, Result};

/// Upstream release repository. `cli.rs` repeats the literal because `concat!` needs one.
pub const DEFAULT_REPO: &str = "bigunmd/leshiy";

/// A renderable snapshot of server state. Pure data → `render_status` is golden-testable.
pub struct StatusReport {
    pub active: bool,
    pub listen: String,
    pub dest: String,
    pub quic: bool,
    pub connector: bool,
}

pub fn render_status(r: &StatusReport) -> String {
    let onoff = |b: bool| if b { "yes" } else { "no" };
    format!(
        "{}{}\n{}{}\n{}{}\n{}{}\n{}{}",
        ui::label("service active: "),
        ui::value(onoff(r.active)),
        ui::label("listen:         "),
        r.listen,
        ui::label("dest (cloak):   "),
        r.dest,
        ui::label("quic:           "),
        ui::value(onoff(r.quic)),
        ui::label("connector:      "),
        ui::value(onoff(r.connector)),
    )
}

/// Stop + remove the service and binary. Removes the config dir only when `purge` is set
/// (so identity/keys are never deleted silently).
pub fn uninstall(config: &str, purge: bool, host: &dyn HostOps) -> Result<()> {
    // Stop+disable is best-effort (service may already be gone).
    let _ = host.systemctl(&["disable", "--now", "leshiy"]);
    host.remove_path("/etc/systemd/system/leshiy.service")?;
    let _ = host.systemctl(&["daemon-reload"]);
    let _ = host.firewall_revoke();
    host.remove_path("/usr/local/bin/leshiy")?;
    if purge {
        let dir = std::path::Path::new(config)
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && p.as_os_str() != "/")
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/etc/leshiy".into());
        host.remove_path(&dir)?;
        ui::ok(&format!("purged {dir}"));
    } else {
        ui::ok("removed service + binary; kept config (use --purge to remove it)");
    }
    Ok(())
}

/// Fetch+verify the release binary for `version` and restart the service onto it.
pub fn upgrade(repo: &str, version: &str, host: &dyn HostOps) -> Result<()> {
    validate_repo(repo)?;
    validate_version(version)?;
    host.fetch_verified_binary(repo, version, "/usr/local/bin/leshiy")?;
    host.systemctl(&["restart", "leshiy"])?;
    ui::ok(&format!("upgraded to {version} and restarted"));
    Ok(())
}

/// Replace the **running** binary with a verified release.
///
/// Distinct from [`upgrade`], which manages the server: there is no service to restart
/// here, because the thing being replaced is the caller. `rename(2)` leaves this process
/// on the old inode, so the new build only takes effect on the next invocation.
pub fn update(
    repo: &str,
    version: &str,
    dest: &std::path::Path,
    force: bool,
    host: &dyn HostOps,
) -> Result<()> {
    validate_repo(repo)?;
    validate_version(version)?;
    let current = env!("CARGO_PKG_VERSION");
    if !force && is_downgrade(version, current) {
        anyhow::bail!(
            "{version} is older than the running {current}; every release carries the same \
             signature, so a valid signature alone cannot stop a rollback to a known-bad \
             build — pass --force if you meant it"
        );
    }
    ensure_replaceable(dest)?;
    let dest_str = dest
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("binary path is not valid UTF-8: {}", dest.display()))?;
    host.fetch_verified_binary(repo, version, dest_str)?;
    ui::ok(&format!("updated {} to {version}", dest.display()));
    ui::hint("restart any running leshiy process to pick up the new build");
    Ok(())
}

/// Path of the running binary, for in-place replacement.
pub fn self_path() -> Result<std::path::PathBuf> {
    let p = std::env::current_exe().context("resolve the running binary path")?;
    validate_self_path(&p)?;
    Ok(p)
}

/// Reject a `current_exe()` we must not overwrite. Linux resolves `/proc/self/exe` to a
/// magic symlink whose target gains a `" (deleted)"` suffix once the file is unlinked —
/// Rust does not strip it, so replacing that path would create a bizarrely-named file
/// instead of updating anything.
fn validate_self_path(p: &std::path::Path) -> Result<()> {
    let s = p.to_string_lossy();
    if s.ends_with(" (deleted)") {
        anyhow::bail!("the running binary was already replaced or removed ({s}); re-run update");
    }
    if !p.is_absolute() {
        anyhow::bail!("could not resolve an absolute path for the running binary ({s})");
    }
    Ok(())
}

/// `rename(2)` needs write permission on the destination *directory*, not on the file, so
/// probe the directory rather than testing the binary's own mode. Failing here with
/// guidance is deliberate: auto-escalating would run a freshly downloaded binary as root.
fn ensure_replaceable(dest: &std::path::Path) -> Result<()> {
    let dir = dest.parent().unwrap_or_else(|| std::path::Path::new("."));
    let probe = dir.join(format!(".leshiy.probe.{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => anyhow::bail!(
            "cannot replace {} ({e}); re-run as the owner of {}, e.g. sudo leshiy update",
            dest.display(),
            dir.display()
        ),
    }
}

/// Split `v1.11.3` / `1.11.3` into ordered parts. `None` for anything that is not a plain
/// three-part version (pre-release or date tags), which we decline to order.
fn version_parts(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim_start_matches('v').split('.');
    let mut next = || it.next()?.parse::<u64>().ok();
    let (a, b, c) = (next()?, next()?, next()?);
    it.next().is_none().then_some((a, b, c))
}

/// Only report a downgrade when both tags are comparable; an unorderable tag is allowed
/// through rather than blocking a legitimate install.
fn is_downgrade(target: &str, current: &str) -> bool {
    match (version_parts(target), version_parts(current)) {
        (Some(t), Some(c)) => t < c,
        _ => false,
    }
}

/// Validate `owner/name` so it can never inject into a URL/shell.
fn validate_repo(repo: &str) -> Result<()> {
    let ok = repo.split('/').count() == 2
        && !repo.is_empty()
        && repo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c));
    if !ok {
        anyhow::bail!("invalid repo {repo:?} (expected owner/name)");
    }
    Ok(())
}

/// Validate a release tag so it can never inject.
fn validate_version(v: &str) -> Result<()> {
    let ok = !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "v._-".contains(c));
    if !ok {
        anyhow::bail!("invalid version {v:?}");
    }
    Ok(())
}

/// Resolve the latest release tag for `repo` via the GitHub API (no shell).
pub fn latest_version(repo: &str) -> Result<String> {
    validate_repo(repo)?;
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let out = std::process::Command::new("curl")
        .args(["-fsSL", &url])
        .output()
        .context("query latest release")?;
    if !out.status.success() {
        anyhow::bail!("could not fetch latest release for {repo}");
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let tag = body
        .split("\"tag_name\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .map(str::to_string)
        .unwrap_or_default();
    if tag.is_empty() {
        anyhow::bail!("could not resolve latest release for {repo} (pass --version)");
    }
    Ok(tag)
}

pub fn status(config: &str, host: &dyn HostOps) -> Result<StatusReport> {
    let toml_str = std::fs::read_to_string(config).with_context(|| format!("read {config}"))?;
    let cfg: RealityServerConfig = toml::from_str(&toml_str).context("parse config")?;
    let report = StatusReport {
        active: host.service_active("leshiy"),
        listen: cfg.listen.clone(),
        dest: cfg.dest.clone(),
        quic: cfg.quic_listen.is_some(),
        connector: cfg.connector.is_some(),
    };
    println!("{}", render_status(&report));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::mock::MockHostOps;

    #[test]
    fn render_status_is_readable() {
        let s = render_status(&StatusReport {
            active: true,
            listen: "0.0.0.0:443".into(),
            dest: "www.microsoft.com:443".into(),
            quic: false,
            connector: true,
        });
        assert!(s.contains("service active: yes"));
        assert!(s.contains("connector:      yes"));
        assert!(s.contains("quic:           no"));
    }

    #[test]
    fn status_reads_config_and_queries_service() {
        let dir = std::env::temp_dir().join(format!("leshiy-st-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("server.toml");
        std::fs::write(
            &cfg,
            concat!(
                "listen = \"0.0.0.0:443\"\n",
                "dest = \"www.microsoft.com:443\"\n",
                "server_names = [\"www.microsoft.com\"]\n",
                "static_private_key_b64 = \"AAAA\"\n",
                "short_ids = []\n",
                "max_time_diff_secs = 120\n",
                "host = \"203.0.113.5:443\"\n",
            ),
        )
        .unwrap();
        let host = MockHostOps::new(true);
        let report = status(cfg.to_str().unwrap(), &host).unwrap();
        assert!(host.calls().contains(&"active:leshiy".to_string()));
        assert!(report.active);
        assert_eq!(report.listen, "0.0.0.0:443");
        assert_eq!(report.dest, "www.microsoft.com:443");
        assert!(!report.quic);
        assert!(!report.connector);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn uninstall_keeps_config_without_purge() {
        let host = MockHostOps::new(true);
        uninstall("/etc/leshiy/server.toml", false, &host).unwrap();
        let c = host.calls();
        assert!(c.iter().any(|s| s == "systemctl:disable --now leshiy"));
        assert!(c.contains(&"remove:/etc/systemd/system/leshiy.service".to_string()));
        assert!(c.contains(&"systemctl:daemon-reload".to_string()));
        assert!(c.contains(&"firewall_revoke".to_string()));
        assert!(c.contains(&"remove:/usr/local/bin/leshiy".to_string()));
        // Without --purge, the config dir is NOT removed.
        assert!(!c.iter().any(|s| s == "remove:/etc/leshiy"));
        let disable = c
            .iter()
            .position(|s| s == "systemctl:disable --now leshiy")
            .unwrap();
        let rm_unit = c
            .iter()
            .position(|s| s == "remove:/etc/systemd/system/leshiy.service")
            .unwrap();
        assert!(
            disable < rm_unit,
            "must disable service before deleting its unit file"
        );
    }

    #[test]
    fn uninstall_purge_removes_config_dir() {
        let host = MockHostOps::new(true);
        uninstall("/etc/leshiy/server.toml", true, &host).unwrap();
        assert!(host.calls().contains(&"remove:/etc/leshiy".to_string()));
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("leshiy-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn version_parts_orders_only_plain_three_part_tags() {
        assert_eq!(version_parts("v1.11.3"), Some((1, 11, 3)));
        assert_eq!(version_parts("1.11.3"), Some((1, 11, 3)));
        assert_eq!(version_parts("v1.11"), None);
        assert_eq!(version_parts("v1.11.3.4"), None);
        assert_eq!(version_parts("v1.11.3-rc1"), None);
        assert_eq!(version_parts("nightly"), None);
    }

    #[test]
    fn is_downgrade_only_when_both_tags_are_comparable() {
        assert!(is_downgrade("v1.0.0", "v1.11.3"));
        assert!(is_downgrade("v1.11.2", "v1.11.3"));
        assert!(!is_downgrade("v1.11.3", "v1.11.3"));
        assert!(!is_downgrade("v2.0.0", "v1.11.3"));
        // Unorderable tags must not block a legitimate install.
        assert!(!is_downgrade("v1.11.3-rc1", "v1.11.3"));
        assert!(!is_downgrade("v1.0.0", "nightly"));
    }

    #[test]
    fn validate_self_path_rejects_a_replaced_binary() {
        let deleted = std::path::PathBuf::from("/usr/local/bin/leshiy (deleted)");
        assert!(validate_self_path(&deleted).is_err());
        assert!(validate_self_path(std::path::Path::new("leshiy")).is_err());
        assert!(validate_self_path(std::path::Path::new("/usr/local/bin/leshiy")).is_ok());
    }

    /// A rollback to an older, still-validly-signed release is a real attack: every build
    /// carries the same minisign key, so signature verification alone cannot prevent it.
    #[test]
    fn update_refuses_a_downgrade_unless_forced() {
        let dir = tmpdir("dg");
        let dest = dir.join("leshiy");
        let host = MockHostOps::new(true);
        let err = update("bigunmd/leshiy", "v0.0.1", &dest, false, &host).unwrap_err();
        assert!(format!("{err}").contains("older than the running"));
        assert!(
            host.calls().is_empty(),
            "must not fetch a refused downgrade"
        );

        update("bigunmd/leshiy", "v0.0.1", &dest, true, &host).unwrap();
        assert!(host.calls().iter().any(|c| c.starts_with("fetch:")));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `update` replaces the caller, so unlike `upgrade` it must never touch systemd.
    #[test]
    fn update_targets_the_given_path_and_leaves_systemd_alone() {
        let dir = tmpdir("up");
        let dest = dir.join("leshiy");
        let host = MockHostOps::new(true);
        update("bigunmd/leshiy", "v99.0.0", &dest, false, &host).unwrap();
        let c = host.calls();
        assert_eq!(c.len(), 1, "exactly one host call expected: {c:?}");
        assert!(c[0].ends_with(&format!(":{}", dest.display())), "{c:?}");
        assert!(
            !c.iter().any(|s| s.starts_with("systemctl:")),
            "update must not restart a service: {c:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn update_fails_with_guidance_when_the_directory_is_not_writable() {
        let dir = tmpdir("ro");
        let dest = dir.join("leshiy");
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&dir, perms).unwrap();

        let host = MockHostOps::new(true);
        let res = update("bigunmd/leshiy", "v99.0.0", &dest, false, &host);

        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&dir, perms).unwrap();

        // Root ignores the mode bits, so only assert the contract when it actually applied.
        if let Err(e) = res {
            assert!(format!("{e}").contains("cannot replace"), "{e}");
            assert!(
                host.calls().is_empty(),
                "must not download before it can install"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn upgrade_fetches_then_restarts_in_order() {
        let host = MockHostOps::new(true);
        upgrade("bigunmd/leshiy", "v0.2.0", &host).unwrap();
        let c = host.calls();
        let fetch = c
            .iter()
            .position(|s| s.starts_with("fetch:bigunmd/leshiy:v0.2.0:"))
            .unwrap();
        let restart = c
            .iter()
            .position(|s| s == "systemctl:restart leshiy")
            .unwrap();
        assert!(
            fetch < restart,
            "must fetch+verify before restarting: {c:?}"
        );
        assert!(c[fetch].ends_with(":/usr/local/bin/leshiy"));
    }
}
