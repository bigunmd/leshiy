//! Day-2 lifecycle orchestration over a `HostOps`. Decisions/sequencing are unit-tested
//! against a mock; the real host effects live in `RealHostOps`.
use crate::host::HostOps;
use crate::reality_config::RealityServerConfig;
use crate::ui;
use anyhow::{Context, Result};

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
