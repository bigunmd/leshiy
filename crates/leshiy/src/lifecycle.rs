//! Day-2 lifecycle orchestration over a `HostOps`. Decisions/sequencing are unit-tested
//! against a mock; the real host effects live in `RealHostOps`.
use crate::host::HostOps;
use crate::reality_config::RealityServerConfig;
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
        "service active: {}\nlisten:         {}\ndest (cloak):   {}\nquic:           {}\nconnector:      {}",
        onoff(r.active),
        r.listen,
        r.dest,
        onoff(r.quic),
        onoff(r.connector),
    )
}

pub fn status(config: &str, host: &dyn HostOps) -> Result<()> {
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
    Ok(())
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
        status(cfg.to_str().unwrap(), &host).unwrap();
        assert!(host.calls().contains(&"active:leshiy".to_string()));
        std::fs::remove_dir_all(&dir).ok();
    }
}
