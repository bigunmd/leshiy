//! `leshiy mtproxy`: the Telegram proxy link for a server config, optionally enabling it.
use crate::reality_config::RealityServerConfig;
use anyhow::{Context, Result};
use leshiy_reality::mtproxy::{MtProxySecret, tg_link};

/// The `tg://proxy` link for the server at `config`. With `enable`, a config without a secret
/// gets one (the running server picks it up on restart); without, that is an error.
pub fn link(config: &str, enable: bool) -> Result<String> {
    let text = std::fs::read_to_string(config).with_context(|| format!("read {config}"))?;
    let mut cfg: RealityServerConfig = toml::from_str(&text).context("parse config")?;
    let secret = match cfg.mtproxy_secret.as_deref() {
        Some(hex) => MtProxySecret::from_hex(hex).context("bad mtproxy_secret")?,
        None if enable => {
            let s = MtProxySecret::generate();
            cfg.mtproxy_secret = Some(s.to_hex());
            replace_config(config, &toml::to_string_pretty(&cfg)?)?;
            crate::ui::ok("Telegram proxy enabled — restart the server to apply");
            s
        }
        None => anyhow::bail!("the Telegram proxy is not enabled in {config} (pass --enable)"),
    };
    anyhow::ensure!(
        !cfg.host.is_empty(),
        "{config} has no public `host`, so there is no address to put in the link"
    );
    let sni = cfg
        .server_names
        .first()
        .with_context(|| format!("{config} has no server_names"))?;
    Ok(tg_link(&cfg.host, &secret, sni))
}

/// Swap in the new config atomically, owner-only: it holds the server's private key.
fn replace_config(path: &str, contents: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");
    crate::server::write_secret_file(&tmp, contents)?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &std::path::Path, extra: &str) -> String {
        let path = dir.join("server.toml");
        std::fs::write(
            &path,
            format!(
                r#"listen = "0.0.0.0:443"
dest = "www.microsoft.com:443"
server_names = ["www.microsoft.com"]
static_private_key_b64 = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"
short_ids = []
max_time_diff_secs = 120
host = "203.0.113.5:443"
{extra}"#
            ),
        )
        .unwrap();
        path.to_string_lossy().into_owned()
    }

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("leshiy-mtpcli-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn link_for_enabled_config() {
        let dir = tempdir("on");
        let cfg = write_config(
            &dir,
            "mtproxy_secret = \"00112233445566778899aabbccddeeff\"\n",
        );
        assert_eq!(
            link(&cfg, false).unwrap(),
            format!(
                "tg://proxy?server=203.0.113.5&port=443&secret=ee00112233445566778899aabbccddeeff{}",
                hex::encode("www.microsoft.com")
            )
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disabled_config_is_an_error_without_enable() {
        let dir = tempdir("off");
        let cfg = write_config(&dir, "");
        assert!(link(&cfg, false).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enable_persists_a_secret_that_later_calls_reuse() {
        let dir = tempdir("enable");
        let cfg = write_config(&dir, "");
        let first = link(&cfg, true).unwrap();
        assert_eq!(link(&cfg, false).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cfg).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
