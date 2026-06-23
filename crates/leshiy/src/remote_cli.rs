//! `leshiy remote` — drive leshiy-provision from the CLI.

use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn vault_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("leshiy").join("servers.lvault")
}

pub fn prompt_passphrase(confirm: bool) -> Result<String> {
    let pass = rpassword::prompt_password("Vault passphrase: ").context("read passphrase")?;
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")?;
        anyhow::ensure!(pass == again, "passphrases do not match");
    }
    Ok(pass)
}

pub async fn run(cmd: crate::cli::RemoteCmd) -> Result<()> {
    use crate::cli::RemoteCmd;
    match cmd {
        RemoteCmd::Ls => {
            let pass = prompt_passphrase(false)?;
            let vault = leshiy_provision::vault::Vault::load(&vault_path(), &pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            for r in vault.list() {
                println!("{}", r.id);
                crate::ui::eline(&crate::ui::field("label", &crate::ui::value(&r.label)));
                crate::ui::eline(&crate::ui::field("host", &crate::ui::value(&r.public_host)));
                crate::ui::eline(&crate::ui::field("clients", &r.clients.len().to_string()));
            }
            Ok(())
        }
        _ => anyhow::bail!("not yet implemented"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_path_ends_with_expected_file() {
        let p = vault_path();
        assert!(p.ends_with("leshiy/servers.lvault"));
    }
}
