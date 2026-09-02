//! Prompt primitives for interactive (`-i`) mode.
//!
//! Every dialoguer prompt renders on `Term::stderr()`, which is what keeps `-i` compatible
//! with the `ui` contract: stdout still carries only machine data (the issued `leshiy://`
//! URI), so `leshiy remote provision -i > uri.txt` remains a valid thing to do.

use anyhow::{Context, Result};
use dialoguer::theme::{ColorfulTheme, SimpleTheme, Theme};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Camouflage sites offered by the dest picker. All verified to negotiate TLS 1.3, which
/// is what REALITY requires — but the wizard still probes the chosen one, because a site
/// that is reachable from the operator's laptop may not be from the server.
pub const DEST_PRESETS: &[&str] = &[
    "www.microsoft.com:443",
    "www.cloudflare.com:443",
    "www.apple.com:443",
    "www.icloud.com:443",
    "www.amazon.com:443",
    "dl.google.com:443",
    "www.bing.com:443",
];

/// Private-key filenames `ssh-keygen` produces by default, newest algorithm first so the
/// picker's first entry is the one a modern host most likely accepts.
const KNOWN_KEY_FILES: &[&str] = &["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"];

/// Reject `-i` when there is nothing to prompt on, instead of blocking forever on a read
/// that will never see a keystroke.
pub fn require_tty() -> Result<()> {
    anyhow::ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "--interactive needs a terminal on stdin and stderr; \
         pass the options as flags instead (see --help)"
    );
    Ok(())
}

fn theme() -> Box<dyn Theme> {
    if crate::ui::color_stderr() {
        Box::new(ColorfulTheme::default())
    } else {
        Box::new(SimpleTheme)
    }
}

/// A `n/total  Title` section header on the decoration channel.
///
/// `asks` suppresses the header when flags already answered everything in that step, so a
/// partially-flagged run does not print headings with nothing underneath them.
pub fn step(n: u8, total: u8, title: &str, asks: bool) {
    if !asks {
        return;
    }
    crate::ui::eline("");
    crate::ui::eline(&crate::ui::heading(&format!("{n}/{total}  {title}")));
}

pub fn text(prompt: &str, default: Option<&str>) -> Result<String> {
    let theme = theme();
    let mut input = dialoguer::Input::<String>::with_theme(&*theme)
        .with_prompt(prompt)
        .validate_with(|v: &String| {
            if v.trim().is_empty() {
                Err("cannot be empty")
            } else {
                Ok(())
            }
        });
    if let Some(d) = default {
        input = input.default(d.to_string());
    }
    Ok(input
        .interact_text()
        .context("read input")?
        .trim()
        .to_string())
}

/// An optional field: an empty line means "leave unset" rather than a validation error.
pub fn text_opt(prompt: &str) -> Result<Option<String>> {
    let theme = theme();
    let raw = dialoguer::Input::<String>::with_theme(&*theme)
        .with_prompt(prompt)
        .allow_empty(true)
        .interact_text()
        .context("read input")?;
    let trimmed = raw.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
}

pub fn port(prompt: &str, default: u16) -> Result<u16> {
    let theme = theme();
    dialoguer::Input::<u16>::with_theme(&*theme)
        .with_prompt(prompt)
        .default(default)
        .validate_with(|v: &u16| {
            if *v == 0 {
                Err("port must be between 1 and 65535")
            } else {
                Ok(())
            }
        })
        .interact_text()
        .context("read port")
}

pub fn confirm(prompt: &str, default: bool) -> Result<bool> {
    let theme = theme();
    dialoguer::Confirm::with_theme(&*theme)
        .with_prompt(prompt)
        .default(default)
        .interact()
        .context("read confirmation")
}

pub fn select(prompt: &str, items: &[String], default: usize) -> Result<usize> {
    let theme = theme();
    dialoguer::Select::with_theme(&*theme)
        .with_prompt(prompt)
        .items(items)
        .default(default)
        .interact()
        .context("read selection")
}

pub fn secret(prompt: &str) -> Result<Zeroizing<String>> {
    let theme = theme();
    Ok(Zeroizing::new(
        dialoguer::Password::with_theme(&*theme)
            .with_prompt(prompt)
            .interact()
            .context("read secret")?,
    ))
}

/// A secret typed twice. dialoguer re-prompts on mismatch rather than aborting, so a typo
/// while creating a vault does not throw away everything already answered.
pub fn secret_confirmed(prompt: &str) -> Result<Zeroizing<String>> {
    let theme = theme();
    Ok(Zeroizing::new(
        dialoguer::Password::with_theme(&*theme)
            .with_prompt(prompt)
            .with_confirmation("Confirm", "passphrases do not match")
            .interact()
            .context("read secret")?,
    ))
}

/// Default-named private keys present in `dir`, in `KNOWN_KEY_FILES` order.
pub fn ssh_key_candidates(dir: &Path) -> Vec<PathBuf> {
    KNOWN_KEY_FILES
        .iter()
        .map(|name| dir.join(name))
        .filter(|p| p.is_file())
        .collect()
}

pub fn ssh_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ssh"))
}

/// Render `s` so a POSIX shell passes it through as one argument, unchanged.
pub fn shell_quote(s: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c);
    if !s.is_empty() && s.chars().all(safe) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Accumulates the non-interactive invocation equivalent to a wizard run, so the review
/// screen can teach the flags and the run stays reproducible in a script.
pub struct CommandLine {
    prefix: Vec<String>,
    args: Vec<String>,
}

impl CommandLine {
    pub fn new(base: &str) -> Self {
        Self {
            prefix: base.split_whitespace().map(str::to_string).collect(),
            args: Vec::new(),
        }
    }

    pub fn arg(&mut self, value: &str) -> &mut Self {
        self.args.push(value.to_string());
        self
    }

    pub fn opt(&mut self, name: &str, value: Option<&str>) -> &mut Self {
        if let Some(v) = value {
            self.args.push(name.to_string());
            self.args.push(v.to_string());
        }
        self
    }

    pub fn flag(&mut self, name: &str, on: bool) -> &mut Self {
        if on {
            self.args.push(name.to_string());
        }
        self
    }

    /// The arguments unquoted, for handing to `exec` where no shell is involved.
    ///
    /// Quoting happens in [`Self::render`] instead of at insertion, so the same builder
    /// drives both the displayed command and a real re-exec without the two drifting.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Wrap at `width` with a trailing backslash, so a long provision line stays
    /// copy-pasteable into a terminal rather than becoming an unreadable smear.
    pub fn render(&self, width: usize) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut current = String::new();
        let tokens = self
            .prefix
            .iter()
            .cloned()
            .chain(self.args.iter().map(|a| shell_quote(a)));
        for part in tokens {
            if !current.is_empty() && current.len() + 1 + part.len() > width {
                lines.push(std::mem::take(&mut current));
                current.push_str("    ");
            } else if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(&part);
        }
        if !current.is_empty() {
            lines.push(current);
        }
        lines.join(" \\\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dest_preset_carries_an_explicit_port() {
        // The dest is parsed with `rsplit_once(':')`, so a bare hostname would silently
        // probe port 443 while sending the portless string on to the server config.
        for d in DEST_PRESETS {
            let (host, port) = d
                .rsplit_once(':')
                .unwrap_or_else(|| panic!("{d} has no port"));
            assert!(!host.is_empty(), "{d} has an empty host");
            assert!(port.parse::<u16>().is_ok(), "{d} has a non-numeric port");
        }
    }

    #[test]
    fn shell_quote_leaves_ordinary_arguments_alone() {
        assert_eq!(shell_quote("root@1.2.3.4"), "root@1.2.3.4");
        assert_eq!(
            shell_quote("www.microsoft.com:443"),
            "www.microsoft.com:443"
        );
        assert_eq!(
            shell_quote("/home/u/.ssh/id_ed25519"),
            "/home/u/.ssh/id_ed25519"
        );
        assert_eq!(
            shell_quote("ghcr.io/bigunmd/leshiy:v1.0.0"),
            "ghcr.io/bigunmd/leshiy:v1.0.0"
        );
    }

    #[test]
    fn shell_quote_escapes_whitespace_and_quotes() {
        assert_eq!(shell_quote("my server"), "'my server'");
        assert_eq!(shell_quote(""), "''");
        // A label containing a quote must not be able to close the quoting and inject.
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
    }

    #[test]
    fn command_line_skips_absent_options_and_off_flags() {
        let mut c = CommandLine::new("leshiy remote provision");
        c.opt("--host", Some("root@1.2.3.4"))
            .opt("--label", None)
            .flag("--sudo", false)
            .flag("--interactive", true);
        assert_eq!(
            c.render(200),
            "leshiy remote provision --host root@1.2.3.4 --interactive"
        );
    }

    #[test]
    fn command_line_wraps_long_invocations_with_continuations() {
        let mut c = CommandLine::new("leshiy remote provision");
        c.opt("--host", Some("root@203.0.113.5"))
            .opt("--dest", Some("www.microsoft.com:443"))
            .opt("--image", Some("ghcr.io/bigunmd/leshiy:v1.12.4"));
        let out = c.render(60);
        assert!(out.contains(" \\\n"), "expected a wrapped line, got: {out}");
        // Every continuation is indented, and joining the pieces recovers the argv.
        let flat = out.replace(" \\\n    ", " ").replace(" \\\n", " ");
        assert_eq!(
            flat,
            "leshiy remote provision --host root@203.0.113.5 \
             --dest www.microsoft.com:443 --image ghcr.io/bigunmd/leshiy:v1.12.4"
        );
    }

    #[test]
    fn ssh_key_candidates_finds_known_names_in_algorithm_order() {
        let dir = std::env::temp_dir().join(format!("leshiy-wiz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // id_rsa and id_ed25519 present; id_ecdsa absent; a directory and a stray file ignored.
        std::fs::write(dir.join("id_rsa"), "x").unwrap();
        std::fs::write(dir.join("id_ed25519"), "x").unwrap();
        std::fs::write(dir.join("id_ed25519.pub"), "x").unwrap();
        std::fs::write(dir.join("known_hosts"), "x").unwrap();
        std::fs::create_dir_all(dir.join("id_dsa")).unwrap();

        let found = ssh_key_candidates(&dir);
        assert_eq!(
            found,
            vec![dir.join("id_ed25519"), dir.join("id_rsa")],
            "expected ed25519 before rsa, public keys and directories excluded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssh_key_candidates_is_empty_for_a_missing_directory() {
        let missing =
            std::env::temp_dir().join(format!("leshiy-wiz-absent-{}", std::process::id()));
        assert!(ssh_key_candidates(&missing).is_empty());
    }
}
