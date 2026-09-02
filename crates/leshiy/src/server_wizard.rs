//! The `-i` flow for standing a server up here: `server-init` and `quickstart`.
//!
//! Both commands ask the same questions and differ only in what they do afterwards, so one
//! wizard fills a [`ServerPlan`] and each command consumes the parts it has flags for.

use crate::cli::{self, Role};
use crate::wizard;
use anyhow::Result;

/// Which command will execute the plan. Decides the subcommand the review echoes and how
/// the chosen role is expressed, since only `quickstart` has a `--role` flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerMode {
    Init,
    Quickstart,
}

impl ServerMode {
    fn subcommand(self) -> &'static str {
        match self {
            Self::Init => "server-init",
            Self::Quickstart => "quickstart",
        }
    }
}

const ROLES: &[(Role, &str)] = &[
    (
        Role::Single,
        "standalone — clients connect here and this server egresses directly",
    ),
    (
        Role::Entry,
        "censor-facing — forwards to an exit you already stood up",
    ),
    (
        Role::Exit,
        "clean egress — hands out a connector credential for the entry in front",
    ),
];

pub struct ServerFlags {
    pub host: Option<String>,
    pub dest: Option<String>,
    pub listen: Option<String>,
    pub out: Option<String>,
    pub quic_listen: Option<String>,
    pub quic_sni: Option<String>,
    pub quic_cert: Option<String>,
    pub quic_key: Option<String>,
    pub role: Option<Role>,
    pub exit_uri: Option<String>,
    pub no_probe: bool,
}

pub struct ServerPlan {
    pub host: String,
    pub dest: String,
    pub listen: Option<String>,
    pub out: String,
    pub quic_listen: Option<String>,
    pub quic_sni: Option<String>,
    pub quic_cert: Option<String>,
    pub quic_key: Option<String>,
    pub role: Role,
    pub exit_uri: Option<String>,
    pub no_probe: bool,
}

/// This machine's public `host:port`, the way `install.sh` finds it.
///
/// A VPS's outbound address is not discoverable locally when it sits behind NAT, so this
/// asks an echo service — the same two `install.sh` uses, in the same order. Failure is
/// not an error: the wizard simply offers no default and asks.
pub fn detect_public_host(port: u16) -> Option<String> {
    for url in ["https://api.ipify.org", "https://ifconfig.me"] {
        let out = std::process::Command::new("curl")
            .args(["-fsSL", "--max-time", "5", url])
            .output()
            .ok()?;
        if !out.status.success() {
            continue;
        }
        let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
            return Some(leshiy_reality::addr::join_host_port(&ip, port));
        }
    }
    None
}

/// Merge flags with defaults, asking nothing. The non-interactive path.
pub fn plan_from_flags(flags: ServerFlags, mode: ServerMode) -> Result<ServerPlan> {
    let host = flags
        .host
        .ok_or_else(|| anyhow::anyhow!("--host is required (or pass -i to be asked for it)"))?;
    let dest = flags
        .dest
        .ok_or_else(|| anyhow::anyhow!("--dest is required (or pass -i to be asked for it)"))?;
    let plan = ServerPlan {
        host,
        dest,
        listen: flags.listen,
        out: flags.out.unwrap_or_else(|| cli::DEFAULT_CONFIG.to_string()),
        quic_listen: flags.quic_listen,
        quic_sni: flags.quic_sni,
        quic_cert: flags.quic_cert,
        quic_key: flags.quic_key,
        role: flags.role.unwrap_or(Role::Single),
        exit_uri: flags.exit_uri,
        no_probe: flags.no_probe,
    };
    check_role_preconditions(&plan, mode)?;
    Ok(plan)
}

/// An entry has nothing to forward to without a credential, and an exit has no carrier for
/// the hop in front without QUIC. Enforced here so both commands fail the same way.
fn check_role_preconditions(plan: &ServerPlan, mode: ServerMode) -> Result<()> {
    match plan.role {
        Role::Entry if plan.exit_uri.is_none() => {
            let flag = match mode {
                ServerMode::Init => "--connector",
                ServerMode::Quickstart => "--exit-uri",
            };
            anyhow::bail!("--role entry requires {flag} <EXIT_URI>")
        }
        Role::Exit if plan.quic_listen.is_none() => anyhow::bail!(
            "--role exit requires --quic-listen <public-host:port> (the carrier the entry dials)"
        ),
        _ => Ok(()),
    }
}

/// Ask for whatever `flags` left unset, then show a review the operator confirms.
pub async fn plan_interactively(flags: ServerFlags, mode: ServerMode) -> Result<ServerPlan> {
    const TOTAL: u8 = 6;

    wizard::step(1, TOTAL, "Public address", flags.host.is_none());
    let host = match flags.host {
        Some(h) => h,
        None => ask_public_host()?,
    };
    let listen_port = leshiy_reality::addr::split_host_port(&host)
        .1
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(443);

    wizard::step(2, TOTAL, "Camouflage", flags.dest.is_none());
    let dest = match flags.dest {
        Some(d) => d,
        None => ask_dest(flags.no_probe).await?,
    };

    wizard::step(3, TOTAL, "Role", flags.role.is_none());
    let role = match flags.role {
        Some(r) => r,
        None => {
            let items: Vec<String> = ROLES
                .iter()
                .map(|(r, help)| format!("{:<7} {help}", r.as_flag()))
                .collect();
            ROLES[wizard::select("Role for this server", &items, 0)?].0
        }
    };
    let exit_uri = match (role, flags.exit_uri.clone()) {
        (_, Some(u)) => Some(u),
        (Role::Entry, None) => {
            crate::ui::hint("paste the credential the exit printed — it is not echoed back");
            let uri = wizard::secret("Exit connector credential")?;
            validate_connector(&uri)?;
            Some(uri.to_string())
        }
        _ => None,
    };

    wizard::step(4, TOTAL, "QUIC", flags.quic_listen.is_none());
    let (quic_listen, quic_sni) = ask_quic(
        flags.quic_listen.clone(),
        flags.quic_sni.clone(),
        role,
        &host,
        listen_port,
    )?;

    wizard::step(
        5,
        TOTAL,
        "Config file",
        flags.out.is_none() || flags.listen.is_none(),
    );
    let out = match flags.out {
        Some(o) => o,
        None => wizard::text("Write the server config to", Some(cli::DEFAULT_CONFIG))?,
    };
    let listen = match flags.listen {
        Some(l) => Some(l),
        None if wizard::confirm("Bind to a specific address (not all interfaces)?", false)? => {
            Some(wizard::text(
                "Bind address",
                Some(&format!("0.0.0.0:{listen_port}")),
            )?)
        }
        None => None,
    };

    let plan = ServerPlan {
        host,
        dest,
        listen,
        out,
        quic_listen,
        quic_sni,
        quic_cert: flags.quic_cert,
        quic_key: flags.quic_key,
        role,
        exit_uri,
        no_probe: flags.no_probe,
    };
    check_role_preconditions(&plan, mode)?;

    wizard::step(6, TOTAL, "Review", true);
    review(&plan, mode);
    anyhow::ensure!(
        wizard::confirm("Create the server config now?", true)?,
        "cancelled at the review step"
    );
    Ok(plan)
}

fn ask_public_host() -> Result<String> {
    crate::ui::hint("the address clients dial — it goes into the share URI");
    let detected = detect_public_host(cli::DEFAULT_LISTEN_PORT);
    match &detected {
        Some(h) => crate::ui::ok(&format!("detected public address {}", crate::ui::value(h))),
        None => crate::ui::warn("could not detect this machine's public address"),
    }
    wizard::text("Public host:port clients dial", detected.as_deref())
}

async fn ask_dest(no_probe: bool) -> Result<String> {
    let mut items: Vec<String> = wizard::DEST_PRESETS.iter().map(|s| s.to_string()).collect();
    let custom_idx = items.len();
    items.push("Custom…".to_string());
    crate::ui::hint("the real site whose TLS identity this server presents to a prober");

    loop {
        let idx = wizard::select("Borrowed TLS site (dest)", &items, 0)?;
        let dest = if idx == custom_idx {
            wizard::text("Site as host:port", Some(wizard::DEST_PRESETS[0]))?
        } else {
            items[idx].clone()
        };
        if no_probe || probe_dest(&dest).await? {
            return Ok(dest);
        }
        anyhow::ensure!(
            wizard::confirm("Pick a different site?", true)?,
            "dest {dest} is unusable for REALITY — it must negotiate TLS 1.3"
        );
    }
}

async fn probe_dest(dest: &str) -> Result<bool> {
    let (host, port_str) = dest.rsplit_once(':').unwrap_or((dest, "443"));
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("dest {dest} has a non-numeric port"))?;
    crate::ui::hint(&format!("probing {host}:{port} …"));
    match crate::quickstart::dest_is_tls13(host, port).await {
        Ok(true) => {
            crate::ui::ok(&format!("{host}:{port} negotiates TLS 1.3"));
            Ok(true)
        }
        Ok(false) => {
            crate::ui::warn(&format!(
                "{host}:{port} did not negotiate TLS 1.3 — REALITY needs a TLS 1.3 site"
            ));
            Ok(false)
        }
        Err(e) => {
            crate::ui::warn(&format!("could not reach {host}:{port}: {e}"));
            Ok(false)
        }
    }
}

fn ask_quic(
    given_listen: Option<String>,
    given_sni: Option<String>,
    role: Role,
    host: &str,
    listen_port: u16,
) -> Result<(Option<String>, Option<String>)> {
    if let Some(ql) = given_listen {
        return Ok((Some(ql), given_sni));
    }
    // An exit publishes the carrier its entry dials, so QUIC is not optional there.
    if role == Role::Exit {
        crate::ui::hint("an exit must publish a QUIC carrier for the entry to dial");
    } else if !wizard::confirm("Also serve the QUIC/HTTP-3 transport?", true)? {
        return Ok((None, None));
    }
    let (h, _) = leshiy_reality::addr::split_host_port(host);
    let default = leshiy_reality::addr::join_host_port(h, listen_port);
    let quic_listen = wizard::text("QUIC endpoint clients dial (host:port)", Some(&default))?;
    let sni = match given_sni {
        Some(s) => Some(s),
        None => wizard::text_opt("QUIC SNI (blank = the dest hostname)")?,
    };
    Ok((Some(quic_listen), sni))
}

/// A connector credential is a `leshiy://` URI that must carry a QUIC endpoint — an entry
/// reaches its exit over the QUIC carrier, so one without `quic=` can never connect.
fn validate_connector(uri: &str) -> Result<()> {
    let parsed = leshiy_reality::config::RealityUri::parse(uri.trim())
        .map_err(|e| anyhow::anyhow!("that is not a usable leshiy:// URI: {e}"))?;
    anyhow::ensure!(
        parsed.quic.is_some(),
        "this credential has no quic= endpoint; provision the exit with QUIC enabled"
    );
    Ok(())
}

fn review(plan: &ServerPlan, mode: ServerMode) {
    let f = |k: &str, v: &str| crate::ui::eline(&crate::ui::field(k, &crate::ui::value(v)));
    f("command", mode.subcommand());
    f("public", &plan.host);
    f("dest", &plan.dest);
    f("role", plan.role.as_flag());
    if plan.role == Role::Entry {
        f("downstream", "an exit credential (not shown)");
    }
    f("quic", plan.quic_listen.as_deref().unwrap_or("off"));
    if let Some(s) = &plan.quic_sni {
        f("qsni", s);
    }
    f("listen", plan.listen.as_deref().unwrap_or("all interfaces"));
    f("config", &plan.out);
    crate::ui::eline("");
    crate::ui::eline(&crate::ui::label("Same run, without the wizard:"));
    crate::ui::eline(&format!("  {}", equivalent_command(plan, mode)));
    if plan.role == Role::Exit {
        crate::ui::hint(
            "this prints a connector credential — give it to the entry, not to clients",
        );
    }
    crate::ui::eline("");
}

/// The non-interactive invocation equivalent to `plan`.
///
/// The exit credential is redacted for the same reason a client URI is: it authenticates
/// the entry to the exit, and argv is readable by every local user through `ps`.
pub fn equivalent_command(plan: &ServerPlan, mode: ServerMode) -> String {
    // Matches the spelling in --exit-uri's own help and the README, and needs no shell
    // escaping, so the echoed line stays copy-pasteable.
    const CRED_PLACEHOLDER: &str = "<EXIT_URI>";
    let mut c = wizard::CommandLine::new("leshiy");
    c.arg(mode.subcommand())
        .opt("--host", Some(plan.host.as_str()))
        .opt("--dest", Some(plan.dest.as_str()));
    if plan.out != cli::DEFAULT_CONFIG {
        c.opt("--out", Some(plan.out.as_str()));
    }
    c.opt("--listen", plan.listen.as_deref())
        .opt("--quic-listen", plan.quic_listen.as_deref());
    match mode {
        // Only `quickstart` has --role/--exit-uri; `server-init` expresses an entry purely
        // by carrying the downstream credential in --connector.
        ServerMode::Quickstart => {
            c.opt("--quic-sni", plan.quic_sni.as_deref());
            if plan.role != Role::Single {
                c.opt("--role", Some(plan.role.as_flag()));
            }
            if plan.exit_uri.is_some() {
                c.opt("--exit-uri", Some(CRED_PLACEHOLDER));
            }
            if plan.no_probe {
                c.flag("--no-probe", true);
            }
        }
        ServerMode::Init => {
            c.opt("--quic-domain", plan.quic_sni.as_deref())
                .opt("--quic-cert", plan.quic_cert.as_deref())
                .opt("--quic-key", plan.quic_key.as_deref());
            if plan.exit_uri.is_some() {
                c.opt("--connector", Some(CRED_PLACEHOLDER));
            }
        }
    }
    c.render(78)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> ServerFlags {
        ServerFlags {
            host: Some("203.0.113.5:443".into()),
            dest: Some("www.microsoft.com:443".into()),
            listen: None,
            out: None,
            quic_listen: None,
            quic_sni: None,
            quic_cert: None,
            quic_key: None,
            role: None,
            exit_uri: None,
            no_probe: false,
        }
    }

    #[test]
    fn plan_from_flags_applies_the_documented_defaults() {
        let p = plan_from_flags(flags(), ServerMode::Quickstart).unwrap();
        assert_eq!(p.out, cli::DEFAULT_CONFIG);
        assert_eq!(p.role, Role::Single);
        assert_eq!(p.listen, None);
        assert_eq!(p.quic_listen, None);
    }

    #[test]
    fn plan_from_flags_demands_host_and_dest_and_mentions_interactive() {
        let e = plan_from_flags(
            ServerFlags {
                host: None,
                ..flags()
            },
            ServerMode::Init,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("--host") && e.contains("-i"), "got: {e}");

        let e = plan_from_flags(
            ServerFlags {
                dest: None,
                ..flags()
            },
            ServerMode::Init,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("--dest") && e.contains("-i"), "got: {e}");
    }

    /// An entry with no credential has nothing to forward to, and the error has to name the
    /// flag the command being run actually has.
    #[test]
    fn an_entry_without_a_credential_is_rejected_per_command() {
        let entry = || ServerFlags {
            role: Some(Role::Entry),
            ..flags()
        };
        let e = plan_from_flags(entry(), ServerMode::Init)
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains("--connector"),
            "server-init names --connector: {e}"
        );

        let e = plan_from_flags(entry(), ServerMode::Quickstart)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("--exit-uri"), "quickstart names --exit-uri: {e}");

        // With the credential it passes for both.
        for mode in [ServerMode::Init, ServerMode::Quickstart] {
            plan_from_flags(
                ServerFlags {
                    exit_uri: Some("leshiy://x".into()),
                    ..entry()
                },
                mode,
            )
            .unwrap_or_else(|e| panic!("{mode:?} should accept a credential: {e}"));
        }
    }

    /// An exit's whole purpose is to publish a carrier the entry dials; without QUIC it is
    /// unreachable, so this must fail at plan time rather than produce a dead config.
    #[test]
    fn an_exit_without_quic_is_rejected() {
        let e = plan_from_flags(
            ServerFlags {
                role: Some(Role::Exit),
                ..flags()
            },
            ServerMode::Quickstart,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("--quic-listen"), "got: {e}");

        plan_from_flags(
            ServerFlags {
                role: Some(Role::Exit),
                quic_listen: Some("203.0.113.5:443".into()),
                ..flags()
            },
            ServerMode::Quickstart,
        )
        .expect("an exit with QUIC is valid");
    }

    /// The connector credential authenticates the entry to the exit. It must never reach
    /// argv, exactly like a client URI.
    #[test]
    fn equivalent_command_never_renders_the_exit_credential() {
        let secret = "leshiy://SUPERSECRETKEY@203.0.113.9:443?sid=dead&quic=203.0.113.9:443";
        for mode in [ServerMode::Init, ServerMode::Quickstart] {
            let p = plan_from_flags(
                ServerFlags {
                    role: Some(Role::Entry),
                    exit_uri: Some(secret.into()),
                    ..flags()
                },
                mode,
            )
            .unwrap();
            let out = equivalent_command(&p, mode);
            assert!(!out.contains("SUPERSECRETKEY"), "{mode:?} leaked: {out}");
            assert!(!out.contains("203.0.113.9"), "{mode:?} leaked: {out}");
            assert!(out.contains("<EXIT_URI>"), "{mode:?}: {out}");
        }
    }

    /// `--role` and `--exit-uri` exist only on quickstart; emitting them for `server-init`
    /// would print a command that does not parse.
    #[test]
    fn the_echo_uses_only_flags_the_target_command_has() {
        let p = plan_from_flags(
            ServerFlags {
                role: Some(Role::Entry),
                exit_uri: Some("leshiy://x@h:443?quic=h:443".into()),
                quic_sni: Some("cdn.example.com".into()),
                ..flags()
            },
            ServerMode::Init,
        )
        .unwrap();
        let out = equivalent_command(&p, ServerMode::Init);
        assert!(out.starts_with("leshiy server-init "), "got: {out}");
        assert!(!out.contains("--role"), "server-init has no --role: {out}");
        assert!(
            !out.contains("--exit-uri"),
            "server-init has no --exit-uri: {out}"
        );
        assert!(out.contains("--connector"), "got: {out}");
        assert!(
            out.contains("--quic-domain"),
            "server-init spells it --quic-domain: {out}"
        );
        assert!(!out.contains("--quic-sni"), "got: {out}");
    }

    #[test]
    fn the_echo_uses_quickstarts_own_spelling() {
        let p = plan_from_flags(
            ServerFlags {
                role: Some(Role::Exit),
                quic_listen: Some("203.0.113.5:443".into()),
                quic_sni: Some("cdn.example.com".into()),
                ..flags()
            },
            ServerMode::Quickstart,
        )
        .unwrap();
        let out = equivalent_command(&p, ServerMode::Quickstart);
        assert!(out.contains("--role exit"), "got: {out}");
        assert!(out.contains("--quic-sni cdn.example.com"), "got: {out}");
        assert!(!out.contains("--quic-domain"), "got: {out}");
    }

    #[test]
    fn equivalent_command_omits_values_that_are_already_the_default() {
        let p = plan_from_flags(flags(), ServerMode::Quickstart).unwrap();
        assert_eq!(
            equivalent_command(&p, ServerMode::Quickstart),
            "leshiy quickstart --host 203.0.113.5:443 --dest www.microsoft.com:443"
        );
    }

    /// A credential without a `quic=` endpoint leaves the entry unable to reach the exit,
    /// so the wizard rejects it while the operator still has the terminal.
    #[test]
    fn a_connector_without_a_quic_endpoint_is_rejected() {
        // 43 base64url chars = the 32-byte x25519 public key a real URI carries.
        const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let no_quic = format!("leshiy://{KEY}@1.2.3.4:443?sni=x&sid=0102030400000000");
        let e = validate_connector(&no_quic).err().unwrap().to_string();
        assert!(
            e.contains("quic="),
            "must fail on the missing carrier, not on parsing: {e}"
        );

        // `quic=` is only meaningful with the `qsni=` it is served under; the URI parser
        // rejects one without the other, so a valid fixture must carry both.
        let with_quic = format!(
            "leshiy://{KEY}@1.2.3.4:443?sni=x&sid=0102030400000000&quic=1.2.3.4:443&qsni=cdn.x"
        );
        validate_connector(&with_quic).expect("a credential with a carrier is valid");

        assert!(validate_connector("not a uri").is_err());
    }
}
