//! The `-i` flows for `leshiy remote`: a provisioning wizard and the saved-server pickers
//! the day-2 subcommands use in place of a typed id.
//!
//! Flags win over prompts. Every field arrives as the `Option` clap parsed, and a `Some`
//! short-circuits its question, so `-i` composes with any subset of the flag surface.

use crate::cli;
use crate::wizard;
use anyhow::Result;
use leshiy_provision::vault::{ServerRecord, Vault};

/// Every decision `remote provision` needs, after flags and prompts have been merged.
pub struct ProvisionPlan {
    pub host: String,
    pub key: Option<String>,
    pub sudo: bool,
    pub dest: String,
    pub dns: Option<String>,
    pub port: u16,
    pub quic: Option<u16>,
    pub image: String,
    pub label: Option<String>,
    pub user_label: String,
    pub role: String,
    pub downstream: Option<String>,
}

const ROLES: &[(&str, &str)] = &[
    (
        "single",
        "standalone — clients connect here and this server egresses directly",
    ),
    (
        "entry",
        "censor-facing — forwards everything to a downstream hop",
    ),
    ("middle", "extra hop between an entry and an exit"),
    (
        "exit",
        "clean egress — hands out a connector credential for the hop in front",
    ),
];

/// Roles whose provisioning requires selecting a downstream to forward to.
fn needs_downstream(role: &str) -> bool {
    matches!(role, "entry" | "middle")
}

/// Roles that publish a QUIC carrier, which the hop in front dials.
fn requires_quic(role: &str) -> bool {
    matches!(role, "exit" | "middle")
}

fn user_is_root(host_spec: &str) -> bool {
    crate::remote_cli::parse_ssh_host(host_spec).is_ok_and(|(user, _, _)| user == "root")
}

/// The vault id `provision` derives for an SSH target: host plus SSH port.
pub fn vault_id_for(host_spec: &str) -> Result<String> {
    let (_, host, ssh_port) = crate::remote_cli::parse_ssh_host(host_spec)?;
    Ok(format!("{host}-{ssh_port}"))
}

/// Guard the operator against silently replacing a server they already have.
fn confirm_not_already_saved(vault: &Vault, host_spec: &str) -> Result<()> {
    let id = vault_id_for(host_spec)?;
    let Some(existing) = vault.list().iter().find(|r| r.id == id) else {
        return Ok(());
    };
    crate::ui::warn(&format!("this vault already has {}", server_row(existing)));
    anyhow::ensure!(
        wizard::confirm("Replace its saved entry?", false)?,
        "cancelled: {id} is already saved"
    );
    Ok(())
}

/// One line per saved server for the picker: what an operator needs to tell two of their
/// servers apart without opening the vault by hand.
pub fn server_row(rec: &ServerRecord) -> String {
    let role = if rec.role.is_empty() {
        "single"
    } else {
        &rec.role
    };
    let clients = match rec.clients.len() {
        1 => "1 client".to_string(),
        n => format!("{n} clients"),
    };
    format!(
        "{}  ({})  {}  {}  {}",
        rec.label, rec.id, role, rec.public_host, clients
    )
}

/// The non-interactive invocation equivalent to `plan`, for the review screen.
///
/// Secrets are deliberately absent: an SSH or sudo password would end up in shell history
/// the moment someone copies this line, so the rendered command re-prompts for them.
pub fn equivalent_command(plan: &ProvisionPlan) -> String {
    let mut c = wizard::CommandLine::new("leshiy remote provision");
    c.opt("--host", Some(&plan.host))
        .opt("--dest", Some(&plan.dest))
        .opt("--key", plan.key.as_deref())
        .flag("--sudo", plan.sudo)
        .opt(
            "--role",
            (plan.role != cli::DEFAULT_ROLE).then_some(&plan.role),
        )
        .opt("--downstream", plan.downstream.as_deref())
        .opt(
            "--port",
            (plan.port != cli::DEFAULT_LISTEN_PORT)
                .then(|| plan.port.to_string())
                .as_deref(),
        )
        .opt("--quic", plan.quic.map(|p| p.to_string()).as_deref())
        .opt("--label", plan.label.as_deref())
        .opt(
            "--user-label",
            (plan.user_label != cli::DEFAULT_USER_LABEL).then_some(&plan.user_label),
        )
        .opt("--dns", plan.dns.as_deref())
        .opt(
            "--image",
            (plan.image != cli::DEFAULT_IMAGE).then_some(&plan.image),
        );
    c.render(78)
}

/// Pick a saved server, or resolve `given` when the operator already named one.
pub fn pick_server(vault: &Vault, given: Option<String>, prompt: &str) -> Result<String> {
    if let Some(s) = given {
        return Ok(s);
    }
    let records = vault.list();
    anyhow::ensure!(
        !records.is_empty(),
        "no saved servers yet — run `leshiy remote provision -i` first"
    );
    let rows: Vec<String> = records.iter().map(server_row).collect();
    let idx = wizard::select(prompt, &rows, 0)?;
    Ok(records[idx].id.clone())
}

/// Pick the hop this server forwards to. Only servers holding a connector credential are
/// offered: without one there is nothing for an entry to authenticate against.
pub fn pick_downstream(vault: &Vault, given: Option<String>, role: &str) -> Result<String> {
    if let Some(d) = given {
        return Ok(d);
    }
    let eligible: Vec<&ServerRecord> = vault
        .list()
        .iter()
        .filter(|r| r.connector_uri.is_some())
        .collect();
    anyhow::ensure!(
        !eligible.is_empty(),
        "--role {role} forwards to another server, but no saved server has a connector \
         credential — provision one with `--role exit` first"
    );
    let rows: Vec<String> = eligible.iter().map(|r| server_row(r)).collect();
    let idx = wizard::select("Downstream server to forward to", &rows, 0)?;
    Ok(eligible[idx].id.clone())
}

/// Pick a user on the live server. `rows` is `annotate_users`' output.
pub fn pick_user(rows: &[(String, Option<String>, bool)], given: Option<String>) -> Result<String> {
    if let Some(s) = given {
        return Ok(s);
    }
    anyhow::ensure!(!rows.is_empty(), "no users on this server");
    let items: Vec<String> = rows
        .iter()
        .map(|(short_id, label, enabled)| {
            format!(
                "{}  ({})  {}",
                label.as_deref().unwrap_or("(not in vault)"),
                short_id,
                if *enabled { "enabled" } else { "disabled" }
            )
        })
        .collect();
    let idx = wizard::select("User", &items, 0)?;
    Ok(rows[idx].0.clone())
}

/// Flags as clap parsed them; `None` means "ask".
pub struct ProvisionFlags {
    pub host: Option<String>,
    pub key: Option<String>,
    pub sudo: bool,
    pub dest: Option<String>,
    pub dns: Option<String>,
    pub port: Option<u16>,
    pub quic: Option<u16>,
    pub image: Option<String>,
    pub label: Option<String>,
    pub user_label: Option<String>,
    pub role: Option<String>,
    pub downstream: Option<String>,
}

/// Merge `flags` with defaults, asking nothing. The non-interactive path.
pub fn plan_from_flags(flags: ProvisionFlags) -> Result<ProvisionPlan> {
    let host = flags
        .host
        .ok_or_else(|| anyhow::anyhow!("--host is required (or pass -i to be asked for it)"))?;
    let dest = flags
        .dest
        .ok_or_else(|| anyhow::anyhow!("--dest is required (or pass -i to be asked for it)"))?;
    Ok(ProvisionPlan {
        host,
        key: flags.key,
        sudo: flags.sudo,
        dest,
        dns: flags.dns,
        port: flags.port.unwrap_or(cli::DEFAULT_LISTEN_PORT),
        quic: flags.quic,
        image: flags
            .image
            .unwrap_or_else(|| cli::DEFAULT_IMAGE.to_string()),
        label: flags.label,
        user_label: flags
            .user_label
            .unwrap_or_else(|| cli::DEFAULT_USER_LABEL.to_string()),
        role: flags.role.unwrap_or_else(|| cli::DEFAULT_ROLE.to_string()),
        downstream: flags.downstream,
    })
}

/// Ask for whatever `flags` left unset, then show a review the operator confirms.
pub async fn plan_interactively(flags: ProvisionFlags, vault: &Vault) -> Result<ProvisionPlan> {
    const TOTAL: u8 = 5;

    // Root needs no escalation, so sudo is only ever asked about for another user. That
    // makes `--host root@… --key …` a step with no questions left in it.
    let asks_sudo = !flags.sudo && !flags.host.as_deref().is_some_and(user_is_root);
    wizard::step(
        1,
        TOTAL,
        "SSH target",
        flags.host.is_none() || flags.key.is_none() || asks_sudo,
    );
    let host = match flags.host {
        Some(h) => h,
        None => ask_ssh_target()?,
    };
    let key = match flags.key {
        Some(k) => Some(k),
        None => ask_ssh_key()?,
    };
    let sudo = flags.sudo
        || (!user_is_root(&host) && wizard::confirm("Run privileged commands via sudo?", true)?);
    // Checked here rather than after the review: the operator should learn the server is
    // already known before answering another ten questions about it.
    confirm_not_already_saved(vault, &host)?;

    wizard::step(
        2,
        TOTAL,
        "Role",
        flags.role.is_none()
            || flags
                .role
                .as_deref()
                .is_some_and(|r| needs_downstream(r) && flags.downstream.is_none()),
    );
    let role = match flags.role {
        Some(r) => r,
        None => {
            let items: Vec<String> = ROLES
                .iter()
                .map(|(name, help)| format!("{name:<7} {help}"))
                .collect();
            ROLES[wizard::select("Role for this server", &items, 0)?]
                .0
                .to_string()
        }
    };
    crate::remote_cli::parse_role(&role)?;
    let downstream = if needs_downstream(&role) {
        Some(pick_downstream(vault, flags.downstream, &role)?)
    } else {
        flags.downstream
    };

    wizard::step(
        3,
        TOTAL,
        "Camouflage and ports",
        flags.dest.is_none() || flags.port.is_none() || flags.quic.is_none(),
    );
    let dest = match flags.dest {
        Some(d) => d,
        None => ask_dest().await?,
    };
    let port = match flags.port {
        Some(p) => p,
        None => wizard::port("REALITY/TCP listen port", cli::DEFAULT_LISTEN_PORT)?,
    };
    let quic = match flags.quic {
        Some(q) => Some(q),
        None if requires_quic(&role) => {
            crate::ui::hint(&format!(
                "role {role} publishes a QUIC carrier for the hop in front — it is required"
            ));
            Some(wizard::port("QUIC/UDP port", port)?)
        }
        None if wizard::confirm("Enable the QUIC/HTTP-3 transport?", true)? => {
            Some(wizard::port("QUIC/UDP port", port)?)
        }
        None => None,
    };

    wizard::step(
        4,
        TOTAL,
        "Labels",
        flags.label.is_none() || flags.user_label.is_none() || flags.image.is_none(),
    );
    let label = match flags.label {
        Some(l) => Some(l),
        None => wizard::text_opt("Server label (blank = the hostname)")?,
    };
    let user_label = match flags.user_label {
        Some(l) => l,
        None => wizard::text(
            "Label for the first client config",
            Some(cli::DEFAULT_USER_LABEL),
        )?,
    };
    let (image, dns) = match (flags.image.clone(), flags.dns.clone()) {
        (Some(i), dns) => (i, dns),
        (None, dns) if !wizard::confirm("Set advanced options (image, DNS)?", false)? => {
            (cli::DEFAULT_IMAGE.to_string(), dns)
        }
        (None, dns) => {
            let image = wizard::text("Container image", Some(cli::DEFAULT_IMAGE))?;
            let dns = match dns {
                Some(d) => Some(d),
                None => wizard::text_opt("DNS resolver override (blank = auto-detect)")?,
            };
            (image, dns)
        }
    };

    let plan = ProvisionPlan {
        host,
        key,
        sudo,
        dest,
        dns,
        port,
        quic,
        image,
        label,
        user_label,
        role,
        downstream,
    };

    wizard::step(5, TOTAL, "Review", true);
    review(&plan);
    anyhow::ensure!(
        wizard::confirm("Provision now?", true)?,
        "cancelled at the review step"
    );
    Ok(plan)
}

fn review(plan: &ProvisionPlan) {
    let f = |k: &str, v: &str| crate::ui::eline(&crate::ui::field(k, &crate::ui::value(v)));
    f("ssh", &plan.host);
    f("auth", plan.key.as_deref().unwrap_or("password (prompted)"));
    if plan.sudo {
        f("sudo", "yes (prompted)");
    }
    f("role", &plan.role);
    if let Some(d) = &plan.downstream {
        f("downstream", d);
    }
    f("dest", &plan.dest);
    f("port", &plan.port.to_string());
    f("quic", &plan.quic.map_or("off".into(), |p| p.to_string()));
    f("label", plan.label.as_deref().unwrap_or("(hostname)"));
    f("client", &plan.user_label);
    if let Some(d) = &plan.dns {
        f("dns", d);
    }
    f("image", &plan.image);
    crate::ui::eline("");
    crate::ui::eline(&crate::ui::label("Same run, without the wizard:"));
    crate::ui::eline(&format!("  {}", equivalent_command(plan)));
    crate::ui::eline("");
}

fn ask_ssh_target() -> Result<String> {
    let host = wizard::text("Server host or IP", None)?;
    let user = wizard::text("SSH user", Some("root"))?;
    let port = wizard::port("SSH port", 22)?;
    let hostport = leshiy_reality::addr::join_host_port(&host, port);
    Ok(format!("{user}@{hostport}"))
}

fn ask_ssh_key() -> Result<Option<String>> {
    let found = wizard::ssh_dir()
        .map(|d| wizard::ssh_key_candidates(&d))
        .unwrap_or_default();
    let mut items: Vec<String> = found
        .iter()
        .map(|p| format!("{}  (detected)", p.display()))
        .collect();
    let password_idx = items.len();
    items.push("Password".to_string());
    items.push("Another key file…".to_string());

    let idx = wizard::select("Authentication", &items, 0)?;
    if idx < password_idx {
        Ok(Some(found[idx].display().to_string()))
    } else if idx == password_idx {
        Ok(None)
    } else {
        Ok(Some(wizard::text("Path to the private key", None)?))
    }
}

async fn ask_dest() -> Result<String> {
    let mut items: Vec<String> = wizard::DEST_PRESETS.iter().map(|s| s.to_string()).collect();
    let custom_idx = items.len();
    items.push("Custom…".to_string());
    crate::ui::hint("the borrowed site whose TLS identity this server presents — pick one");
    crate::ui::hint("that is popular and plausible to visit from your users' region");

    loop {
        let idx = wizard::select("Borrowed TLS site (dest)", &items, 0)?;
        let dest = if idx == custom_idx {
            wizard::text("Site as host:port", Some("www.microsoft.com:443"))?
        } else {
            items[idx].clone()
        };
        if probe_dest(&dest).await? {
            return Ok(dest);
        }
        anyhow::ensure!(
            wizard::confirm("Pick a different site?", true)?,
            "dest {dest} is unusable for REALITY — it must negotiate TLS 1.3"
        );
    }
}

/// Probe `dest` for TLS 1.3, reporting the outcome. A failure is not fatal on its own: the
/// operator's network may block the site their server can reach perfectly well.
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

#[cfg(test)]
mod tests {
    use super::*;
    use leshiy_provision::vault::{ClientConfig, SshSecret};

    fn record(id: &str, label: &str, role: &str, connector: Option<&str>) -> ServerRecord {
        ServerRecord {
            id: id.into(),
            label: label.into(),
            host: "1.2.3.4".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::Password("p".to_string().into()),
            host_key_fp: "fp".into(),
            public_host: "1.2.3.4:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "x".into(),
            quic: None,
            clients: vec![ClientConfig {
                short_id: "01".into(),
                label: "self".into(),
                uri: "leshiy://x@1.2.3.4:443?sid=01".into(),
            }],
            created_at: 0,
            role: role.into(),
            connector_uri: connector.map(str::to_string),
            downstream: None,
            sudo: false,
        }
    }

    fn plan() -> ProvisionPlan {
        ProvisionPlan {
            host: "root@203.0.113.5".into(),
            key: None,
            sudo: false,
            dest: "www.microsoft.com:443".into(),
            dns: None,
            port: cli::DEFAULT_LISTEN_PORT,
            quic: None,
            image: cli::DEFAULT_IMAGE.into(),
            label: None,
            user_label: cli::DEFAULT_USER_LABEL.into(),
            role: cli::DEFAULT_ROLE.into(),
            downstream: None,
        }
    }

    /// An all-defaults run must echo the short command, not every flag at its default —
    /// the point of the review line is to be copy-pasteable, not exhaustive.
    #[test]
    fn equivalent_command_omits_values_that_are_already_the_default() {
        let out = equivalent_command(&plan());
        assert_eq!(
            out,
            "leshiy remote provision --host root@203.0.113.5 --dest www.microsoft.com:443"
        );
    }

    #[test]
    fn equivalent_command_includes_every_non_default_choice() {
        let mut p = plan();
        p.key = Some("/home/u/.ssh/id_ed25519".into());
        p.sudo = true;
        p.port = 8443;
        p.quic = Some(8443);
        p.role = "entry".into();
        p.downstream = Some("exit-1".into());
        p.label = Some("paris".into());
        p.user_label = "phone".into();
        p.dns = Some("1.1.1.1".into());
        p.image = "ghcr.io/x/y:v9".into();
        let flat = equivalent_command(&p)
            .replace(" \\\n    ", " ")
            .replace(" \\\n", " ");
        for expected in [
            "--host root@203.0.113.5",
            "--dest www.microsoft.com:443",
            "--key /home/u/.ssh/id_ed25519",
            "--sudo",
            "--role entry",
            "--downstream exit-1",
            "--port 8443",
            "--quic 8443",
            "--label paris",
            "--user-label phone",
            "--dns 1.1.1.1",
            "--image ghcr.io/x/y:v9",
        ] {
            assert!(flat.contains(expected), "missing {expected} in: {flat}");
        }
    }

    /// A password-authenticated run must never render a credential into a copy-pasteable
    /// line; the equivalent command re-prompts instead.
    #[test]
    fn equivalent_command_never_renders_a_secret() {
        let mut p = plan();
        p.sudo = true;
        let out = equivalent_command(&p);
        assert!(!out.contains("password"), "leaked a credential: {out}");
        assert!(!out.contains("passphrase"), "leaked a credential: {out}");
    }

    /// A shell-hostile label must survive the round trip as one argument.
    #[test]
    fn equivalent_command_quotes_hostile_labels() {
        let mut p = plan();
        p.label = Some("my server; rm -rf /".into());
        let out = equivalent_command(&p);
        assert!(out.contains("--label 'my server; rm -rf /'"), "got: {out}");
    }

    #[test]
    fn server_row_shows_what_distinguishes_two_servers() {
        let row = server_row(&record("1.2.3.4-22", "paris", "exit", Some("leshiy://c")));
        assert!(row.contains("paris"));
        assert!(row.contains("1.2.3.4-22"));
        assert!(row.contains("exit"));
        assert!(row.contains("1.2.3.4:443"));
        assert!(row.contains("1 client"));
    }

    /// Legacy records predate the `role` field and deserialize it as an empty string;
    /// the picker must still say what they are rather than render a blank column.
    #[test]
    fn server_row_labels_a_roleless_record_as_single() {
        let row = server_row(&record("id", "old", "", None));
        assert!(row.contains("single"), "got: {row}");
    }

    #[test]
    fn given_values_short_circuit_every_picker() {
        let vault = Vault::new();
        assert_eq!(
            pick_server(&vault, Some("srv".into()), "Server").unwrap(),
            "srv"
        );
        assert_eq!(
            pick_downstream(&vault, Some("ds".into()), "entry").unwrap(),
            "ds"
        );
        assert_eq!(pick_user(&[], Some("abcd".into())).unwrap(), "abcd");
    }

    /// With nothing to choose from, the pickers must explain the way forward rather than
    /// open an empty menu the operator cannot escape.
    #[test]
    fn empty_pickers_fail_with_an_actionable_message() {
        let vault = Vault::new();
        let e = pick_server(&vault, None, "Server")
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("remote provision -i"), "got: {e}");

        let e = pick_downstream(&vault, None, "entry")
            .unwrap_err()
            .to_string();
        assert!(e.contains("--role exit"), "got: {e}");
    }

    /// An entry can only chain onto a server that actually issued a connector credential.
    #[test]
    fn downstream_picker_rejects_a_vault_of_only_single_servers() {
        let mut vault = Vault::new();
        vault.upsert(record("a-22", "alpha", "single", None));
        vault.upsert(record("b-22", "beta", "single", None));
        let e = pick_downstream(&vault, None, "entry")
            .unwrap_err()
            .to_string();
        assert!(e.contains("no saved server has a connector"), "got: {e}");
    }

    /// Drives whether the wizard offers sudo at all. A malformed spec must not be treated
    /// as root, or the escalation question would be silently skipped for a non-root user.
    #[test]
    fn user_is_root_only_for_a_parseable_root_target() {
        assert!(user_is_root("root@1.2.3.4"));
        assert!(user_is_root("root@1.2.3.4:2222"));
        assert!(user_is_root("root@[2001:db8::1]:22"));
        assert!(!user_is_root("deploy@1.2.3.4"));
        assert!(!user_is_root("rooted@1.2.3.4"));
        assert!(!user_is_root("1.2.3.4"));
        assert!(!user_is_root(""));
    }

    /// The id must match the one `provision` derives, or the overwrite guard silently
    /// never fires and a re-provision quietly replaces a saved server.
    #[test]
    fn vault_id_matches_the_host_port_pair_provision_persists() {
        assert_eq!(vault_id_for("root@1.2.3.4").unwrap(), "1.2.3.4-22");
        assert_eq!(vault_id_for("root@1.2.3.4:2222").unwrap(), "1.2.3.4-2222");
        // IPv6 is stored unbracketed, exactly as the provision arm formats it.
        assert_eq!(
            vault_id_for("root@[2001:db8::1]:2222").unwrap(),
            "2001:db8::1-2222"
        );
        assert!(vault_id_for("no-at-sign").is_err());
    }

    #[test]
    fn role_capabilities_match_the_provisioning_engine() {
        assert!(needs_downstream("entry") && needs_downstream("middle"));
        assert!(!needs_downstream("single") && !needs_downstream("exit"));
        assert!(requires_quic("exit") && requires_quic("middle"));
        assert!(!requires_quic("single") && !requires_quic("entry"));
    }

    /// Every role offered in the picker must be one `parse_role` accepts, or the wizard
    /// would collect a full plan and only then reject it.
    #[test]
    fn every_offered_role_is_accepted_by_the_parser() {
        for (name, help) in ROLES {
            crate::remote_cli::parse_role(name)
                .unwrap_or_else(|e| panic!("role {name} rejected: {e}"));
            assert!(!help.is_empty(), "role {name} has no explanation");
        }
    }

    #[test]
    fn plan_from_flags_applies_the_documented_defaults() {
        let p = plan_from_flags(ProvisionFlags {
            host: Some("root@h".into()),
            key: None,
            sudo: false,
            dest: Some("d:443".into()),
            dns: None,
            port: None,
            quic: None,
            image: None,
            label: None,
            user_label: None,
            role: None,
            downstream: None,
        })
        .unwrap();
        assert_eq!(p.port, 443);
        assert_eq!(p.user_label, "self");
        assert_eq!(p.role, "single");
        assert_eq!(p.image, cli::DEFAULT_IMAGE);
    }

    /// Without `-i` the required flags must still be required, and the error has to point
    /// at the escape hatch rather than just restating the flag name.
    #[test]
    fn plan_from_flags_demands_host_and_dest_and_mentions_interactive() {
        let bare = || ProvisionFlags {
            host: None,
            key: None,
            sudo: false,
            dest: None,
            dns: None,
            port: None,
            quic: None,
            image: None,
            label: None,
            user_label: None,
            role: None,
            downstream: None,
        };
        let e = plan_from_flags(bare()).err().unwrap().to_string();
        assert!(e.contains("--host") && e.contains("-i"), "got: {e}");

        let e = plan_from_flags(ProvisionFlags {
            host: Some("root@h".into()),
            ..bare()
        })
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("--dest") && e.contains("-i"), "got: {e}");
    }
}
