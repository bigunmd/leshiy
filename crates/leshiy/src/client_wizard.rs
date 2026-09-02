//! The `-i` flows for the client side: `connect`, `client`, `tun`, `vpn` and
//! `service start`.
//!
//! The `leshiy://` URI is a bearer credential — `service.rs` goes to some length to keep
//! it out of `ExecStart` and out of `ps`. This module holds that line: [`UriSource`]
//! records where a URI came from so the review screen can echo a runnable command without
//! ever printing the credential itself.

use crate::cli::{self, Transport};
use crate::wizard;
use anyhow::Result;

/// Which command the plan will be executed by. Decides the defaults, the questions worth
/// asking, and the subcommand the review screen echoes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Proxy,
    Connect,
    Tun,
    Vpn,
    Service { tun: bool },
}

impl Mode {
    /// Modes that route the whole device and therefore need UDP and ICMP in the tunnel.
    fn is_full_tunnel(self) -> bool {
        matches!(self, Self::Tun | Self::Vpn | Self::Service { tun: true })
    }

    fn subcommand(self) -> &'static str {
        match self {
            Self::Proxy => "client",
            Self::Connect => "connect",
            Self::Tun => "tun",
            Self::Vpn => "vpn",
            Self::Service { .. } => "service start",
        }
    }

    /// `tun` defaults to REALITY/TCP because only it carries UDP and ICMP today; a proxy
    /// has no such constraint and prefers the faster QUIC path. Delegated so the wizard
    /// and the generated systemd unit can never disagree about it.
    fn default_transport(self) -> Transport {
        Transport::for_service(None, self.is_full_tunnel())
    }
}

/// Where the URI came from, which decides what the review screen may safely print.
pub enum UriSource {
    /// Typed or pasted, or already on the command line. Echoing it would put a credential
    /// into shell history, so the review screen prints a placeholder.
    Direct,
    /// Read from a 0600 credential file. The *path* is not secret, so the echoed command
    /// is both runnable and leak-free.
    File(String),
    /// Taken from the provisioning vault; there is no flag that expresses this.
    Vault,
}

pub struct ClientPlan {
    pub uri: String,
    pub source: UriSource,
    pub transport: Transport,
    pub socks: Option<String>,
    pub mtu: u16,
    pub tun_name: String,
    pub dns: String,
    pub ipv6: bool,
    pub socket: String,
}

impl ClientPlan {
    /// The proxy modes always listen somewhere, so they need a concrete address even
    /// though the shared plan models `socks` as optional for `tun`'s sake.
    pub fn socks_or_default(&self) -> String {
        self.socks
            .clone()
            .unwrap_or_else(|| cli::DEFAULT_SOCKS.to_string())
    }
}

/// Flags as clap parsed them; `None` means "ask".
#[derive(Default)]
pub struct ClientFlags {
    pub uri: Option<String>,
    pub uri_file: Option<String>,
    pub transport: Option<Transport>,
    pub socks: Option<String>,
    pub no_socks: bool,
    pub mtu: Option<u16>,
    pub tun_name: Option<String>,
    pub dns: Option<String>,
    pub ipv6: bool,
    pub socket: Option<String>,
}

const TRANSPORTS: &[(Transport, &str, &str)] = &[
    (
        Transport::Auto,
        "auto",
        "try QUIC, fall back to REALITY/TCP where UDP is blocked",
    ),
    (
        Transport::Quic,
        "quic",
        "QUIC/HTTP-3 only — needs a quic= endpoint in the URI",
    ),
    (
        Transport::Tcp,
        "tcp",
        "REALITY over TCP/443 — the only transport carrying UDP and ICMP today",
    ),
];

/// What this machine can actually do, so the router offers real choices rather than a menu
/// of four things three of which fail on selection.
pub struct Capabilities {
    pub privileged: bool,
    pub helper: bool,
    pub systemd: bool,
}

impl Capabilities {
    pub fn probe() -> Self {
        Self {
            privileged: crate::elevate::have_privileges(),
            helper: std::path::Path::new(cli::DEFAULT_HELPER_SOCKET).exists(),
            systemd: crate::service::systemd_available(),
        }
    }
}

pub struct ModeEntry {
    pub mode: Mode,
    pub label: &'static str,
    pub note: &'static str,
    /// Why this machine cannot run it, if it cannot.
    pub blocked: Option<&'static str>,
}

/// The router's menu. Every way of connecting is listed even when unavailable: "why is
/// there no VPN option" is a worse question to leave an operator with than a named reason.
pub fn mode_menu(caps: &Capabilities) -> Vec<ModeEntry> {
    vec![
        ModeEntry {
            mode: Mode::Connect,
            label: "Local SOCKS5 proxy",
            note: "no root needed; point your apps at 127.0.0.1:1080",
            blocked: None,
        },
        ModeEntry {
            mode: Mode::Tun,
            label: "Full-device VPN",
            note: if caps.privileged {
                "routes everything on this machine"
            } else {
                "routes everything on this machine; will prompt for sudo"
            },
            blocked: None,
        },
        ModeEntry {
            mode: Mode::Vpn,
            label: "Full-device VPN via the helper",
            note: "same, but the privileged helper owns it — no sudo prompt",
            blocked: (!caps.helper)
                .then_some("leshiy-helper is not running (no /run/leshiy/helper.sock)"),
        },
        ModeEntry {
            mode: Mode::Service { tun: false },
            label: "Background proxy service",
            note: "a systemd user unit; survives logout",
            blocked: (!caps.systemd).then_some("systemd is not the init here"),
        },
        ModeEntry {
            mode: Mode::Service { tun: true },
            label: "Background full-device VPN service",
            note: "a systemd system unit; survives reboot, needs root",
            blocked: (!caps.systemd).then_some("systemd is not the init here"),
        },
    ]
}

pub fn render_mode_entry(e: &ModeEntry) -> String {
    match e.blocked {
        Some(reason) => format!("{:<36} unavailable — {reason}", e.label),
        None => format!("{:<36} {}", e.label, e.note),
    }
}

/// Ask which way to connect. The entry point for `leshiy connect -i`, which is where
/// someone lands when they do not yet know that `tun`, `vpn` and `service` are different.
pub fn pick_mode() -> Result<Mode> {
    let entries = mode_menu(&Capabilities::probe());
    let items: Vec<String> = entries.iter().map(render_mode_entry).collect();
    let default = entries
        .iter()
        .position(|e| e.blocked.is_none())
        .unwrap_or(0);
    let picked = &entries[wizard::select("How do you want to connect?", &items, default)?];
    if let Some(reason) = picked.blocked {
        anyhow::bail!("{} is unavailable: {reason}", picked.label);
    }
    Ok(picked.mode)
}

/// Merge flags with defaults, asking nothing. The non-interactive path.
pub fn plan_from_flags(flags: ClientFlags, mode: Mode) -> Result<ClientPlan> {
    // `service::resolve_uri` names both flags, but not every entry point has both: the URI
    // is positional on `connect`, and `vpn` has no --uri-file at all.
    if flags.uri.is_none() && flags.uri_file.is_none() {
        anyhow::bail!(
            "{} (or pass -i to pick a server from a list)",
            match mode {
                Mode::Connect => "provide the leshiy:// URI",
                Mode::Vpn => "provide --uri",
                _ => "provide --uri or --uri-file",
            }
        );
    }
    let (uri, source) = resolve_uri_from_flags(&flags)?;
    Ok(ClientPlan {
        uri,
        source,
        transport: flags.transport.unwrap_or_else(|| mode.default_transport()),
        socks: resolve_socks_from_flags(&flags, mode),
        mtu: flags.mtu.unwrap_or(cli::DEFAULT_MTU),
        tun_name: flags
            .tun_name
            .unwrap_or_else(|| cli::DEFAULT_TUN_NAME.to_string()),
        dns: flags.dns.unwrap_or_else(|| cli::DEFAULT_DNS.to_string()),
        ipv6: flags.ipv6,
        socket: flags
            .socket
            .unwrap_or_else(|| cli::DEFAULT_HELPER_SOCKET.to_string()),
    })
}

fn resolve_uri_from_flags(flags: &ClientFlags) -> Result<(String, UriSource)> {
    let uri = crate::service::resolve_uri(flags.uri.as_deref(), flags.uri_file.as_deref())?;
    let source = match flags.uri_file.as_deref() {
        Some(f) => UriSource::File(f.to_string()),
        None => UriSource::Direct,
    };
    Ok((uri, source))
}

/// `tun` runs no proxy unless asked; every other mode always listens somewhere.
fn resolve_socks_from_flags(flags: &ClientFlags, mode: Mode) -> Option<String> {
    if flags.no_socks {
        return None;
    }
    match (flags.socks.clone(), mode) {
        (Some(s), _) => Some(s),
        (None, Mode::Tun) => None,
        (None, _) => Some(cli::DEFAULT_SOCKS.to_string()),
    }
}

/// Ask for whatever `flags` left unset, then show a review the operator confirms.
pub fn plan_interactively(flags: ClientFlags, mode: Mode) -> Result<ClientPlan> {
    let total: u8 = if mode.is_full_tunnel() { 4 } else { 3 };

    wizard::step(
        1,
        total,
        "Server",
        flags.uri.is_none() && flags.uri_file.is_none(),
    );
    let (uri, source) = match (flags.uri.clone(), flags.uri_file.clone()) {
        (None, None) => ask_uri()?,
        _ => resolve_uri_from_flags(&flags)?,
    };
    describe_uri(&uri);

    wizard::step(
        2,
        total,
        "Transport",
        flags.transport.is_none() || flags.socks.is_none(),
    );
    let transport = match flags.transport {
        Some(t) => t,
        None => ask_transport(mode)?,
    };
    let socks = ask_socks(&flags, mode)?;

    let (mtu, tun_name, dns, ipv6, socket) = if mode.is_full_tunnel() {
        ask_tunnel_options(&flags, mode, total)?
    } else {
        (
            cli::DEFAULT_MTU,
            cli::DEFAULT_TUN_NAME.to_string(),
            cli::DEFAULT_DNS.to_string(),
            false,
            cli::DEFAULT_HELPER_SOCKET.to_string(),
        )
    };

    let plan = ClientPlan {
        uri,
        source,
        transport,
        socks,
        mtu,
        tun_name,
        dns,
        ipv6,
        socket,
    };

    wizard::step(total, total, "Review", true);
    review(&plan, mode);
    anyhow::ensure!(
        wizard::confirm("Connect now?", true)?,
        "cancelled at the review step"
    );
    Ok(plan)
}

fn ask_uri() -> Result<(String, UriSource)> {
    let vault = crate::remote_cli::vault_path();
    let has_vault = vault.exists();
    let mut items = Vec::new();
    if has_vault {
        items.push("A server I provisioned (from the vault)".to_string());
    }
    items.push("Paste a leshiy:// URI".to_string());
    items.push("Read from a credential file".to_string());

    let choice = wizard::select("Where is the server URI?", &items, 0)?;
    let choice = if has_vault { choice } else { choice + 1 };
    let (uri, source) = match choice {
        0 => (pick_uri_from_vault()?, UriSource::Vault),
        1 => {
            crate::ui::hint("this is a credential — it will not be echoed back to you");
            let uri = wizard::secret("Paste the leshiy:// URI")?;
            (uri.trim().to_string(), UriSource::Direct)
        }
        _ => {
            let path = wizard::text("Path to the 0600 credential file", None)?;
            let uri = crate::service::read_credential(std::path::Path::new(&path))?;
            (uri, UriSource::File(path))
        }
    };
    // Every source is checked, the vault included: a corrupt saved entry should be named
    // here rather than surface as an opaque dial failure minutes later.
    validate_uri(&uri)?;
    Ok((uri, source))
}

/// Every client config in the vault, flattened to one pickable row per issued user.
pub fn vault_client_rows(vault: &leshiy_provision::vault::Vault) -> Vec<(String, String)> {
    vault
        .list()
        .iter()
        .flat_map(|rec| {
            rec.clients.iter().map(move |c| {
                (
                    format!("{}  ·  {}  ({})", rec.label, c.label, rec.public_host),
                    c.uri.clone(),
                )
            })
        })
        .collect()
}

fn pick_uri_from_vault() -> Result<String> {
    let pass = wizard::secret("Vault passphrase")?;
    let vault = leshiy_provision::vault::Vault::load(&crate::remote_cli::vault_path(), &pass)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = vault_client_rows(&vault);
    anyhow::ensure!(
        !rows.is_empty(),
        "no client configs in the vault — issue one with `leshiy remote user add -i`"
    );
    let items: Vec<String> = rows.iter().map(|(label, _)| label.clone()).collect();
    let idx = wizard::select("Server", &items, 0)?;
    Ok(rows[idx].1.clone())
}

fn validate_uri(uri: &str) -> Result<()> {
    leshiy_reality::config::RealityUri::parse(uri.trim())
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("that is not a usable leshiy:// URI: {e}"))
}

/// Confirm which server was selected without echoing the credential. The host and SNI are
/// visible to any observer of the connection anyway, so they leak nothing new.
fn describe_uri(uri: &str) {
    let Ok(parsed) = leshiy_reality::config::RealityUri::parse(uri.trim()) else {
        return;
    };
    crate::ui::ok(&format!(
        "server {} (sni {}){}",
        crate::ui::value(&parsed.server_addr),
        crate::ui::value(&parsed.client.sni),
        if parsed.quic.is_some() {
            ", QUIC available"
        } else {
            ""
        }
    ));
}

fn ask_transport(mode: Mode) -> Result<Transport> {
    let default = mode.default_transport();
    let default_idx = TRANSPORTS
        .iter()
        .position(|(t, _, _)| *t == default)
        .unwrap_or(0);
    let items: Vec<String> = TRANSPORTS
        .iter()
        .map(|(_, name, help)| format!("{name:<5} {help}"))
        .collect();
    let picked = TRANSPORTS[wizard::select("Transport", &items, default_idx)?].0;
    // Same trap `service start` warns about: a full tunnel on QUIC serves TCP while DNS
    // and ping die inside it, which looks like a dead network on a healthy-looking tunnel.
    if mode.is_full_tunnel() && picked != Transport::Tcp {
        crate::ui::warn(
            "a full tunnel needs UDP and ICMP, which only tcp carries today; \
             DNS and ping will not work inside the tunnel",
        );
        anyhow::ensure!(
            wizard::confirm("Use it anyway?", false)?,
            "cancelled: pick tcp for a full tunnel"
        );
    }
    Ok(picked)
}

fn ask_socks(flags: &ClientFlags, mode: Mode) -> Result<Option<String>> {
    if flags.no_socks {
        return Ok(None);
    }
    if let Some(s) = flags.socks.clone() {
        return Ok(Some(s));
    }
    // A full tunnel already carries everything, so a proxy alongside it is the exception.
    if mode.is_full_tunnel() && !wizard::confirm("Also expose a local SOCKS5 proxy?", false)? {
        return Ok(None);
    }
    let addr = wizard::text("Local SOCKS5 listen address", Some(cli::DEFAULT_SOCKS))?;
    if let Some(err) = port_unavailable(&addr) {
        crate::ui::warn(&format!("{addr} is not bindable right now: {err}"));
        crate::ui::hint("something else may already be listening there");
    }
    Ok(Some(addr))
}

/// Report why `addr` cannot be bound, so a busy port is caught at the prompt rather than
/// after the wizard has finished and the tunnel is already dialling.
fn port_unavailable(addr: &str) -> Option<String> {
    match std::net::TcpListener::bind(addr) {
        Ok(l) => {
            drop(l);
            None
        }
        Err(e) => Some(e.to_string()),
    }
}

fn ask_tunnel_options(
    flags: &ClientFlags,
    mode: Mode,
    total: u8,
) -> Result<(u16, String, String, bool, String)> {
    let asks = flags.mtu.is_none()
        || flags.tun_name.is_none()
        || flags.dns.is_none()
        || !flags.ipv6
        || (mode == Mode::Vpn && flags.socket.is_none());
    wizard::step(3, total, "Tunnel", asks);

    let dns = match flags.dns.clone() {
        Some(d) => d,
        None => wizard::text(
            "DNS resolver to force through the tunnel",
            Some(cli::DEFAULT_DNS),
        )?,
    };
    let ipv6 = flags.ipv6
        || wizard::confirm(
            "Carry IPv6 as well? Only if the server has working outbound IPv6",
            false,
        )?;
    let (mtu, tun_name, socket) =
        if flags.mtu.is_some() || flags.tun_name.is_some() || flags.socket.is_some() {
            (
                flags.mtu.unwrap_or(cli::DEFAULT_MTU),
                flags
                    .tun_name
                    .clone()
                    .unwrap_or_else(|| cli::DEFAULT_TUN_NAME.to_string()),
                flags
                    .socket
                    .clone()
                    .unwrap_or_else(|| cli::DEFAULT_HELPER_SOCKET.to_string()),
            )
        } else if wizard::confirm("Set advanced options (MTU, interface name)?", false)? {
            let mtu = wizard::port("TUN MTU", cli::DEFAULT_MTU)?;
            let name = wizard::text("TUN interface name", Some(cli::DEFAULT_TUN_NAME))?;
            let socket = if mode == Mode::Vpn {
                wizard::text("Helper control socket", Some(cli::DEFAULT_HELPER_SOCKET))?
            } else {
                cli::DEFAULT_HELPER_SOCKET.to_string()
            };
            (mtu, name, socket)
        } else {
            (
                cli::DEFAULT_MTU,
                cli::DEFAULT_TUN_NAME.to_string(),
                cli::DEFAULT_HELPER_SOCKET.to_string(),
            )
        };
    Ok((mtu, tun_name, dns, ipv6, socket))
}

fn review(plan: &ClientPlan, mode: Mode) {
    let f = |k: &str, v: &str| crate::ui::eline(&crate::ui::field(k, &crate::ui::value(v)));
    f("mode", mode.subcommand());
    f(
        "server",
        &leshiy_reality::config::RealityUri::parse(plan.uri.trim())
            .map(|p| p.server_addr.clone())
            .unwrap_or_else(|_| "(unparsed)".into()),
    );
    f(
        "credential",
        match &plan.source {
            UriSource::Direct => "given on the command line",
            UriSource::File(p) => p,
            UriSource::Vault => "from the provisioning vault",
        },
    );
    f("transport", plan.transport.as_flag());
    f("socks", plan.socks.as_deref().unwrap_or("none"));
    if mode.is_full_tunnel() {
        f("dns", &plan.dns);
        f("ipv6", if plan.ipv6 { "yes" } else { "no" });
        f("mtu", &plan.mtu.to_string());
        f("interface", &plan.tun_name);
        if mode == Mode::Vpn {
            f("helper", &plan.socket);
        }
    }
    crate::ui::eline("");
    crate::ui::eline(&crate::ui::label("Same run, without the wizard:"));
    crate::ui::eline(&format!("  {}", equivalent_command(plan, mode)));
    if matches!(plan.source, UriSource::Direct | UriSource::Vault) {
        crate::ui::hint(
            "the URI is a bearer credential, so it is not printed above. Keep it in a \
             0600 file and use --uri-file to stay out of shell history and `ps`.",
        );
    }
    crate::ui::eline("");
}

/// The non-interactive invocation equivalent to `plan`.
///
/// The URI is never rendered. A file-sourced credential echoes `--uri-file <path>`, which
/// is both runnable and safe; anything else echoes a placeholder, because putting a bearer
/// credential in argv exposes it to every other user on the box via `ps`.
pub fn equivalent_command(plan: &ClientPlan, mode: Mode) -> String {
    let uri_file = match &plan.source {
        UriSource::File(path) => Some(path.as_str()),
        _ => None,
    };
    build_command(plan, mode, uri_file).render(78)
}

/// The argv for the sudo re-exec of an interactively planned full tunnel.
///
/// `cred` is a 0600 file holding the URI: the elevated child must not receive the
/// credential in argv, where `ps` would expose it to every local user.
pub fn elevated_args(plan: &ClientPlan, mode: Mode, cred: &std::path::Path) -> Vec<String> {
    build_command(plan, mode, Some(&cred.to_string_lossy()))
        .args()
        .to_vec()
}

/// A 0600 file handing the URI to an elevated re-exec, deleted when this value drops.
///
/// The window in which it exists is bounded by the child process; `read_credential` on the
/// far side still refuses it if the mode or symlink status is ever wrong.
pub struct CredentialHandoff {
    path: std::path::PathBuf,
}

impl CredentialHandoff {
    pub fn new(uri: &str) -> Result<Self> {
        Self::new_in(&crate::service::config_home()?.join("leshiy"), uri)
    }

    /// Directory injected rather than read from the environment: `XDG_CONFIG_HOME` is
    /// process-global and other tests resolve paths through it in parallel.
    fn new_in(dir: &std::path::Path, uri: &str) -> Result<Self> {
        let path = dir.join(format!(".handoff-{}.uri", std::process::id()));
        crate::service::write_credential(&path, uri)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for CredentialHandoff {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn build_command(plan: &ClientPlan, mode: Mode, uri_file: Option<&str>) -> wizard::CommandLine {
    const URI_PLACEHOLDER: &str = "<your leshiy:// URI>";
    let mut c = wizard::CommandLine::new("leshiy");
    // `connect` has no --uri-file; its long form `client` does, so a file-backed
    // credential is shown in the form that can actually accept it.
    let subcommand = match (mode, uri_file) {
        (Mode::Connect, Some(_)) => "client",
        _ => mode.subcommand(),
    };
    for word in subcommand.split_whitespace() {
        c.arg(word);
    }
    match uri_file {
        Some(path) => c.opt("--uri-file", Some(path)),
        None if mode == Mode::Connect => c.arg(URI_PLACEHOLDER),
        None => c.opt("--uri", Some(URI_PLACEHOLDER)),
    };
    if plan.transport != mode.default_transport() {
        c.opt("--transport", Some(plan.transport.as_flag()));
    }
    match (&plan.socks, mode) {
        (None, Mode::Tun) => {}
        (None, Mode::Service { tun: true }) => {
            c.flag("--no-socks", true);
        }
        (None, _) => {}
        (Some(s), _) if s != cli::DEFAULT_SOCKS || mode == Mode::Tun => {
            c.opt("--socks", Some(s.as_str()));
        }
        (Some(_), _) => {}
    }
    if matches!(mode, Mode::Service { tun: true }) {
        c.flag("--tun", true);
    }
    if mode.is_full_tunnel() {
        if plan.dns != cli::DEFAULT_DNS {
            c.opt("--dns", Some(plan.dns.as_str()));
        }
        if plan.mtu != cli::DEFAULT_MTU {
            c.opt("--mtu", Some(&plan.mtu.to_string()));
        }
        if plan.tun_name != cli::DEFAULT_TUN_NAME {
            c.opt("--tun-name", Some(plan.tun_name.as_str()));
        }
        c.flag("--ipv6", plan.ipv6);
        if mode == Mode::Vpn && plan.socket != cli::DEFAULT_HELPER_SOCKET {
            c.opt("--socket", Some(plan.socket.as_str()));
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use leshiy_provision::vault::{ClientConfig, ServerRecord, SshSecret, Vault};

    const URI: &str = "leshiy://abc@1.2.3.4:443?sni=www.microsoft.com&sid=0102030400000000";

    fn plan(mode: Mode) -> ClientPlan {
        plan_from_flags(
            ClientFlags {
                uri: Some(URI.into()),
                ..Default::default()
            },
            mode,
        )
        .unwrap()
    }

    /// The credential must never reach argv, where `ps` exposes it to every local user —
    /// the same invariant `service.rs` enforces for the generated unit.
    #[test]
    fn equivalent_command_never_renders_the_uri() {
        for mode in [
            Mode::Proxy,
            Mode::Connect,
            Mode::Tun,
            Mode::Vpn,
            Mode::Service { tun: false },
            Mode::Service { tun: true },
        ] {
            let out = equivalent_command(&plan(mode), mode);
            assert!(!out.contains("abc"), "{mode:?} leaked the pubkey: {out}");
            assert!(
                !out.contains("0102030400000000"),
                "{mode:?} leaked the sid: {out}"
            );
            assert!(
                !out.contains("1.2.3.4"),
                "{mode:?} leaked the server: {out}"
            );
        }
    }

    /// A file-sourced credential is the one case the echoed command can be run verbatim,
    /// because a path is not a secret.
    #[test]
    fn a_file_sourced_credential_echoes_a_runnable_command() {
        let mut p = plan(Mode::Tun);
        p.source = UriSource::File("/etc/leshiy/uri".into());
        let out = equivalent_command(&p, Mode::Tun);
        assert!(out.contains("--uri-file /etc/leshiy/uri"), "got: {out}");
        assert!(
            !out.contains("<your"),
            "should not use a placeholder: {out}"
        );
    }

    #[test]
    fn connect_echoes_the_uri_positionally_not_as_a_flag() {
        let out = equivalent_command(&plan(Mode::Connect), Mode::Connect);
        assert!(out.starts_with("leshiy connect "), "got: {out}");
        assert!(
            !out.contains("--uri "),
            "connect takes it positionally: {out}"
        );
    }

    #[test]
    fn equivalent_command_omits_values_that_are_already_the_default() {
        assert_eq!(
            equivalent_command(&plan(Mode::Proxy), Mode::Proxy),
            "leshiy client --uri '<your leshiy:// URI>'"
        );
        // tun defaults to tcp, so an explicit tcp is not worth echoing.
        assert_eq!(
            equivalent_command(&plan(Mode::Tun), Mode::Tun),
            "leshiy tun --uri '<your leshiy:// URI>'"
        );
    }

    #[test]
    fn equivalent_command_includes_every_non_default_choice() {
        let mut p = plan(Mode::Vpn);
        p.transport = Transport::Quic;
        p.socks = Some("127.0.0.1:9999".into());
        p.dns = "9.9.9.9".into();
        p.mtu = 1200;
        p.tun_name = "leshiy9".into();
        p.ipv6 = true;
        p.socket = "/tmp/h.sock".into();
        let flat = equivalent_command(&p, Mode::Vpn)
            .replace(" \\\n    ", " ")
            .replace(" \\\n", " ");
        for expected in [
            "leshiy vpn",
            "--transport quic",
            "--socks 127.0.0.1:9999",
            "--dns 9.9.9.9",
            "--mtu 1200",
            "--tun-name leshiy9",
            "--ipv6",
            "--socket /tmp/h.sock",
        ] {
            assert!(flat.contains(expected), "missing {expected} in: {flat}");
        }
    }

    /// `--no-socks` only exists on `service start`; `tun` expresses the same thing by
    /// simply omitting `--socks`, and emitting the flag there would fail to parse.
    #[test]
    fn no_socks_is_only_emitted_where_the_flag_exists() {
        let mut p = plan(Mode::Tun);
        p.socks = None;
        assert!(!equivalent_command(&p, Mode::Tun).contains("--no-socks"));

        let svc = Mode::Service { tun: true };
        let mut p = plan(svc);
        p.socks = None;
        let out = equivalent_command(&p, svc);
        assert!(out.contains("--no-socks"), "got: {out}");
        assert!(out.contains("--tun"), "got: {out}");
    }

    fn caps(privileged: bool, helper: bool, systemd: bool) -> Capabilities {
        Capabilities {
            privileged,
            helper,
            systemd,
        }
    }

    /// The router must reach every way of connecting; a mode missing from the menu is one
    /// an operator can only find by already knowing the subcommand.
    #[test]
    fn the_menu_offers_every_client_mode() {
        let menu = mode_menu(&caps(false, true, true));
        let modes: Vec<Mode> = menu.iter().map(|e| e.mode).collect();
        assert_eq!(
            modes,
            vec![
                Mode::Connect,
                Mode::Tun,
                Mode::Vpn,
                Mode::Service { tun: false },
                Mode::Service { tun: true },
            ]
        );
        assert!(
            menu.iter().all(|e| e.blocked.is_none()),
            "all available here"
        );
    }

    /// Absent dependencies must block the mode, not hide it: the reason is the useful part.
    #[test]
    fn missing_dependencies_block_only_the_modes_that_need_them() {
        let menu = mode_menu(&caps(false, false, false));
        let blocked = |m: Mode| menu.iter().find(|e| e.mode == m).unwrap().blocked.is_some();
        assert!(!blocked(Mode::Connect), "a proxy needs nothing");
        assert!(
            !blocked(Mode::Tun),
            "tun elevates on demand, so it stays offered"
        );
        assert!(blocked(Mode::Vpn), "no helper socket");
        assert!(blocked(Mode::Service { tun: false }), "no systemd");
        assert!(blocked(Mode::Service { tun: true }), "no systemd");
        // Still listed, so the operator sees why rather than wondering where it went.
        assert_eq!(menu.len(), 5);
    }

    #[test]
    fn only_the_helper_mode_depends_on_the_helper_socket() {
        let menu = mode_menu(&caps(false, true, false));
        let vpn = menu.iter().find(|e| e.mode == Mode::Vpn).unwrap();
        assert!(vpn.blocked.is_none(), "helper present, so it is offered");
    }

    /// The sudo note is the difference between "this will just work" and "this is about to
    /// ask for your password", which is worth knowing before choosing.
    #[test]
    fn the_tun_note_reflects_whether_elevation_is_still_needed() {
        let unpriv = mode_menu(&caps(false, false, false));
        let priv_ = mode_menu(&caps(true, false, false));
        let note = |m: &[ModeEntry]| m.iter().find(|e| e.mode == Mode::Tun).unwrap().note;
        assert!(note(&unpriv).contains("sudo"), "got: {}", note(&unpriv));
        assert!(!note(&priv_).contains("sudo"), "got: {}", note(&priv_));
    }

    #[test]
    fn a_blocked_entry_renders_its_reason_instead_of_its_note() {
        let menu = mode_menu(&caps(false, false, true));
        let vpn = menu.iter().find(|e| e.mode == Mode::Vpn).unwrap();
        let rendered = render_mode_entry(vpn);
        assert!(rendered.contains("unavailable"), "got: {rendered}");
        assert!(rendered.contains("leshiy-helper"), "got: {rendered}");

        let proxy = menu.iter().find(|e| e.mode == Mode::Connect).unwrap();
        let rendered = render_mode_entry(proxy);
        assert!(!rendered.contains("unavailable"), "got: {rendered}");
        assert!(rendered.contains("127.0.0.1:1080"), "got: {rendered}");
    }

    /// The cursor must land on something selectable, or the obvious Enter press fails.
    #[test]
    fn the_default_selection_is_never_a_blocked_entry() {
        for c in [
            caps(false, false, false),
            caps(true, true, true),
            caps(false, true, false),
        ] {
            let menu = mode_menu(&c);
            let default = menu.iter().position(|e| e.blocked.is_none()).unwrap_or(0);
            assert!(menu[default].blocked.is_none(), "default must be runnable");
        }
    }

    /// A full tunnel that silently ran on QUIC would serve TCP while dropping DNS and
    /// ping, so tcp has to be the default everywhere the whole device is routed.
    #[test]
    fn full_tunnel_modes_default_to_tcp_and_proxy_modes_to_auto() {
        for mode in [Mode::Tun, Mode::Vpn, Mode::Service { tun: true }] {
            assert!(mode.is_full_tunnel(), "{mode:?} should be a full tunnel");
            assert_eq!(mode.default_transport(), Transport::Tcp, "{mode:?}");
        }
        for mode in [Mode::Proxy, Mode::Connect, Mode::Service { tun: false }] {
            assert!(
                !mode.is_full_tunnel(),
                "{mode:?} should not be a full tunnel"
            );
            assert_eq!(mode.default_transport(), Transport::Auto, "{mode:?}");
        }
    }

    /// `tun` is the one mode that listens nowhere unless asked: the device is already
    /// routed, so a proxy is redundant.
    #[test]
    fn socks_defaults_differ_between_tun_and_the_proxy_modes() {
        assert_eq!(plan(Mode::Tun).socks, None);
        assert_eq!(plan(Mode::Proxy).socks.as_deref(), Some(cli::DEFAULT_SOCKS));
        assert_eq!(
            plan(Mode::Connect).socks.as_deref(),
            Some(cli::DEFAULT_SOCKS)
        );
        assert_eq!(
            plan(Mode::Service { tun: false }).socks.as_deref(),
            Some(cli::DEFAULT_SOCKS)
        );
    }

    #[test]
    fn no_socks_beats_an_explicit_socks_address() {
        let p = plan_from_flags(
            ClientFlags {
                uri: Some(URI.into()),
                socks: Some("127.0.0.1:1080".into()),
                no_socks: true,
                ..Default::default()
            },
            Mode::Service { tun: true },
        )
        .unwrap();
        assert_eq!(p.socks, None);
    }

    #[test]
    fn plan_from_flags_applies_the_documented_tunnel_defaults() {
        let p = plan(Mode::Vpn);
        assert_eq!(p.mtu, cli::DEFAULT_MTU);
        assert_eq!(p.tun_name, cli::DEFAULT_TUN_NAME);
        assert_eq!(p.dns, cli::DEFAULT_DNS);
        assert_eq!(p.socket, cli::DEFAULT_HELPER_SOCKET);
        assert!(!p.ipv6);
    }

    /// The argv handed to the elevated child. It must name the subcommand, carry the
    /// credential only as a file path, and be free of `-i` — an elevated re-run of the
    /// wizard would prompt again, as root, after the sudo password was already accepted.
    #[test]
    fn elevated_args_pass_the_credential_by_file_and_drop_the_wizard_flag() {
        let mut p = plan(Mode::Tun);
        p.source = UriSource::Vault;
        p.ipv6 = true;
        let args = elevated_args(&p, Mode::Tun, std::path::Path::new("/run/u/handoff.uri"));

        assert_eq!(args[0], "tun", "the subcommand must lead: {args:?}");
        let joined = args.join(" ");
        assert!(joined.contains("--uri-file /run/u/handoff.uri"), "{joined}");
        assert!(
            !joined.contains("--uri "),
            "the URI must not be in argv: {joined}"
        );
        assert!(!joined.contains("abc"), "leaked the pubkey: {joined}");
        // Per argument, not as a substring: `--ipv6` legitimately contains "-i".
        assert!(
            !args.iter().any(|a| a == "-i" || a == "--interactive"),
            "the wizard flag must not survive: {args:?}"
        );
        assert!(joined.contains("--ipv6"), "choices must survive: {joined}");
    }

    /// `service start --tun` elevates through the same path, so it must carry its own
    /// subcommand pair rather than `tun`'s.
    #[test]
    fn elevated_args_for_the_service_keep_both_subcommand_words() {
        let mode = Mode::Service { tun: true };
        let args = elevated_args(&plan(mode), mode, std::path::Path::new("/c.uri"));
        assert_eq!(&args[..2], &["service", "start"], "got: {args:?}");
        assert!(args.contains(&"--tun".to_string()), "got: {args:?}");
    }

    /// The handoff file is the only thing standing between a vault-sourced credential and
    /// every other local user, so its mode matters as much as its contents.
    #[test]
    fn credential_handoff_is_0600_and_disappears_when_dropped() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("leshiy-cw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let path = {
            let h = CredentialHandoff::new_in(&dir, URI).expect("write handoff");
            let path = h.path().to_path_buf();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "a bearer credential must not be group/world readable"
            );
            // `read_credential` is the far side of the handoff; it must accept what we wrote.
            assert_eq!(crate::service::read_credential(&path).unwrap(), URI);
            path
        };
        assert!(!path.exists(), "the handoff must not outlive the re-exec");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The message has to name flags the command actually has: `connect` takes its URI
    /// positionally and `vpn` has no --uri-file, so the generic wording misdirects there.
    #[test]
    fn plan_from_flags_demands_a_uri_and_points_at_the_escape_hatch() {
        let msg = |mode| {
            plan_from_flags(ClientFlags::default(), mode)
                .err()
                .unwrap()
                .to_string()
        };
        for mode in [Mode::Proxy, Mode::Tun, Mode::Service { tun: false }] {
            let e = msg(mode);
            assert!(e.contains("--uri or --uri-file"), "{mode:?}: {e}");
            assert!(e.contains("-i"), "{mode:?}: {e}");
        }
        let e = msg(Mode::Connect);
        assert!(e.contains("provide the leshiy:// URI"), "got: {e}");
        assert!(!e.contains("--uri-file"), "connect has no such flag: {e}");

        let e = msg(Mode::Vpn);
        assert!(!e.contains("--uri-file"), "vpn has no such flag: {e}");
    }

    #[test]
    fn plan_from_flags_rejects_both_uri_forms_at_once() {
        let e = plan_from_flags(
            ClientFlags {
                uri: Some(URI.into()),
                uri_file: Some("/f".into()),
                ..Default::default()
            },
            Mode::Proxy,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("mutually exclusive"), "got: {e}");
    }

    fn vault_with(server: &str, clients: &[&str]) -> Vault {
        let mut v = Vault::new();
        v.upsert(ServerRecord {
            id: format!("{server}-22"),
            label: server.into(),
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
            clients: clients
                .iter()
                .enumerate()
                .map(|(i, l)| ClientConfig {
                    short_id: format!("{i:016x}"),
                    label: (*l).into(),
                    uri: format!("leshiy://k@1.2.3.4:443?sid={i:016x}"),
                })
                .collect(),
            created_at: 0,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
            sudo: false,
        });
        v
    }

    /// One row per issued client, not per server: a server with three users offers three
    /// distinct credentials to connect with.
    #[test]
    fn vault_rows_flatten_every_client_of_every_server() {
        let v = vault_with("paris", &["laptop", "phone"]);
        let rows = vault_client_rows(&v);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].0.contains("paris") && rows[0].0.contains("laptop"));
        assert!(rows[1].0.contains("phone"));
        assert_ne!(rows[0].1, rows[1].1, "each row must carry its own URI");
        assert!(rows[0].1.starts_with("leshiy://"));
    }

    #[test]
    fn vault_rows_are_empty_when_no_client_was_ever_issued() {
        assert!(vault_client_rows(&vault_with("paris", &[])).is_empty());
        assert!(vault_client_rows(&Vault::new()).is_empty());
    }

    /// Binding a port the wizard just released must succeed, and a port genuinely in use
    /// must be reported — this is what warns the operator before the tunnel dials.
    #[test]
    fn port_availability_check_detects_a_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        assert!(
            port_unavailable(&addr).is_some(),
            "a held port must report unavailable"
        );
        drop(l);
        assert!(
            port_unavailable("127.0.0.1:0").is_none(),
            "an ephemeral port must be bindable"
        );
    }
}
