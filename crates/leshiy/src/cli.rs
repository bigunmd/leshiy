//! CLI subcommand definitions via clap derive.
use clap::{Parser, Subcommand, ValueEnum};

/// Shown after `leshiy tun --help`. Elevation is automatic, so the only thing left to warn
/// about is the shortcut users reach for when they want it to stop asking for a password.
const SUDO_PATH_HELP: &str = "\
VPN mode needs root. Run it normally — it re-executes itself through sudo using its own\n\
absolute path, so no symlink or PATH change is required.\n\
\n\
If you want it passwordless, scope the sudoers rule to a root-owned path such as\n\
/usr/local/bin/leshiy. Never point a NOPASSWD rule at a user-writable location like\n\
~/.local/bin, and never add such a directory to sudoers secure_path: anything able to\n\
write there could then replace the binary and obtain root.";

/// Shown after `leshiy service start --help`. A tunnel inside WSL only ever covers WSL's
/// own traffic, which surprises people who expect their Windows browser to follow.
const WSL_SERVICE_HELP: &str = "\
Note for WSL2: a tunnel started inside WSL carries only WSL's own traffic. Windows\n\
applications keep using the Windows network stack and are unaffected, whether you use\n\
proxy mode or --tun.";

#[derive(Parser)]
#[command(
    name = "leshiy",
    version,
    about = "Leshiy REALITY-style stealth tunnel"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
    /// Set on the sudo re-exec so the elevated process never elevates again.
    ///
    /// Global, because `ensure_root` appends it to whatever argv it re-runs: any
    /// subcommand that can elevate must accept it, or the elevated process dies on an
    /// "unexpected argument" from clap. An argv flag rather than an env var, since sudo's
    /// default `env_reset` would drop the latter.
    #[arg(long = "already-elevated", hide = true, global = true)]
    pub already_elevated: bool,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Print a fresh x25519 keypair (base64url).
    Keygen,
    /// Generate a REALITY server key + config + print the client leshiy:// URI.
    ServerInit {
        /// Public host:port clients dial (goes in the URI).
        #[arg(long)]
        host: String,
        /// Borrowed TLS site to camouflage as, host:port (the dest).
        #[arg(long)]
        dest: String,
        /// Bind address (default: 0.0.0.0:<host's port>).
        #[arg(long)]
        listen: Option<String>,
        #[arg(long, default_value = "leshiy-server.toml")]
        out: String,
        /// QUIC listen address (e.g. 0.0.0.0:8443). When set, generates a self-signed QUIC cert
        /// and pins its fingerprint in the URI.
        #[arg(long)]
        quic_listen: Option<String>,
        /// SNI domain for the QUIC TLS cert / endpoint (default: cdn.example.com).
        #[arg(long)]
        quic_domain: Option<String>,
        /// Path to an existing QUIC TLS certificate PEM (skips self-signed generation).
        #[arg(long)]
        quic_cert: Option<String>,
        /// Path to an existing QUIC TLS private key PEM (skips self-signed generation).
        #[arg(long)]
        quic_key: Option<String>,
        /// Exit-node `leshiy://` URI.  When set, the server becomes a connector (Entry)
        /// that forwards traffic to the specified Exit node over QUIC.
        /// The URI must include a `quic=` endpoint (e.g. `quic=host:port&qsni=…`).
        #[arg(long)]
        connector: Option<String>,
    },
    /// Run the REALITY server from a config file.
    Server {
        #[arg(long, default_value = "leshiy-server.toml")]
        config: String,
    },
    /// Run a local SOCKS5 proxy tunneling to the REALITY server URI.
    Client {
        #[arg(long, conflicts_with = "uri_file")]
        uri: Option<String>,
        /// Read the `leshiy://` URI from a 0600 file instead of the command line, so the
        /// credential is not exposed in `ps` output. Used by the generated systemd unit.
        #[arg(long)]
        uri_file: Option<String>,
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks: String,
        /// Transport to use: auto (default: prefer QUIC, fall back to REALITY/TCP), quic, or tcp.
        #[arg(long, default_value = "auto")]
        transport: Transport,
    },
    /// Connect a client: shorthand for `client` with friendly defaults (local SOCKS5 on
    /// 127.0.0.1:1080, transport auto). Just pass the leshiy:// URI your server printed.
    Connect {
        /// The leshiy:// share URI from your server.
        uri: String,
        /// Local SOCKS5 listen address.
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks: String,
        /// Transport: auto (default, prefer QUIC), quic, or tcp.
        #[arg(long, default_value = "auto")]
        transport: Transport,
    },
    /// Run as a full-tunnel VPN via a TUN device (all traffic). Requires root / CAP_NET_ADMIN.
    #[command(after_help = SUDO_PATH_HELP)]
    Tun {
        /// The leshiy:// server URI.
        #[arg(long, conflicts_with = "uri_file")]
        uri: Option<String>,
        /// Read the `leshiy://` URI from a 0600 file instead of the command line, keeping
        /// the credential out of `ps`. Used by the generated systemd unit.
        #[arg(long)]
        uri_file: Option<String>,
        /// Transport: tcp (REALITY — required for UDP today, the default), quic, or auto.
        #[arg(long, default_value = "tcp")]
        transport: Transport,
        /// TUN MTU (kept below the transport's to absorb TLS + mux framing).
        #[arg(long, default_value_t = 1400)]
        mtu: u16,
        /// TUN interface name.
        #[arg(long, default_value = "leshiy0")]
        tun_name: String,
        /// DNS resolver forced through the tunnel.
        #[arg(long, default_value = "1.1.1.1")]
        dns: String,
        /// Carry IPv6 through the tunnel (dual-stack). Off by default: only enable when the
        /// server has working outbound IPv6, else v6-preferred traffic blackholes.
        #[arg(long)]
        ipv6: bool,
        /// Also run a local SOCKS5 proxy on this address, sharing the same tunnel.
        ///
        /// For apps that need an explicit proxy endpoint while the whole device is already
        /// tunneled. Loopback only. TCP CONNECT only — UDP needs no proxy here, because
        /// the full tunnel already carries it.
        #[arg(long)]
        socks: Option<String>,
    },
    /// Run a full-tunnel VPN via the privileged `leshiy-helper` daemon (this process
    /// stays unprivileged). Requires `leshiy-helper` to be installed + running.
    Vpn {
        /// The leshiy:// server URI.
        #[arg(long)]
        uri: String,
        /// Transport: tcp (REALITY — required for UDP today, the default), quic, or auto.
        #[arg(long, default_value = "tcp")]
        transport: Transport,
        /// TUN MTU.
        #[arg(long, default_value_t = 1400)]
        mtu: u16,
        /// TUN interface name.
        #[arg(long, default_value = "leshiy0")]
        tun_name: String,
        /// DNS resolver forced through the tunnel.
        #[arg(long, default_value = "1.1.1.1")]
        dns: String,
        /// Path to the helper's control socket.
        #[arg(long, default_value = "/run/leshiy/helper.sock")]
        socket: String,
        /// Carry IPv6 through the tunnel (dual-stack). Off by default: only enable when the
        /// server has working outbound IPv6, else v6-preferred traffic blackholes.
        #[arg(long)]
        ipv6: bool,
    },
    /// Interactive (or flag-driven) single-server setup: probe dest, init, print URI + QR.
    Quickstart {
        /// Public host:port clients dial.
        #[arg(long)]
        host: String,
        /// Borrowed TLS site to camouflage as, host:port.
        #[arg(long)]
        dest: String,
        /// Output config path.
        #[arg(long, default_value = "leshiy-server.toml")]
        out: String,
        /// Bind address (default 0.0.0.0:<host port>).
        #[arg(long)]
        listen: Option<String>,
        /// Enable QUIC by listening on this addr (e.g. 0.0.0.0:443).
        #[arg(long)]
        quic_listen: Option<String>,
        /// SNI advertised on the QUIC endpoint (qsni= in the URI + the self-signed cert
        /// domain). Defaults to the --dest hostname when unset.
        #[arg(long)]
        quic_sni: Option<String>,
        /// Skip the live TLS1.3 dest probe (for tests / offline).
        #[arg(long)]
        no_probe: bool,
        /// Emit one machine-readable JSON summary line on stdout (for install.sh).
        #[arg(long)]
        summary_json: bool,
        /// Connector role: single (default), entry, or exit.
        #[arg(long, default_value = "single")]
        role: Role,
        /// Exit node's `leshiy://` URI (the connector credential) — required for --role entry.
        #[arg(long)]
        exit_uri: Option<String>,
    },
    /// Show service + config status for an installed server.
    Status {
        #[arg(long, default_value = "leshiy-server.toml")]
        config: String,
    },
    /// Stop and remove the installed server (keeps config unless --purge).
    Uninstall {
        #[arg(long, default_value = "leshiy-server.toml")]
        config: String,
        /// Also delete the config directory (identity, user DB). Irreversible.
        #[arg(long)]
        purge: bool,
    },
    /// Manage users on a running leshiy server via its control socket.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Download + verify the latest (or --version) release binary and restart the service.
    ///
    /// This is the *server* path: it replaces /usr/local/bin/leshiy and restarts the
    /// `leshiy` systemd unit. To update the client you are running, use `leshiy update`.
    Upgrade {
        /// GitHub repo to pull from.
        #[arg(long, default_value = "bigunmd/leshiy")]
        repo: String,
        /// Release tag to install (e.g. v0.2.0). Defaults to the latest release.
        #[arg(long)]
        version: Option<String>,
    },
    /// Update this client: verify the release signature and replace the running binary.
    ///
    /// Works for a user-local install (`~/.local/bin/leshiy`) without root. The swap is an
    /// atomic rename, so the running process keeps the old build until it is restarted.
    /// Requires `minisign` on PATH, the same as the client installer.
    Update {
        /// GitHub repo to pull from.
        #[arg(long, default_value = "bigunmd/leshiy")]
        repo: String,
        /// Release tag to install (e.g. v1.11.3). Defaults to the latest release.
        #[arg(long)]
        version: Option<String>,
        /// Install an older release than the one running. Refused by default: a valid
        /// signature cannot distinguish a legitimate rollback from a forced downgrade.
        #[arg(long)]
        force: bool,
    },
    /// Provision and manage remote leshiy servers.
    Remote {
        #[command(subcommand)]
        cmd: RemoteCmd,
    },
    /// Run the client in the background as a systemd service that survives logout.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Container entrypoint: build config from LESHIY_* env vars on first boot, then run.
    Boot,
}

#[derive(Subcommand)]
pub enum ServiceCmd {
    /// Connect, verify the tunnel actually works, then hand it to systemd and report how
    /// to check or stop it. Proxy mode installs a user unit (no root); `--tun` installs a
    /// system unit, since a full tunnel must change routes and DNS.
    #[command(after_help = WSL_SERVICE_HELP)]
    Start {
        /// The leshiy:// server URI.
        #[arg(long, conflicts_with = "uri_file")]
        uri: Option<String>,
        /// Read the URI from a 0600 file instead.
        #[arg(long)]
        uri_file: Option<String>,
        /// Transport. Defaults to `auto` for proxy mode and `tcp` for `--tun`, because a
        /// full tunnel needs UDP and ICMP, which only REALITY/TCP carries today.
        #[arg(long)]
        transport: Option<Transport>,
        /// Local SOCKS5 listen address. With --tun this adds a proxy alongside the tunnel.
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks: String,
        /// Run a full-device tunnel instead of only a local proxy. Needs root.
        #[arg(long)]
        tun: bool,
        /// TUN interface name (--tun only).
        #[arg(long, default_value = "leshiy0")]
        tun_name: String,
        /// DNS resolver forced through the tunnel (--tun only).
        #[arg(long, default_value = "1.1.1.1")]
        dns: String,
        /// TUN MTU (--tun only).
        #[arg(long, default_value_t = 1400)]
        mtu: u16,
        /// Carry IPv6 through the tunnel (--tun only).
        #[arg(long)]
        ipv6: bool,
        /// Do not expose a SOCKS5 proxy at all (--tun only): tunnel everything, listen
        /// nowhere.
        #[arg(long, conflicts_with = "socks")]
        no_socks: bool,
    },
    /// Stop the service and disable it at boot.
    Stop,
    /// Show whether the tunnel is running.
    Status,
    /// Show the service's log.
    Logs {
        /// Follow the log instead of printing the last lines.
        #[arg(short, long)]
        follow: bool,
    },
}

/// Connector role for `quickstart`.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Standalone server (default): clients connect, server egresses directly.
    Single,
    /// Censor-facing entry that forwards to an exit via `--exit-uri`.
    Entry,
    /// Clean-egress exit (requires QUIC); its share URI is the connector credential.
    Exit,
}

/// Transport selection for the client subcommand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    /// Prefer QUIC where the URI has a `quic=` endpoint and UDP is open; fall back
    /// to REALITY/TCP when QUIC is blocked or absent.
    Auto,
    /// Use QUIC/H3 transport (requires `quic=` in the URI).
    Quic,
    /// Use REALITY (TCP) transport.
    Tcp,
}

impl Transport {
    pub fn as_flag(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Quic => "quic",
            Self::Tcp => "tcp",
        }
    }

    /// Pick the transport a generated unit should run with.
    ///
    /// A full tunnel carries DNS (UDP) and ping (ICMP), and only REALITY/TCP carries both
    /// today — `QuicTunnel` doesn't implement `open_icmp` at all. So `auto` picking QUIC
    /// leaves TCP streams working while DNS and ping die inside the tunnel, which presents
    /// as a totally dead network on a service that reports itself healthy. `leshiy tun`
    /// already defaults to tcp for this reason; the unit must not silently differ.
    pub fn for_service(explicit: Option<Self>, tun: bool) -> Self {
        match (explicit, tun) {
            (Some(t), _) => t,
            (None, true) => Self::Tcp,
            (None, false) => Self::Auto,
        }
    }
}

/// Default server config path (same default as `server --config`).
pub const DEFAULT_CONFIG: &str = "leshiy-server.toml";

#[derive(Subcommand)]
pub enum UserCmd {
    /// Add a new user and print their leshiy:// URI.
    Add {
        /// SNI (server name) to embed in the URI.
        #[arg(long)]
        sni: Option<String>,
        /// Data cap, e.g. 10GB / 512MB / 1000000 (1000-based; bare = bytes).
        #[arg(long)]
        data_cap: Option<String>,
        /// Upload rate limit, e.g. 5Mbps / 500Kbps / 1MBps / 600KBps / bare bytes/s.
        #[arg(long)]
        rate_up: Option<String>,
        /// Download rate limit (same format as --rate-up).
        #[arg(long)]
        rate_down: Option<String>,
        /// Expiry: +30d / +12h / +45m relative to now, or a raw unix timestamp.
        #[arg(long)]
        expires: Option<String>,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
        /// Also render the URI as a scannable QR code.
        #[arg(long)]
        qr: bool,
    },
    /// List all users.
    List {
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
        /// Emit the raw users array as JSON (machine-readable) instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show details for a single user.
    Show {
        /// User short_id (16 hex chars).
        short_id: String,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Update limits for an existing user (replaces all limit fields).
    Update {
        /// User short_id (16 hex chars).
        short_id: String,
        /// New data cap (same format as `add --data-cap`).
        #[arg(long)]
        data_cap: Option<String>,
        /// New upload rate limit.
        #[arg(long)]
        rate_up: Option<String>,
        /// New download rate limit.
        #[arg(long)]
        rate_down: Option<String>,
        /// New expiry (same format as `add --expires`).
        #[arg(long)]
        expires: Option<String>,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Disable a user (blocks new and mid-session connections).
    Disable {
        /// User short_id (16 hex chars).
        short_id: String,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Re-enable a previously disabled user.
    Enable {
        /// User short_id (16 hex chars).
        short_id: String,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Reset usage counters to zero for a user.
    ResetUsage {
        /// User short_id (16 hex chars).
        short_id: String,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Remove a user permanently.
    Rm {
        /// User short_id (16 hex chars).
        short_id: String,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Print the leshiy:// URI for an existing user.
    Uri {
        /// User short_id (16 hex chars).
        short_id: String,
        /// SNI override for the URI.
        #[arg(long)]
        sni: Option<String>,
        /// Server config file — used to locate the control socket when --socket is not given.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Explicit path to the control socket (overrides --config-derived path).
        #[arg(long)]
        socket: Option<String>,
        /// Also render the URI as a scannable QR code.
        #[arg(long)]
        qr: bool,
    },
}

#[derive(clap::Subcommand)]
pub enum RemoteCmd {
    /// Provision a fresh VPS into a leshiy server over SSH.
    Provision {
        /// SSH target as user@host[:port].
        #[arg(long)]
        host: String,
        /// Path to a private key file (PEM). If omitted, you'll be prompted for a password.
        #[arg(long)]
        key: Option<String>,
        /// Read the SSH password from stdin (first line).
        #[arg(long)]
        password_stdin: bool,
        /// Read the private key's passphrase from stdin instead of prompting. Only
        /// meaningful with --key; ignored for an unencrypted key.
        #[arg(long, conflicts_with_all = ["password_stdin", "sudo_password_stdin"])]
        key_passphrase_stdin: bool,
        /// Connect as a non-root user and run privileged commands via sudo.
        /// Prompts for the sudo password unless --sudo-password-stdin is set.
        #[arg(long)]
        sudo: bool,
        /// Read the sudo password from stdin instead of prompting (implies --sudo).
        /// Cannot be combined with --password-stdin.
        #[arg(long, conflicts_with = "password_stdin")]
        sudo_password_stdin: bool,
        /// Borrowed TLS site for REALITY, host:port.
        #[arg(long)]
        dest: String,
        /// Override the container's DNS resolver (a bare IPv4/IPv6 literal). By
        /// default the host's IPv4 upstream is detected and a public IPv4 fallback
        /// is added; set this only for split-horizon/private-resolver hosts.
        #[arg(long)]
        dns: Option<String>,
        /// REALITY/TCP external listen port (default 443).
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Enable QUIC on this UDP port.
        #[arg(long)]
        quic: Option<u16>,
        /// Container image reference. Defaults to the release matching this CLI
        /// (`ghcr.io/bigunmd/leshiy:v<CLI version>`), the tag CI publishes.
        #[arg(long, default_value = concat!("ghcr.io/bigunmd/leshiy:v", env!("CARGO_PKG_VERSION")))]
        image: String,
        /// Friendly server label.
        #[arg(long)]
        label: Option<String>,
        /// Label for the first (self) client config.
        #[arg(long, default_value = "self")]
        user_label: String,
        /// Connector role: single (default), exit, middle, or entry.
        #[arg(long, default_value = "single")]
        role: String,
        /// For entry/middle: the saved downstream server (id or label) to forward to.
        #[arg(long)]
        downstream: Option<String>,
    },
    /// List saved servers.
    Ls,
    /// Manage users on a saved server.
    User {
        #[command(subcommand)]
        cmd: RemoteUserCmd,
    },
    /// Show whether a saved server is running.
    Status { server: String },
    /// Upgrade a saved server: pull a new image and recreate its container.
    ///
    /// Re-running `provision` does NOT do this — it reuses an already-running container by
    /// design, so it silently changes nothing. Users, keys and client URIs survive (they live on
    /// the data volume); only `teardown --purge` removes those.
    Upgrade {
        server: String,
        /// Image reference to upgrade to. Defaults to the release matching this CLI
        /// (`ghcr.io/bigunmd/leshiy:v<CLI version>`), the tag CI publishes.
        #[arg(long, default_value = concat!("ghcr.io/bigunmd/leshiy:v", env!("CARGO_PKG_VERSION")))]
        image: String,
        /// Resolve the newest published release instead of the tag matching this CLI.
        /// Conflicts with an explicit --image.
        #[arg(long, conflicts_with = "image")]
        latest: bool,
    },
    /// Export an encrypted backup of a saved server.
    Backup {
        server: String,
        #[arg(long)]
        connection_only: bool,
        #[arg(long)]
        out: String,
    },
    /// Import a server backup blob into the vault.
    Restore { file: String },
    /// Remove the server container; optionally purge its config.
    Teardown {
        server: String,
        #[arg(long)]
        purge: bool,
    },
}

#[derive(clap::Subcommand)]
pub enum RemoteUserCmd {
    /// Add a client and print its config (URI to stdout, QR to stderr).
    Add {
        server: String,
        #[arg(long, default_value = "client")]
        label: String,
    },
    /// List the users currently on the server (live).
    Ls { server: String },
    /// Delete a user on the server by short_id.
    Rm { server: String, short_id: String },
}

#[cfg(test)]
mod tests {
    /// The generated unit used to hardcode `auto`, which picks QUIC whenever the URI carries
    /// a `quic=` endpoint. QUIC declines `open_icmp` and did not carry DNS either, so the
    /// tunnel came up, reported healthy, served TCP over SOCKS -- and dropped every ping and
    /// DNS query inside the tunnel. Indistinguishable from a blackholed network.
    #[test]
    fn a_full_tunnel_defaults_to_tcp_because_only_reality_carries_udp_and_icmp() {
        use super::Transport;
        assert_eq!(Transport::for_service(None, true), Transport::Tcp);
        assert_eq!(Transport::for_service(None, false), Transport::Auto);
        // An explicit choice is still honored in both modes, warning or not.
        assert_eq!(
            Transport::for_service(Some(Transport::Quic), true),
            Transport::Quic
        );
        assert_eq!(
            Transport::for_service(Some(Transport::Tcp), false),
            Transport::Tcp
        );
    }

    use super::*;
    use clap::Parser;

    #[test]
    fn tun_parses_uri_and_defaults() {
        let cli = Cli::try_parse_from([
            "leshiy",
            "tun",
            "--uri",
            "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000",
        ])
        .expect("tun should parse");
        match cli.cmd {
            Cmd::Tun {
                uri,
                transport,
                mtu,
                tun_name,
                ipv6,
                ..
            } => {
                assert_eq!(
                    uri.as_deref(),
                    Some("leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000")
                );
                assert!(matches!(transport, Transport::Tcp));
                assert_eq!(mtu, 1400);
                assert_eq!(tun_name, "leshiy0");
                // Dual-stack is opt-in: absent `--ipv6` means IPv4-only.
                assert!(!ipv6);
            }
            _ => panic!("expected Tun"),
        }
    }

    #[test]
    fn tun_ipv6_flag_opts_into_dual_stack() {
        let cli = Cli::try_parse_from([
            "leshiy",
            "tun",
            "--uri",
            "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000",
            "--ipv6",
        ])
        .expect("tun --ipv6 should parse");
        match cli.cmd {
            Cmd::Tun { ipv6, .. } => assert!(ipv6),
            _ => panic!("expected Tun"),
        }
    }

    #[test]
    fn vpn_parses_uri_and_defaults() {
        let cli = Cli::try_parse_from([
            "leshiy",
            "vpn",
            "--uri",
            "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000",
        ])
        .expect("vpn should parse");
        match cli.cmd {
            Cmd::Vpn {
                uri,
                transport,
                mtu,
                tun_name,
                socket,
                ..
            } => {
                assert_eq!(uri, "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000");
                assert!(matches!(transport, Transport::Tcp));
                assert_eq!(mtu, 1400);
                assert_eq!(tun_name, "leshiy0");
                assert_eq!(socket, "/run/leshiy/helper.sock");
            }
            _ => panic!("expected Vpn"),
        }
    }

    /// `ensure_root` appends `--already-elevated` to whatever argv it re-runs, so every
    /// subcommand that can elevate must accept it. Shipping it on `tun` alone made
    /// `service start --tun` die on "unexpected argument" the moment it re-execed.
    #[test]
    fn every_elevating_subcommand_accepts_the_guard_flag() {
        let uri = "leshiy://abc@1.2.3.4:443?sni=x&sid=00";
        for argv in [
            vec!["leshiy", "tun", "--uri", uri, "--already-elevated"],
            vec![
                "leshiy",
                "service",
                "start",
                "--tun",
                "--uri",
                uri,
                "--already-elevated",
            ],
        ] {
            let cli = Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{argv:?} must parse, got: {e}"));
            assert!(cli.already_elevated, "{argv:?} lost the guard flag");
        }
    }

    /// The flag is global, so it must also parse before the subcommand.
    #[test]
    fn guard_flag_is_accepted_ahead_of_the_subcommand() {
        let cli = Cli::try_parse_from([
            "leshiy",
            "--already-elevated",
            "tun",
            "--uri",
            "leshiy://abc@1.2.3.4:443?sni=x&sid=00",
        ])
        .expect("global flag should parse before the subcommand");
        assert!(cli.already_elevated);
    }

    #[test]
    fn connect_takes_positional_uri_with_defaults() {
        let cli =
            Cli::try_parse_from(["leshiy", "connect", "leshiy://abc@1.2.3.4:443?sni=x&sid=00"])
                .expect("connect should parse");
        match cli.cmd {
            Cmd::Connect {
                uri,
                socks,
                transport,
            } => {
                assert_eq!(uri, "leshiy://abc@1.2.3.4:443?sni=x&sid=00");
                assert_eq!(socks, "127.0.0.1:1080");
                assert!(matches!(transport, Transport::Auto));
            }
            _ => panic!("expected Connect"),
        }
    }
}
