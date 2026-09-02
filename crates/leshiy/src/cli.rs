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
    ///
    /// Required without `-i`: --host and --dest. With `-i`, anything omitted is asked for.
    ServerInit {
        /// Public host:port clients dial (goes in the URI).
        #[arg(long)]
        host: Option<String>,
        /// Borrowed TLS site to camouflage as, host:port (the dest).
        #[arg(long)]
        dest: Option<String>,
        /// Ask for whatever was not passed as a flag, probing the camouflage site first.
        #[arg(short = 'i', long)]
        interactive: bool,
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
        /// Local SOCKS5 listen address [default: 127.0.0.1:1080].
        #[arg(long)]
        socks: Option<String>,
        /// Transport to use: auto (default: prefer QUIC, fall back to REALITY/TCP), quic, or tcp.
        #[arg(long)]
        transport: Option<Transport>,
        /// Ask for whatever was not passed as a flag, including which saved server to use.
        #[arg(short = 'i', long)]
        interactive: bool,
    },
    /// Connect a client: shorthand for `client` with friendly defaults (local SOCKS5 on
    /// 127.0.0.1:1080, transport auto). Just pass the leshiy:// URI your server printed.
    ///
    /// With `-i` the URI can be picked from the servers you provisioned instead of pasted.
    Connect {
        /// The leshiy:// share URI from your server.
        uri: Option<String>,
        /// Local SOCKS5 listen address [default: 127.0.0.1:1080].
        #[arg(long)]
        socks: Option<String>,
        /// Transport: auto (default, prefer QUIC), quic, or tcp.
        #[arg(long)]
        transport: Option<Transport>,
        /// Ask for whatever was not passed as a flag, including which saved server to use.
        #[arg(short = 'i', long)]
        interactive: bool,
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
        #[arg(long)]
        transport: Option<Transport>,
        /// TUN MTU (kept below the transport's to absorb TLS + mux framing) [default: 1400].
        #[arg(long)]
        mtu: Option<u16>,
        /// TUN interface name [default: leshiy0].
        #[arg(long)]
        tun_name: Option<String>,
        /// DNS resolver forced through the tunnel [default: 1.1.1.1].
        #[arg(long)]
        dns: Option<String>,
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
        /// Ask for whatever was not passed as a flag. Everything is resolved before the
        /// sudo prompt, so the elevated process runs without re-asking.
        #[arg(short = 'i', long)]
        interactive: bool,
    },
    /// Run a full-tunnel VPN via the privileged `leshiy-helper` daemon (this process
    /// stays unprivileged). Requires `leshiy-helper` to be installed + running.
    Vpn {
        /// The leshiy:// server URI.
        #[arg(long)]
        uri: Option<String>,
        /// Transport: tcp (REALITY — required for UDP today, the default), quic, or auto.
        #[arg(long)]
        transport: Option<Transport>,
        /// TUN MTU [default: 1400].
        #[arg(long)]
        mtu: Option<u16>,
        /// TUN interface name [default: leshiy0].
        #[arg(long)]
        tun_name: Option<String>,
        /// DNS resolver forced through the tunnel [default: 1.1.1.1].
        #[arg(long)]
        dns: Option<String>,
        /// Path to the helper's control socket [default: /run/leshiy/helper.sock].
        #[arg(long)]
        socket: Option<String>,
        /// Carry IPv6 through the tunnel (dual-stack). Off by default: only enable when the
        /// server has working outbound IPv6, else v6-preferred traffic blackholes.
        #[arg(long)]
        ipv6: bool,
        /// Ask for whatever was not passed as a flag.
        #[arg(short = 'i', long)]
        interactive: bool,
    },
    /// Interactive (`-i`) or flag-driven single-server setup: probe dest, init, print
    /// URI + QR.
    Quickstart {
        /// Public host:port clients dial.
        #[arg(long)]
        host: Option<String>,
        /// Borrowed TLS site to camouflage as, host:port.
        #[arg(long)]
        dest: Option<String>,
        /// Ask for whatever was not passed as a flag, detecting this host's public address
        /// and probing the camouflage site.
        #[arg(short = 'i', long, conflicts_with = "summary_json")]
        interactive: bool,
        /// Output config path [default: leshiy-server.toml].
        #[arg(long)]
        out: Option<String>,
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
        #[arg(long)]
        role: Option<Role>,
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
        /// Fill in whatever was not passed as a flag by asking for it, and pick saved
        /// servers from a list instead of typing their id.
        ///
        /// Flags always win: `remote provision -i --dest www.apple.com:443` asks for
        /// everything except the dest. Needs a terminal — in a script, pass flags.
        #[arg(short = 'i', long, global = true)]
        interactive: bool,
    },
    /// Run the client in the background as a systemd service that survives logout.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
        /// Ask for whatever was not passed as a flag, including which saved server to use.
        #[arg(short = 'i', long, global = true)]
        interactive: bool,
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
        /// Local SOCKS5 listen address, added alongside the tunnel with --tun
        /// [default: 127.0.0.1:1080].
        #[arg(long)]
        socks: Option<String>,
        /// Run a full-device tunnel instead of only a local proxy. Needs root.
        #[arg(long)]
        tun: bool,
        /// TUN interface name (--tun only) [default: leshiy0].
        #[arg(long)]
        tun_name: Option<String>,
        /// DNS resolver forced through the tunnel (--tun only) [default: 1.1.1.1].
        #[arg(long)]
        dns: Option<String>,
        /// TUN MTU (--tun only) [default: 1400].
        #[arg(long)]
        mtu: Option<u16>,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Standalone server (default): clients connect, server egresses directly.
    Single,
    /// Censor-facing entry that forwards to an exit via `--exit-uri`.
    Entry,
    /// Clean-egress exit (requires QUIC); its share URI is the connector credential.
    Exit,
}

impl Role {
    pub fn as_flag(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Entry => "entry",
            Self::Exit => "exit",
        }
    }
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

/// Defaults for `remote provision`. These live here rather than in `default_value`
/// attributes because the fields are `Option`: `-i` has to distinguish "the operator
/// chose 443" from "nobody has said anything about the port yet", and a clap default
/// makes those two cases indistinguishable.
pub const DEFAULT_LISTEN_PORT: u16 = 443;
pub const DEFAULT_USER_LABEL: &str = "self";
pub const DEFAULT_CLIENT_LABEL: &str = "client";
pub const DEFAULT_ROLE: &str = "single";
pub const DEFAULT_IMAGE: &str = concat!("ghcr.io/bigunmd/leshiy:v", env!("CARGO_PKG_VERSION"));

/// Client-side defaults, `Option` for the same reason as the provisioning ones above.
pub const DEFAULT_SOCKS: &str = "127.0.0.1:1080";
pub const DEFAULT_MTU: u16 = 1400;
pub const DEFAULT_TUN_NAME: &str = "leshiy0";
pub const DEFAULT_DNS: &str = "1.1.1.1";
pub const DEFAULT_HELPER_SOCKET: &str = "/run/leshiy/helper.sock";

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
    ///
    /// Required without `-i`: --host and --dest. With `-i`, anything omitted is asked for.
    Provision {
        /// SSH target as user@host[:port].
        #[arg(long)]
        host: Option<String>,
        /// Path to a private key file (PEM). If omitted, you'll be prompted for a password.
        #[arg(long)]
        key: Option<String>,
        /// Read the SSH password from stdin (first line).
        #[arg(long, conflicts_with = "interactive")]
        password_stdin: bool,
        /// Read the private key's passphrase from stdin instead of prompting. Only
        /// meaningful with --key; ignored for an unencrypted key.
        #[arg(long, conflicts_with_all = ["password_stdin", "sudo_password_stdin", "interactive"])]
        key_passphrase_stdin: bool,
        /// Connect as a non-root user and run privileged commands via sudo.
        /// Prompts for the sudo password unless --sudo-password-stdin is set.
        #[arg(long)]
        sudo: bool,
        /// Read the sudo password from stdin instead of prompting (implies --sudo).
        /// Cannot be combined with --password-stdin.
        #[arg(long, conflicts_with_all = ["password_stdin", "interactive"])]
        sudo_password_stdin: bool,
        /// Borrowed TLS site for REALITY, host:port.
        #[arg(long)]
        dest: Option<String>,
        /// Override the container's DNS resolver (a bare IPv4/IPv6 literal). By
        /// default the host's IPv4 upstream is detected and a public IPv4 fallback
        /// is added; set this only for split-horizon/private-resolver hosts.
        #[arg(long)]
        dns: Option<String>,
        /// REALITY/TCP external listen port [default: 443].
        #[arg(long)]
        port: Option<u16>,
        /// Enable QUIC on this UDP port.
        #[arg(long)]
        quic: Option<u16>,
        /// Container image reference. Defaults to the release matching this CLI
        /// (`ghcr.io/bigunmd/leshiy:v<CLI version>`), the tag CI publishes.
        #[arg(long)]
        image: Option<String>,
        /// Friendly server label.
        #[arg(long)]
        label: Option<String>,
        /// Label for the first (self) client config [default: self].
        #[arg(long)]
        user_label: Option<String>,
        /// Connector role: single (default), exit, middle, or entry.
        #[arg(long)]
        role: Option<String>,
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
    Status { server: Option<String> },
    /// Upgrade a saved server: pull a new image and recreate its container.
    ///
    /// Re-running `provision` does NOT do this — it reuses an already-running container by
    /// design, so it silently changes nothing. Users, keys and client URIs survive (they live on
    /// the data volume); only `teardown --purge` removes those.
    Upgrade {
        server: Option<String>,
        /// Image reference to upgrade to. Defaults to the release matching this CLI
        /// (`ghcr.io/bigunmd/leshiy:v<CLI version>`), the tag CI publishes.
        #[arg(long)]
        image: Option<String>,
        /// Resolve the newest published release instead of the tag matching this CLI.
        /// Conflicts with an explicit --image.
        #[arg(long, conflicts_with = "image")]
        latest: bool,
    },
    /// Export an encrypted backup of a saved server.
    Backup {
        server: Option<String>,
        #[arg(long)]
        connection_only: bool,
        /// Destination path for the encrypted blob.
        #[arg(long)]
        out: Option<String>,
    },
    /// Import a server backup blob into the vault.
    Restore { file: Option<String> },
    /// Remove the server container; optionally purge its config.
    Teardown {
        server: Option<String>,
        #[arg(long)]
        purge: bool,
    },
}

#[derive(clap::Subcommand)]
pub enum RemoteUserCmd {
    /// Add a client and print its config (URI to stdout, QR to stderr).
    Add {
        server: Option<String>,
        /// Friendly name for the issued client [default: client].
        #[arg(long)]
        label: Option<String>,
    },
    /// List the users currently on the server (live).
    Ls { server: Option<String> },
    /// Delete a user on the server by short_id.
    Rm {
        server: Option<String>,
        short_id: Option<String>,
    },
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
    fn tun_parses_uri_and_leaves_omitted_options_unset() {
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
                dns,
                ipv6,
                ..
            } => {
                assert_eq!(
                    uri.as_deref(),
                    Some("leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000")
                );
                // The values these carried as clap defaults now live in DEFAULT_* and are
                // applied by `client_wizard::plan_from_flags`, so `-i` can tell an omitted
                // option from a deliberate one. Unset must stay unset here.
                assert_eq!(transport, None);
                assert_eq!(mtu, None);
                assert_eq!(tun_name, None);
                assert_eq!(dns, None);
                // Dual-stack is opt-in: absent `--ipv6` means IPv4-only.
                assert!(!ipv6);
            }
            _ => panic!("expected Tun"),
        }
    }

    /// The defaults themselves did not change when they moved out of clap.
    #[test]
    fn the_documented_defaults_kept_their_values() {
        assert_eq!(DEFAULT_SOCKS, "127.0.0.1:1080");
        assert_eq!(DEFAULT_MTU, 1400);
        assert_eq!(DEFAULT_TUN_NAME, "leshiy0");
        assert_eq!(DEFAULT_DNS, "1.1.1.1");
        assert_eq!(DEFAULT_HELPER_SOCKET, "/run/leshiy/helper.sock");
        assert_eq!(DEFAULT_LISTEN_PORT, 443);
        assert_eq!(DEFAULT_USER_LABEL, "self");
        assert_eq!(DEFAULT_CLIENT_LABEL, "client");
        assert_eq!(DEFAULT_ROLE, "single");
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
    fn vpn_parses_uri_and_leaves_omitted_options_unset() {
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
                assert_eq!(
                    uri.as_deref(),
                    Some("leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000")
                );
                assert_eq!(transport, None);
                assert_eq!(mtu, None);
                assert_eq!(tun_name, None);
                assert_eq!(socket, None);
            }
            _ => panic!("expected Vpn"),
        }
    }

    /// `-i` is per-command on the client side rather than global, so each entry point has
    /// to actually carry it.
    #[test]
    fn every_client_subcommand_accepts_the_interactive_flag() {
        for argv in [
            vec!["leshiy", "connect", "-i"],
            vec!["leshiy", "client", "-i"],
            vec!["leshiy", "tun", "-i"],
            vec!["leshiy", "vpn", "-i"],
            vec!["leshiy", "service", "-i", "start"],
            vec!["leshiy", "service", "start", "-i"],
            vec!["leshiy", "service", "logs", "-i"],
        ] {
            Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{argv:?} must parse with -i, got: {e}"));
        }
    }

    /// `connect`'s URI is positional and was required; `-i` can supply it instead, but the
    /// positional form must keep working untouched.
    #[test]
    fn connect_takes_an_optional_positional_uri() {
        let cli = Cli::try_parse_from(["leshiy", "connect"]).expect("connect -i form");
        let Cmd::Connect { uri, .. } = cli.cmd else {
            panic!("expected Connect")
        };
        assert_eq!(uri, None);
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

    fn remote_interactive(argv: &[&str]) -> bool {
        match Cli::try_parse_from(argv)
            .unwrap_or_else(|e| panic!("{argv:?} must parse, got: {e}"))
            .cmd
        {
            Cmd::Remote { interactive, .. } => interactive,
            _ => panic!("expected Remote for {argv:?}"),
        }
    }

    /// `-i` is global on `remote`, so it must be accepted wherever a user naturally types
    /// it — before the subcommand, after it, and alongside the flags it complements.
    #[test]
    fn remote_accepts_the_interactive_flag_on_either_side_of_the_subcommand() {
        assert!(remote_interactive(&["leshiy", "remote", "-i", "provision"]));
        assert!(remote_interactive(&["leshiy", "remote", "provision", "-i"]));
        assert!(remote_interactive(&[
            "leshiy",
            "remote",
            "provision",
            "--interactive",
            "--host",
            "root@1.2.3.4"
        ]));
        assert!(remote_interactive(&[
            "leshiy", "remote", "-i", "user", "add"
        ]));
        assert!(remote_interactive(&["leshiy", "remote", "teardown", "-i"]));
        assert!(!remote_interactive(&["leshiy", "remote", "provision"]));
    }

    /// Each `--*-stdin` flag consumes the very stdin the wizard needs for its prompts, so
    /// the combination has to fail at parse time rather than deadlock on a read.
    #[test]
    fn interactive_conflicts_with_every_stdin_secret_flag() {
        for flag in [
            "--password-stdin",
            "--key-passphrase-stdin",
            "--sudo-password-stdin",
        ] {
            let argv = ["leshiy", "remote", "provision", "-i", flag];
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "{flag} must conflict with --interactive"
            );
            // Without -i the same flag is still perfectly valid.
            assert!(
                Cli::try_parse_from(["leshiy", "remote", "provision", flag]).is_ok(),
                "{flag} must still parse on its own"
            );
        }
    }

    /// `--host` / `--dest` moved from clap-required to code-required so `-i` can supply
    /// them. Parsing must therefore succeed while leaving them `None`.
    #[test]
    fn provision_leaves_omitted_options_unset_rather_than_defaulted() {
        let cli = Cli::try_parse_from(["leshiy", "remote", "provision", "-i"])
            .expect("provision -i should parse with no other flags");
        let Cmd::Remote {
            cmd:
                RemoteCmd::Provision {
                    host,
                    dest,
                    port,
                    image,
                    user_label,
                    role,
                    ..
                },
            ..
        } = cli.cmd
        else {
            panic!("expected Remote::Provision")
        };
        // All `None` — a clap `default_value` here would make "unset" indistinguishable
        // from an explicit choice, and the wizard would stop asking about them.
        assert_eq!(host, None);
        assert_eq!(dest, None);
        assert_eq!(port, None);
        assert_eq!(image, None);
        assert_eq!(user_label, None);
        assert_eq!(role, None);
    }

    #[test]
    fn provision_still_captures_every_option_when_passed_as_flags() {
        let cli = Cli::try_parse_from([
            "leshiy",
            "remote",
            "provision",
            "--host",
            "deploy@1.2.3.4:2222",
            "--dest",
            "www.apple.com:443",
            "--port",
            "8443",
            "--quic",
            "8444",
            "--role",
            "entry",
            "--downstream",
            "exit-1",
            "--label",
            "paris",
            "--user-label",
            "phone",
            "--dns",
            "1.1.1.1",
            "--image",
            "ghcr.io/x/y:v9",
            "--key",
            "/k.pem",
            "--sudo",
        ])
        .expect("full flag form should parse");
        let Cmd::Remote {
            cmd:
                RemoteCmd::Provision {
                    host,
                    dest,
                    port,
                    quic,
                    role,
                    downstream,
                    label,
                    user_label,
                    dns,
                    image,
                    key,
                    sudo,
                    ..
                },
            ..
        } = cli.cmd
        else {
            panic!("expected Remote::Provision")
        };
        assert_eq!(host.as_deref(), Some("deploy@1.2.3.4:2222"));
        assert_eq!(dest.as_deref(), Some("www.apple.com:443"));
        assert_eq!(port, Some(8443));
        assert_eq!(quic, Some(8444));
        assert_eq!(role.as_deref(), Some("entry"));
        assert_eq!(downstream.as_deref(), Some("exit-1"));
        assert_eq!(label.as_deref(), Some("paris"));
        assert_eq!(user_label.as_deref(), Some("phone"));
        assert_eq!(dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(image.as_deref(), Some("ghcr.io/x/y:v9"));
        assert_eq!(key.as_deref(), Some("/k.pem"));
        assert!(sudo);
    }

    /// Day-2 subcommands take their server positionally; `-i` picks it from the vault, so
    /// the positional had to become optional without becoming meaningless.
    #[test]
    fn day_two_subcommands_take_an_optional_server_positional() {
        for argv in [
            vec!["leshiy", "remote", "status"],
            vec!["leshiy", "remote", "upgrade"],
            vec!["leshiy", "remote", "teardown"],
            vec!["leshiy", "remote", "backup"],
            vec!["leshiy", "remote", "restore"],
            vec!["leshiy", "remote", "user", "ls"],
            vec!["leshiy", "remote", "user", "rm"],
        ] {
            Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{argv:?} must parse without a server, got: {e}"));
        }
        // And the named form still works.
        let cli = Cli::try_parse_from(["leshiy", "remote", "status", "paris"]).unwrap();
        let Cmd::Remote {
            cmd: RemoteCmd::Status { server },
            ..
        } = cli.cmd
        else {
            panic!("expected Remote::Status")
        };
        assert_eq!(server.as_deref(), Some("paris"));
    }

    /// `--image` lost its `default_value`, which is what `--latest` was declared to
    /// conflict with; the conflict must survive that change.
    #[test]
    fn upgrade_latest_still_conflicts_with_an_explicit_image() {
        assert!(
            Cli::try_parse_from([
                "leshiy", "remote", "upgrade", "srv", "--latest", "--image", "x:1"
            ])
            .is_err(),
            "--latest and --image must conflict"
        );
        assert!(Cli::try_parse_from(["leshiy", "remote", "upgrade", "srv", "--latest"]).is_ok());
        assert!(
            Cli::try_parse_from(["leshiy", "remote", "upgrade", "srv", "--image", "x:1"]).is_ok()
        );
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
                interactive,
            } => {
                assert_eq!(
                    uri.as_deref(),
                    Some("leshiy://abc@1.2.3.4:443?sni=x&sid=00")
                );
                assert_eq!(socks, None);
                assert_eq!(transport, None);
                assert!(!interactive);
            }
            _ => panic!("expected Connect"),
        }
    }
}
