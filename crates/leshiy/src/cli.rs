//! CLI subcommand definitions via clap derive.
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "leshiy",
    version,
    about = "Leshiy REALITY-style stealth tunnel"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
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
        #[arg(long)]
        uri: String,
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
    Tun {
        /// The leshiy:// server URI.
        #[arg(long)]
        uri: String,
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
    Upgrade {
        /// GitHub repo to pull from.
        #[arg(long, default_value = "bigunmd/leshiy")]
        repo: String,
        /// Release tag to install (e.g. v0.2.0). Defaults to the latest release.
        #[arg(long)]
        version: Option<String>,
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
#[derive(Clone, ValueEnum)]
pub enum Transport {
    /// Prefer QUIC where the URI has a `quic=` endpoint and UDP is open; fall back
    /// to REALITY/TCP when QUIC is blocked or absent.
    Auto,
    /// Use QUIC/H3 transport (requires `quic=` in the URI).
    Quic,
    /// Use REALITY (TCP) transport.
    Tcp,
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

#[cfg(test)]
mod tests {
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
                ..
            } => {
                assert_eq!(uri, "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000");
                assert!(matches!(transport, Transport::Tcp));
                assert_eq!(mtu, 1400);
                assert_eq!(tun_name, "leshiy0");
            }
            _ => panic!("expected Tun"),
        }
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
