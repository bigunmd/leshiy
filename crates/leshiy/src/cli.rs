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
        /// Transport to use: auto (default, same as tcp), quic, or tcp.
        #[arg(long, default_value = "auto")]
        transport: Transport,
    },
    /// Manage users on a running leshiy server via its control socket.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
}

/// Transport selection for the client subcommand.
#[derive(Clone, ValueEnum)]
pub enum Transport {
    /// Use REALITY (TCP) transport — same as `tcp`.
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
    },
}
