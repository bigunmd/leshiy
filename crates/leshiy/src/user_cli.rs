//! `leshiy user` — control-socket client.
//!
//! Sends newline-delimited JSON requests to the server's Unix control socket and
//! displays the result in a human-readable form.
use crate::cli::UserCmd;
use crate::reality_config::RealityServerConfig;
use crate::server::default_sock_path;
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

// ── Socket resolution ──────────────────────────────────────────────────────────

/// Resolve the control socket path, using the SAME logic the server uses:
///
/// 1. If `--socket` was given explicitly → use it directly.
/// 2. Otherwise read the config file and use `RealityServerConfig.control_socket` if set.
/// 3. Otherwise fall back to `<config_dir>/leshiy.sock` (the `default_sock_path` helper).
///
/// This ensures `leshiy server --config X` and `leshiy user ... --config X` always agree.
pub(crate) fn resolve_socket(config: &str, socket: Option<&str>) -> String {
    if let Some(s) = socket {
        return s.to_owned();
    }
    // Try to read and parse the config — if anything fails, fall back to the default.
    if let Ok(toml_str) = std::fs::read_to_string(config)
        && let Ok(cfg) = toml::from_str::<RealityServerConfig>(&toml_str)
        && let Some(sock) = cfg.control_socket
    {
        return sock;
    }
    default_sock_path(config)
}

// ── Parse helpers ──────────────────────────────────────────────────────────────

/// Parse a human-friendly size string → bytes (1000-based SI).
///
/// Examples: `"10GB"` → 10_000_000_000, `"512MB"` → 512_000_000,
/// `"1KB"` → 1_000, `"1234"` → 1_234.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("GB") {
        (n, 1_000_000_000u64)
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, 1_000_000u64)
    } else if let Some(n) = s.strip_suffix("KB") {
        (n, 1_000u64)
    } else {
        (s, 1u64)
    };
    let n: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("bad size: {s}"))?;
    Ok(n * mult)
}

/// Parse a human-friendly rate string → bytes/sec.
///
/// `Mbps`/`Kbps` = SI bits/s (÷ 8); `MBps`/`KBps` = SI bytes/s; bare = bytes/s.
///
/// Examples: `"5Mbps"` → 625_000, `"500Kbps"` → 62_500,
/// `"1MBps"` → 1_000_000, `"600KBps"` → 600_000.
pub fn parse_rate(s: &str) -> Result<u32> {
    let s = s.trim();
    let bytes_per_sec: f64 = if let Some(n) = s.strip_suffix("Mbps") {
        n.trim().parse::<f64>()? * 125_000.0
    } else if let Some(n) = s.strip_suffix("Kbps") {
        n.trim().parse::<f64>()? * 125.0
    } else if let Some(n) = s.strip_suffix("MBps") {
        n.trim().parse::<f64>()? * 1_000_000.0
    } else if let Some(n) = s.strip_suffix("KBps") {
        n.trim().parse::<f64>()? * 1_000.0
    } else {
        s.parse::<f64>().with_context(|| format!("bad rate: {s}"))?
    };
    Ok(bytes_per_sec as u32)
}

/// Parse an expiry string → absolute unix seconds.
///
/// Relative: `"+30d"`, `"+12h"`, `"+45m"` (added to `now`).
/// Absolute: a bare integer (unix seconds).
pub fn parse_expires(s: &str, now: u64) -> Result<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('+') {
        let (num_str, unit) = rest.split_at(rest.len() - 1);
        let n: u64 = num_str
            .parse()
            .with_context(|| format!("bad duration: {s}"))?;
        let secs = match unit {
            "d" => n * 86_400,
            "h" => n * 3_600,
            "m" => n * 60,
            _ => return Err(anyhow!("use +Nd / +Nh / +Nm or a unix timestamp")),
        };
        Ok(now + secs)
    } else {
        s.parse::<u64>()
            .with_context(|| format!("bad expires: {s}"))
    }
}

// ── Socket client ──────────────────────────────────────────────────────────────

/// Connect to the control socket, send a JSON request, return the parsed response.
///
/// Returns an error if the socket is unreachable or the server responds with `ok: false`.
pub async fn call(socket: &str, req: Value) -> Result<Value> {
    let mut stream = UnixStream::connect(socket).await.with_context(|| {
        format!("connect to control socket {socket:?} — is the server running?")
    })?;

    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    stream.write_all(line.as_bytes()).await?;

    let mut reader = BufReader::new(stream);
    let mut out = String::new();
    reader.read_line(&mut out).await?;

    let v: Value = serde_json::from_str(out.trim()).context("bad response from server")?;
    if v.get("ok").and_then(|b| b.as_bool()) != Some(true) {
        let msg = v
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(anyhow!("server error: {msg}"));
    }
    Ok(v)
}

// ── Current time (unix secs) ───────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Display helpers ────────────────────────────────────────────────────────────

fn fmt_bytes(b: u64) -> String {
    if b >= 1_000_000_000 {
        format!("{:.2}GB", b as f64 / 1_000_000_000.0)
    } else if b >= 1_000_000 {
        format!("{:.2}MB", b as f64 / 1_000_000.0)
    } else if b >= 1_000 {
        format!("{:.2}KB", b as f64 / 1_000.0)
    } else {
        format!("{b}B")
    }
}

fn fmt_rate(r: u64) -> String {
    if r >= 1_000_000 {
        format!("{:.2}MBps", r as f64 / 1_000_000.0)
    } else if r >= 1_000 {
        format!("{:.2}KBps", r as f64 / 1_000.0)
    } else {
        format!("{r}B/s")
    }
}

fn print_user(u: &Value) {
    let short_id = u["short_id"].as_str().unwrap_or("-");
    let enabled = u["enabled"].as_bool().unwrap_or(false);
    let expires = u["expires_at"]
        .as_u64()
        .map(|t| t.to_string())
        .unwrap_or_else(|| "never".into());
    let cap = u["data_cap"]
        .as_u64()
        .map(fmt_bytes)
        .unwrap_or_else(|| "unlimited".into());
    let rate_up = u["rate_up"]
        .as_u64()
        .map(fmt_rate)
        .unwrap_or_else(|| "unlimited".into());
    let rate_down = u["rate_down"]
        .as_u64()
        .map(fmt_rate)
        .unwrap_or_else(|| "unlimited".into());
    let used_up = u["used_up"].as_u64().unwrap_or(0);
    let used_down = u["used_down"].as_u64().unwrap_or(0);

    println!("short_id:  {short_id}");
    println!("enabled:   {enabled}");
    println!("expires:   {expires}");
    println!("cap:       {cap}");
    println!("rate_up:   {rate_up}");
    println!("rate_down: {rate_down}");
    println!("used_up:   {}", fmt_bytes(used_up));
    println!("used_down: {}", fmt_bytes(used_down));
}

fn print_list(users: &[Value]) {
    if users.is_empty() {
        println!("(no users)");
        return;
    }
    println!(
        "{:<18} {:<8} {:<10} {:<12} {:<12} {:<12}",
        "SHORT_ID", "ENABLED", "EXPIRES", "CAP", "RATE_UP", "RATE_DOWN"
    );
    for u in users {
        let short_id = u["short_id"].as_str().unwrap_or("-");
        let enabled = if u["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let expires = u["expires_at"]
            .as_u64()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "never".into());
        let cap = u["data_cap"]
            .as_u64()
            .map(fmt_bytes)
            .unwrap_or_else(|| "unlimited".into());
        let rate_up = u["rate_up"]
            .as_u64()
            .map(fmt_rate)
            .unwrap_or_else(|| "unlimited".into());
        let rate_down = u["rate_down"]
            .as_u64()
            .map(fmt_rate)
            .unwrap_or_else(|| "unlimited".into());
        println!(
            "{:<18} {:<8} {:<10} {:<12} {:<12} {:<12}",
            short_id, enabled, expires, cap, rate_up, rate_down
        );
    }
}

// ── Main dispatch ──────────────────────────────────────────────────────────────

pub async fn run(cmd: UserCmd) -> Result<()> {
    match cmd {
        UserCmd::Add {
            sni,
            data_cap,
            rate_up,
            rate_down,
            expires,
            config,
            socket,
            qr,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            let now = now_unix();
            let expires_at: Option<u64> = expires
                .as_deref()
                .map(|s| parse_expires(s, now))
                .transpose()?;
            let data_cap_bytes: Option<u64> = data_cap.as_deref().map(parse_size).transpose()?;
            let rate_up_bps: Option<u32> = rate_up.as_deref().map(parse_rate).transpose()?;
            let rate_down_bps: Option<u32> = rate_down.as_deref().map(parse_rate).transpose()?;

            let req = json!({
                "cmd": "add",
                "sni": sni,
                "enabled": true,
                "expires_at": expires_at,
                "data_cap": data_cap_bytes,
                "rate_up": rate_up_bps,
                "rate_down": rate_down_bps,
            });
            let resp = call(&sock, req).await?;
            if let Some(uri) = resp["uri"].as_str() {
                println!("{uri}");
                if qr {
                    println!("{}", crate::quickstart::qr_string(uri));
                }
            }
        }

        UserCmd::List { config, socket } => {
            let sock = resolve_socket(&config, socket.as_deref());
            let resp = call(&sock, json!({"cmd": "list"})).await?;
            let empty = vec![];
            let users = resp["users"].as_array().unwrap_or(&empty);
            print_list(users);
        }

        UserCmd::Show {
            short_id,
            config,
            socket,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            let resp = call(&sock, json!({"cmd": "show", "short_id": short_id})).await?;
            if let Some(u) = resp.get("user") {
                print_user(u);
            }
        }

        UserCmd::Update {
            short_id,
            data_cap,
            rate_up,
            rate_down,
            expires,
            config,
            socket,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            let now = now_unix();
            let expires_at: Option<u64> = expires
                .as_deref()
                .map(|s| parse_expires(s, now))
                .transpose()?;
            let data_cap_bytes: Option<u64> = data_cap.as_deref().map(parse_size).transpose()?;
            let rate_up_bps: Option<u32> = rate_up.as_deref().map(parse_rate).transpose()?;
            let rate_down_bps: Option<u32> = rate_down.as_deref().map(parse_rate).transpose()?;

            let req = json!({
                "cmd": "update",
                "short_id": short_id,
                "expires_at": expires_at,
                "data_cap": data_cap_bytes,
                "rate_up": rate_up_bps,
                "rate_down": rate_down_bps,
            });
            call(&sock, req).await?;
            println!("updated {short_id}");
        }

        UserCmd::Disable {
            short_id,
            config,
            socket,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            call(&sock, json!({"cmd": "disable", "short_id": short_id})).await?;
            println!("disabled {short_id}");
        }

        UserCmd::Enable {
            short_id,
            config,
            socket,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            call(&sock, json!({"cmd": "enable", "short_id": short_id})).await?;
            println!("enabled {short_id}");
        }

        UserCmd::ResetUsage {
            short_id,
            config,
            socket,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            call(&sock, json!({"cmd": "reset-usage", "short_id": short_id})).await?;
            println!("reset usage for {short_id}");
        }

        UserCmd::Rm {
            short_id,
            config,
            socket,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            call(&sock, json!({"cmd": "remove", "short_id": short_id})).await?;
            println!("removed {short_id}");
        }

        UserCmd::Uri {
            short_id,
            sni,
            config,
            socket,
            qr,
        } => {
            let sock = resolve_socket(&config, socket.as_deref());
            let resp = call(
                &sock,
                json!({"cmd": "uri", "short_id": short_id, "sni": sni}),
            )
            .await?;
            if let Some(uri) = resp["uri"].as_str() {
                println!("{uri}");
                if qr {
                    println!("{}", crate::quickstart::qr_string(uri));
                }
            }
        }
    }
    Ok(())
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_variants() {
        assert_eq!(parse_size("10GB").unwrap(), 10_000_000_000);
        assert_eq!(parse_size("512MB").unwrap(), 512_000_000);
        assert_eq!(parse_size("1KB").unwrap(), 1_000);
        assert_eq!(parse_size("1000000").unwrap(), 1_000_000);
        assert!(parse_size("nope").is_err());
    }

    #[test]
    fn parse_rate_variants() {
        assert_eq!(parse_rate("5Mbps").unwrap(), 625_000);
        assert_eq!(parse_rate("500Kbps").unwrap(), 62_500);
        assert_eq!(parse_rate("1MBps").unwrap(), 1_000_000);
        assert_eq!(parse_rate("600KBps").unwrap(), 600_000);
        assert_eq!(parse_rate("9600").unwrap(), 9_600);
        assert!(parse_rate("bad").is_err());
    }

    #[test]
    fn parse_expires_relative() {
        // With now = 0, relative offsets produce the offset itself.
        assert_eq!(parse_expires("+1d", 0).unwrap(), 86_400);
        assert_eq!(parse_expires("+12h", 0).unwrap(), 43_200);
        assert_eq!(parse_expires("+45m", 0).unwrap(), 2_700);
        // Absolute unix secs.
        assert_eq!(parse_expires("1717000000", 0).unwrap(), 1_717_000_000);
        // Bad unit.
        assert!(parse_expires("+5w", 0).is_err());
    }
}
