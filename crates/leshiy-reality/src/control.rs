//! Local control socket (ADR-0020): newline-delimited JSON over a 0600 Unix socket.
use crate::config::format_reality_uri;
use crate::user::{User, UserAdmin};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[derive(Clone)]
pub struct UriIssuer {
    pub server_public: [u8; 32],
    pub host: String,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
enum Req {
    Add {
        short_id: Option<String>,
        sni: Option<String>,
        enabled: Option<bool>,
        expires_at: Option<u64>,
        data_cap: Option<u64>,
        rate_up: Option<u32>,
        rate_down: Option<u32>,
    },
    Update {
        short_id: String,
        expires_at: Option<u64>,
        data_cap: Option<u64>,
        rate_up: Option<u32>,
        rate_down: Option<u32>,
    },
    Remove {
        short_id: String,
    },
    Disable {
        short_id: String,
    },
    Enable {
        short_id: String,
    },
    ResetUsage {
        short_id: String,
    },
    Show {
        short_id: String,
    },
    List,
    Uri {
        short_id: String,
        sni: Option<String>,
    },
}

#[derive(Serialize)]
struct Resp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    users: Option<Vec<UserJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserJson>,
}

impl Resp {
    fn ok() -> Self {
        Resp {
            ok: true,
            error: None,
            uri: None,
            users: None,
            user: None,
        }
    }
    fn err(m: impl Into<String>) -> Self {
        Resp {
            ok: false,
            error: Some(m.into()),
            uri: None,
            users: None,
            user: None,
        }
    }
}

#[derive(Serialize)]
struct UserJson {
    short_id: String,
    enabled: bool,
    expires_at: Option<u64>,
    data_cap: Option<u64>,
    rate_up: Option<u32>,
    rate_down: Option<u32>,
    used_up: u64,
    used_down: u64,
}

fn hexid(s: &str) -> Option<[u8; 8]> {
    let v = hex::decode(s).ok()?;
    v.as_slice().try_into().ok()
}

pub async fn serve_control(
    path: &Path,
    store: Arc<dyn UserAdmin>,
    issuer: UriIssuer,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path); // unlink stale
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    loop {
        let (conn, _) = listener.accept().await?;
        let store = store.clone();
        let issuer = issuer.clone();
        tokio::spawn(async move {
            let _ = handle(conn, store, issuer).await;
        });
    }
}

/// Maximum bytes accepted per request. A line that hits this cap without a newline
/// produces a serde parse error → `{"ok":false}` (correct; no OOM).
const MAX_LINE: u64 = 64 * 1024;

async fn handle(
    conn: UnixStream,
    store: Arc<dyn UserAdmin>,
    issuer: UriIssuer,
) -> std::io::Result<()> {
    // Cap the read side to MAX_LINE bytes so a client streaming bytes with no newline
    // cannot grow the String until OOM.  A line that hits the cap without a newline
    // produces a serde parse error → `{"ok":false}` (correct).
    let mut r = BufReader::new(conn.take(MAX_LINE));
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    // Recover the raw stream for writing:
    //   r.into_inner()             → Take<UnixStream>
    //   .into_inner()              → UnixStream
    let mut stream = r.into_inner().into_inner();
    let resp = match serde_json::from_str::<Req>(line.trim()) {
        Ok(req) => dispatch(req, &store, &issuer),
        Err(e) => Resp::err(format!("bad request: {e}")),
    };
    let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".into());
    out.push('\n');
    stream.write_all(out.as_bytes()).await
}

fn rand_short_id() -> [u8; 8] {
    use rand::RngCore;
    let mut id = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

fn dispatch(req: Req, store: &Arc<dyn UserAdmin>, issuer: &UriIssuer) -> Resp {
    match req {
        Req::Add {
            short_id,
            sni,
            enabled,
            expires_at,
            data_cap,
            rate_up,
            rate_down,
        } => {
            let id = match short_id {
                Some(s) => match hexid(&s) {
                    Some(i) => i,
                    None => return Resp::err("bad short_id"),
                },
                None => rand_short_id(),
            };
            store.upsert(User {
                short_id: id,
                enabled: enabled.unwrap_or(true),
                expires_at,
                data_cap,
                rate_up,
                rate_down,
            });
            let sni = sni.unwrap_or_default();
            let uri = format_reality_uri(&issuer.server_public, &issuer.host, &sni, &id);
            Resp {
                uri: Some(uri),
                ..Resp::ok()
            }
        }
        Req::Update {
            short_id,
            expires_at,
            data_cap,
            rate_up,
            rate_down,
        } => {
            let Some(id) = hexid(&short_id) else {
                return Resp::err("bad short_id");
            };
            // read current enabled via snapshot, then re-upsert with new limits
            let Some(cur) = store.snapshot().into_iter().find(|u| u.user.short_id == id) else {
                return Resp::err("unknown short_id");
            };
            store.upsert(User {
                short_id: id,
                enabled: cur.user.enabled,
                expires_at,
                data_cap,
                rate_up,
                rate_down,
            });
            Resp::ok()
        }
        Req::Remove { short_id } => gate(hexid(&short_id), |id| store.remove(&id)),
        Req::Disable { short_id } => gate(hexid(&short_id), |id| store.set_enabled(&id, false)),
        Req::Enable { short_id } => gate(hexid(&short_id), |id| store.set_enabled(&id, true)),
        Req::ResetUsage { short_id } => gate(hexid(&short_id), |id| store.reset_usage(&id)),
        Req::Show { short_id } => {
            let Some(id) = hexid(&short_id) else {
                return Resp::err("bad short_id");
            };
            match store.snapshot().into_iter().find(|u| u.user.short_id == id) {
                Some(s) => Resp {
                    user: Some(to_json(&s)),
                    ..Resp::ok()
                },
                None => Resp::err("unknown short_id"),
            }
        }
        Req::List => Resp {
            users: Some(store.snapshot().iter().map(to_json).collect()),
            ..Resp::ok()
        },
        Req::Uri { short_id, sni } => match hexid(&short_id) {
            Some(id) => Resp {
                uri: Some(format_reality_uri(
                    &issuer.server_public,
                    &issuer.host,
                    &sni.unwrap_or_default(),
                    &id,
                )),
                ..Resp::ok()
            },
            None => Resp::err("bad short_id"),
        },
    }
}

fn gate(id: Option<[u8; 8]>, f: impl FnOnce([u8; 8]) -> bool) -> Resp {
    match id {
        Some(i) => {
            if f(i) {
                Resp::ok()
            } else {
                Resp::err("unknown short_id")
            }
        }
        None => Resp::err("bad short_id"),
    }
}

fn to_json(s: &crate::user::UserStatus) -> UserJson {
    UserJson {
        short_id: hex::encode(s.user.short_id),
        enabled: s.user.enabled,
        expires_at: s.user.expires_at,
        data_cap: s.user.data_cap,
        rate_up: s.user.rate_up,
        rate_down: s.user.rate_down,
        used_up: s.used_up,
        used_down: s.used_down,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::{InMemoryUserStore, UserStore};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn control_add_list_disable_roundtrip() {
        let dir = std::env::temp_dir().join(format!("leshiy-ctl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("c.sock");
        let store = Arc::new(InMemoryUserStore::new(vec![]));
        let issuer = UriIssuer {
            server_public: [9u8; 32],
            host: "h:443".into(),
        };
        let s2 = store.clone();
        let path = sock.clone();
        tokio::spawn(async move {
            let _ = serve_control(&path, s2, issuer).await;
        });
        // wait for the socket
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let resp = req(
            &sock,
            r#"{"cmd":"add","short_id":"0102030400000000","enabled":true,"expires_at":null,"data_cap":null,"rate_up":null,"rate_down":null}"#,
        )
        .await;
        assert!(resp.contains("\"ok\":true"));
        assert!(resp.contains("leshiy://")); // add returns a URI
        let list = req(&sock, r#"{"cmd":"list"}"#).await;
        assert!(list.contains("0102030400000000"));
        let dis = req(&sock, r#"{"cmd":"disable","short_id":"0102030400000000"}"#).await;
        assert!(dis.contains("\"ok\":true"));
        assert!(store.authorize(&[1, 2, 3, 4, 0, 0, 0, 0], 0).is_none()); // live effect
        let bad = req(&sock, r#"{"cmd":"frobnicate"}"#).await;
        assert!(bad.contains("\"ok\":false")); // unknown cmd, no panic
    }

    async fn req(sock: &std::path::Path, line: &str) -> String {
        let mut s = tokio::net::UnixStream::connect(sock).await.unwrap();
        s.write_all(line.as_bytes()).await.unwrap();
        s.write_all(b"\n").await.unwrap();
        let mut r = BufReader::new(s);
        let mut out = String::new();
        r.read_line(&mut out).await.unwrap();
        out
    }
}
