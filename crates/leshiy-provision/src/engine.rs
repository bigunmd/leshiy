//! Provisioning orchestration. Emits typed progress events; talks only to the
//! `Transport` trait so it is fully testable against a fake.

use crate::docker;
use crate::error::{Error, Result};
use crate::ssh::{SshTarget, Transport};
use crate::vault::{ClientConfig, ServerRecord, SshSecret};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Connect,
    Preflight,
    DockerReady,
    DetectExisting,
    PullImage,
    RunContainer,
    IssueUser,
    Persist,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Started,
    Done,
    Failed,
}

#[derive(Clone, Debug)]
pub struct ProgressEvent {
    pub step: Step,
    pub status: Status,
    pub detail: String,
}

/// The connector role a provisioned node plays in an Entry▶…▶Exit chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionRole {
    Single,
    Exit,
    Middle,
    Entry,
}

impl ProvisionRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ProvisionRole::Single => "single",
            ProvisionRole::Exit => "exit",
            ProvisionRole::Middle => "middle",
            ProvisionRole::Entry => "entry",
        }
    }
    /// Exit and middle nodes expose their issued URI as a connector credential.
    fn exposes_connector(self) -> bool {
        matches!(self, ProvisionRole::Exit | ProvisionRole::Middle)
    }
}

pub struct ProvisionParams {
    pub id: String,
    pub label: String,
    pub target: SshTarget,
    pub secret: SshSecret,
    pub public_host: String,
    pub dest_sni: String,
    pub image_ref: String,
    pub container: String,
    pub quic_port: Option<u16>,
    pub listen_port: u16,
    pub user_label: String,
    pub now: u64,
    pub role: ProvisionRole,
    pub connector: Option<String>,
    pub downstream: Option<String>,
}

fn ev(step: Step, status: Status, detail: impl Into<String>) -> ProgressEvent {
    ProgressEvent {
        step,
        status,
        detail: detail.into(),
    }
}

/// Extract `(short_id, reality_pub_b64)` from an issued `leshiy://` URI.
pub fn parse_uri_fields(uri: &str) -> Result<(String, String)> {
    let rest = uri
        .strip_prefix("leshiy://")
        .ok_or_else(|| Error::Parse("not a leshiy uri".into()))?;
    let (pub_b64, _after) = rest
        .split_once('@')
        .ok_or_else(|| Error::Parse("no '@' in uri".into()))?;
    if pub_b64.is_empty() {
        return Err(Error::Parse("no pubkey".into()));
    }
    let pub_b64 = pub_b64.to_string();
    let sid = uri
        .split("sid=")
        .nth(1)
        .map(|s| s.split(['&', ' ', '\n']).next().unwrap_or(s).to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Parse("no sid".into()))?;
    Ok((sid, pub_b64))
}

/// Extract a QUIC endpoint from an issued URI's query, if present.
pub fn parse_quic_fields(uri: &str) -> Option<crate::vault::QuicInfo> {
    fn q<'a>(uri: &'a str, key: &str) -> Option<&'a str> {
        uri.split(&format!("{key}="))
            .nth(1)
            .map(|s| s.split(['&', ' ', '\n']).next().unwrap_or(s))
            .filter(|s| !s.is_empty())
    }
    let addr = q(uri, "quic")?;
    let sni = q(uri, "qsni")?;
    Some(crate::vault::QuicInfo {
        addr: addr.to_string(),
        sni: sni.to_string(),
        cert_sha256: q(uri, "qcert").map(str::to_string),
    })
}

/// Whether an image reference is composed only of characters safe to place in a
/// shell command (registry/repo/tag/digest). Rejects shell metacharacters.
pub fn valid_image_ref(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
        })
}

/// Provision `target` into a running leshiy server and return its record.
pub async fn provision<T: Transport>(
    t: &mut T,
    p: &ProvisionParams,
    on_event: &mut dyn FnMut(ProgressEvent),
) -> Result<ServerRecord> {
    let mut current = Step::Connect;
    let result = provision_inner(t, p, on_event, &mut current).await;
    if let Err(ref e) = result {
        on_event(ev(current, Status::Failed, format!("{e}")));
    }
    result
}

async fn provision_inner<T: Transport>(
    t: &mut T,
    p: &ProvisionParams,
    on_event: &mut dyn FnMut(ProgressEvent),
    current: &mut Step,
) -> Result<ServerRecord> {
    if !valid_image_ref(&p.image_ref) {
        return Err(Error::Parse(format!(
            "invalid image ref: {:?}",
            p.image_ref
        )));
    }
    if !valid_image_ref(&p.container) {
        return Err(Error::Parse(format!(
            "invalid container name: {:?}",
            p.container
        )));
    }

    // 1. Connect + TOFU pin.
    *current = Step::Connect;
    on_event(ev(Step::Connect, Status::Started, &p.target.host));
    let host_key_fp = t.connect(&p.target, &p.secret).await?;
    on_event(ev(Step::Connect, Status::Done, &host_key_fp));

    // 2. Preflight + 3. Docker ready.
    *current = Step::Preflight;
    on_event(ev(Step::Preflight, Status::Started, ""));
    let has_docker = t.run(docker::detect_docker_cmd()).await?.stdout.trim() == "yes";
    on_event(ev(
        Step::Preflight,
        Status::Done,
        format!("docker={has_docker}"),
    ));

    *current = Step::DockerReady;
    on_event(ev(Step::DockerReady, Status::Started, ""));
    if !has_docker {
        t.run(docker::install_docker_cmd()).await?.ok()?;
    }
    on_event(ev(Step::DockerReady, Status::Done, ""));

    // 4. Detect existing container (idempotent re-run).
    *current = Step::DetectExisting;
    on_event(ev(Step::DetectExisting, Status::Started, ""));
    let names = docker::parse_ps_names(&t.run(docker::ps_names_cmd()).await?.stdout);
    let exists = names.iter().any(|n| n == &p.container);
    on_event(ev(
        Step::DetectExisting,
        Status::Done,
        format!("exists={exists}"),
    ));

    // 5/6. Pull + run (skipped if exists).
    if !exists {
        *current = Step::PullImage;
        on_event(ev(Step::PullImage, Status::Started, &p.image_ref));
        t.run(&docker::pull_cmd(&p.image_ref)).await?.ok()?;
        on_event(ev(Step::PullImage, Status::Done, ""));

        *current = Step::RunContainer;
        on_event(ev(Step::RunContainer, Status::Started, ""));
        let mut envs = vec![
            ("LESHIY_HOST".to_string(), p.public_host.clone()),
            ("LESHIY_DEST".to_string(), p.dest_sni.clone()),
            (
                "LESHIY_LISTEN".to_string(),
                format!("0.0.0.0:{}", p.listen_port),
            ),
        ];
        if let Some(q) = p.quic_port {
            envs.push(("LESHIY_QUIC_LISTEN".to_string(), format!("0.0.0.0:{q}")));
        }
        if let Some(conn) = &p.connector {
            envs.push(("LESHIY_CONNECTOR".to_string(), conn.clone()));
        }
        t.run(&docker::run_cmd(
            &p.container,
            &p.image_ref,
            p.listen_port,
            p.quic_port,
            &envs,
        ))
        .await?
        .ok()?;
        on_event(ev(Step::RunContainer, Status::Done, ""));
    } else {
        on_event(ev(
            Step::PullImage,
            Status::Done,
            "reusing existing container — dest/quic/connector changes are NOT re-applied (teardown first to change them)",
        ));
    }

    // 7. Issue the first user.
    *current = Step::IssueUser;
    on_event(ev(Step::IssueUser, Status::Started, &p.user_label));
    let add = exec_user_add(t, &p.container, &p.user_label).await?;
    let uri = add.trim().lines().next().unwrap_or("").to_string();
    let (short_id, reality_public_b64) = parse_uri_fields(&uri)?;
    on_event(ev(Step::IssueUser, Status::Done, &short_id));

    // 8. Build the record.
    *current = Step::Persist;
    if p.role.exposes_connector() && parse_quic_fields(&uri).is_none() {
        return Err(Error::Parse(format!(
            "node provisioned as {} but its issued URI has no QUIC endpoint — the connector chain needs QUIC (is the image built with QUIC support?)",
            p.role.as_str()
        )));
    }
    let connector_uri = if p.role.exposes_connector() {
        Some(uri.clone())
    } else {
        None
    };
    let rec = ServerRecord {
        id: p.id.clone(),
        label: p.label.clone(),
        host: p.target.host.clone(),
        port: p.target.port,
        ssh_user: p.target.user.clone(),
        ssh_secret: p.secret.clone(),
        host_key_fp,
        public_host: p.public_host.clone(),
        image_ref: p.image_ref.clone(),
        container: p.container.clone(),
        reality_public_b64,
        quic: parse_quic_fields(&uri),
        clients: vec![ClientConfig {
            short_id,
            label: p.user_label.clone(),
            uri,
        }],
        created_at: p.now,
        role: p.role.as_str().to_string(),
        connector_uri,
        downstream: p.downstream.clone(),
    };
    on_event(ev(Step::Persist, Status::Done, &rec.id));
    Ok(rec)
}

/// Add another client on an already-provisioned server; appends to `rec.clients`.
pub async fn add_user<T: Transport>(
    t: &mut T,
    rec: &mut ServerRecord,
    label: &str,
    extra_args: &str,
) -> Result<ClientConfig> {
    // NOTE: --label is a LOCAL annotation only; it is NOT passed to the remote
    // `leshiy user add` command because that subcommand has no --label flag.
    let args = extra_args.trim();
    let cmd = docker::exec_user_add_cmd(&rec.container, args);
    let stdout = t.run(&cmd).await?.ok()?.stdout;
    let uri = stdout.trim().lines().next().unwrap_or("").to_string();
    let (short_id, _pub) = parse_uri_fields(&uri)?;
    let cc = ClientConfig {
        short_id,
        label: label.to_string(),
        uri,
    };
    rec.clients.push(cc.clone());
    Ok(cc)
}

/// A user as reported by the server's `leshiy user list --json`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct RemoteUser {
    pub short_id: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub data_cap: Option<u64>,
    #[serde(default)]
    pub used_up: u64,
    #[serde(default)]
    pub used_down: u64,
}

/// List the users currently registered on the server.
pub async fn list_users<T: Transport>(t: &mut T, rec: &ServerRecord) -> Result<Vec<RemoteUser>> {
    let out = t
        .run(&docker::exec_user_list_json_cmd(&rec.container))
        .await?
        .ok()?;
    // Takes the JSON array line from stdout (stderr is already separate).
    let line = out
        .stdout
        .lines()
        .map(str::trim)
        .rfind(|l| l.starts_with('['))
        .ok_or_else(|| Error::Parse("no user list json".into()))?;
    serde_json::from_str(line).map_err(|e| Error::Parse(format!("user list json: {e}")))
}

/// Delete a user on the server and drop it from the local record.
pub async fn delete_user<T: Transport>(
    t: &mut T,
    rec: &mut ServerRecord,
    short_id: &str,
) -> Result<()> {
    if short_id.len() != 16 || !short_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Parse(format!("invalid short_id: {short_id:?}")));
    }
    t.run(&docker::exec_user_rm_cmd(&rec.container, short_id))
        .await?
        .ok()?;
    rec.clients.retain(|c| c.short_id != short_id);
    Ok(())
}

/// Whether the server container is currently running.
pub async fn status<T: Transport>(t: &mut T, rec: &ServerRecord) -> Result<bool> {
    let names = docker::parse_ps_names(&t.run(docker::ps_names_cmd()).await?.stdout);
    Ok(names.iter().any(|n| n == &rec.container))
}

/// Remove the server container (and optionally purge its config dir).
///
/// Best-effort: `docker rm -f` is allowed to fail (the container may not exist
/// when tearing down a half-built server). The purge step, when requested, runs
/// regardless. Only transport-level errors (SSH connection failures, etc.) are
/// propagated via `?`; the remote command's exit code is intentionally ignored.
pub async fn teardown<T: Transport>(t: &mut T, rec: &ServerRecord, purge: bool) -> Result<()> {
    t.run(&format!("sudo docker rm -f {}", rec.container))
        .await?;
    if purge {
        t.run("sudo rm -rf /etc/leshiy").await?;
    }
    Ok(())
}

/// Run `docker exec ... user add` and return captured stdout.
///
/// The `_label` parameter is intentionally unused here: it is stored locally in
/// `ClientConfig.label` by the caller. The remote `leshiy user add` subcommand
/// has no `--label` flag, so we must not pass it on the wire.
async fn exec_user_add<T: Transport>(t: &mut T, container: &str, _label: &str) -> Result<String> {
    let cmd = docker::exec_user_add_cmd(container, "");
    Ok(t.run(&cmd).await?.ok()?.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::{CommandOutput, FakeTransport, SshTarget};
    use crate::vault::SshSecret;

    fn params() -> ProvisionParams {
        ProvisionParams {
            id: "srv1".into(),
            label: "vps".into(),
            target: SshTarget {
                host: "203.0.113.5".into(),
                port: 22,
                user: "root".into(),
            },
            secret: SshSecret::Password("pw".to_string().into()),
            public_host: "203.0.113.5:443".into(),
            dest_sni: "www.microsoft.com:443".into(),
            image_ref: "ghcr.io/x/leshiy:1.5.0".into(),
            container: "leshiy".into(),
            quic_port: None,
            listen_port: 443,
            user_label: "self".into(),
            now: 1_700_000_000,
            role: ProvisionRole::Single,
            connector: None,
            downstream: None,
        }
    }

    fn issued_uri() -> &'static str {
        "leshiy://QUJD@203.0.113.5:443?sni=www.microsoft.com&sid=0102030400000000"
    }

    #[tokio::test]
    async fn provision_happy_path_builds_record_with_first_client() {
        let mut t = FakeTransport::new();
        t.host_key("SHA256:pinme")
            .on(
                super::super::docker::detect_docker_cmd(),
                CommandOutput {
                    code: 0,
                    stdout: "yes".into(),
                    stderr: String::new(),
                },
            )
            .on(
                "docker ps",
                CommandOutput {
                    code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            )
            .on(
                "docker exec",
                CommandOutput {
                    code: 0,
                    stdout: format!("{}\n", issued_uri()),
                    stderr: String::new(),
                },
            );

        let mut events = Vec::new();
        let rec = provision(&mut t, &params(), &mut |e| events.push(e.step))
            .await
            .unwrap();

        assert_eq!(rec.host_key_fp, "SHA256:pinme");
        assert_eq!(rec.clients.len(), 1);
        assert_eq!(rec.clients[0].short_id, "0102030400000000");
        assert_eq!(rec.reality_public_b64, "QUJD");
        assert!(events.contains(&Step::PullImage));
        assert!(events.contains(&Step::Persist));
        // --label must never be sent to the remote command (the server binary
        // has no such flag; label is a local-only annotation).
        assert!(!t.calls().iter().any(|c| c.contains("--label")));
    }

    #[tokio::test]
    async fn provision_skips_install_when_docker_present() {
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 0,
                stdout: format!("{}\n", issued_uri()),
                stderr: String::new(),
            },
        );
        provision(&mut t, &params(), &mut |_| {}).await.unwrap();
        assert!(
            !t.calls()
                .iter()
                .any(|c| c.contains("apt-get") || c.contains("install -y docker"))
        );
    }

    #[tokio::test]
    async fn provision_detects_existing_container_and_skips_run() {
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker ps",
            CommandOutput {
                code: 0,
                stdout: "leshiy\n".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 0,
                stdout: format!("{}\n", issued_uri()),
                stderr: String::new(),
            },
        );
        provision(&mut t, &params(), &mut |_| {}).await.unwrap();
        assert!(!t.calls().iter().any(|c| c.contains("docker run")));
    }

    #[tokio::test]
    async fn provision_fails_when_user_add_errors() {
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 1,
                stdout: String::new(),
                stderr: "boom".into(),
            },
        );
        let err = provision(&mut t, &params(), &mut |_| {}).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Command { .. }));
    }

    #[tokio::test]
    async fn provision_emits_failed_event_on_user_add_error() {
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 1,
                stdout: String::new(),
                stderr: "boom".into(),
            },
        );
        let mut statuses = Vec::new();
        let _ = provision(&mut t, &params(), &mut |e| {
            statuses.push((e.step, e.status))
        })
        .await;
        assert!(
            statuses
                .iter()
                .any(|(s, st)| *s == Step::IssueUser && *st == Status::Failed)
        );
    }

    #[tokio::test]
    async fn provision_failed_event_names_runcontainer_on_run_error() {
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker run",
            CommandOutput {
                code: 1,
                stdout: String::new(),
                stderr: "run failed".into(),
            },
        );
        let mut statuses = Vec::new();
        let _ = provision(&mut t, &params(), &mut |e| {
            statuses.push((e.step, e.status))
        })
        .await;
        assert!(
            statuses
                .iter()
                .any(|(s, st)| *s == Step::RunContainer && *st == Status::Failed)
        );
    }

    #[test]
    fn parse_uri_requires_at_sign() {
        assert!(parse_uri_fields("leshiy://nohost-no-at?sid=01").is_err());
    }

    #[test]
    fn parse_quic_fields_extracts_endpoint() {
        let uri = "leshiy://QUJD@1.2.3.4:443?sni=d&sid=0102030400000000&quic=1.2.3.4:8443&qsni=cdn.example.com&qcert=abc123";
        let q = parse_quic_fields(uri).unwrap();
        assert_eq!(q.addr, "1.2.3.4:8443");
        assert_eq!(q.sni, "cdn.example.com");
        assert_eq!(q.cert_sha256.as_deref(), Some("abc123"));
        assert!(parse_quic_fields("leshiy://QUJD@1.2.3.4:443?sni=d&sid=01").is_none());
    }

    #[tokio::test]
    async fn provision_populates_quic_when_uri_has_it() {
        let mut t = FakeTransport::new();
        let uri = "leshiy://QUJD@1.2.3.4:443?sni=d&sid=0102030400000000&quic=1.2.3.4:8443&qsni=cdn.example.com&qcert=abc123";
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 0,
                stdout: format!("{uri}\n"),
                stderr: String::new(),
            },
        );
        let mut p = params();
        p.quic_port = Some(8443);
        let rec = provision(&mut t, &p, &mut |_| {}).await.unwrap();
        let q = rec.quic.expect("quic populated");
        assert_eq!(q.addr, "1.2.3.4:8443");
    }

    #[tokio::test]
    async fn add_user_appends_client() {
        let mut t = FakeTransport::new();
        t.on(
            "docker exec",
            CommandOutput {
                code: 0,
                stdout: format!("{}\n", issued_uri()),
                stderr: String::new(),
            },
        );
        let mut rec = ServerRecord {
            id: "srv1".into(),
            label: "vps".into(),
            host: "h".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::Password("p".to_string().into()),
            host_key_fp: "fp".into(),
            public_host: "h:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "QUJD".into(),
            quic: None,
            clients: vec![],
            created_at: 0,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
        };
        let cc = add_user(&mut t, &mut rec, "phone", "").await.unwrap();
        assert_eq!(cc.label, "phone");
        assert_eq!(cc.short_id, "0102030400000000");
        assert_eq!(rec.clients.len(), 1);
        // label is stored locally but must NOT be forwarded to the remote command.
        assert!(!t.calls().iter().any(|c| c.contains("--label")));
    }

    #[tokio::test]
    async fn status_true_when_container_listed() {
        let mut t = FakeTransport::new();
        t.on(
            "docker ps",
            CommandOutput {
                code: 0,
                stdout: "leshiy\n".into(),
                stderr: String::new(),
            },
        );
        let rec = ServerRecord {
            id: "s".into(),
            label: "v".into(),
            host: "h".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::None,
            host_key_fp: "fp".into(),
            public_host: "h:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "x".into(),
            quic: None,
            clients: vec![],
            created_at: 0,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
        };
        assert!(status(&mut t, &rec).await.unwrap());
    }

    #[tokio::test]
    async fn teardown_removes_container() {
        let mut t = FakeTransport::new();
        let rec = ServerRecord {
            id: "s".into(),
            label: "v".into(),
            host: "h".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::None,
            host_key_fp: "fp".into(),
            public_host: "h:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "x".into(),
            quic: None,
            clients: vec![],
            created_at: 0,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
        };
        teardown(&mut t, &rec, false).await.unwrap();
        assert!(t.calls().iter().any(|c| c.contains("docker rm -f leshiy")));
    }

    fn rec_with_one_client() -> ServerRecord {
        ServerRecord {
            id: "s".into(),
            label: "v".into(),
            host: "h".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::None,
            host_key_fp: "fp".into(),
            public_host: "h:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "x".into(),
            quic: None,
            clients: vec![ClientConfig {
                short_id: "0102030400000000".into(),
                label: "self".into(),
                uri: "leshiy://x@h:443?sid=0102030400000000".into(),
            }],
            created_at: 0,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
        }
    }

    #[tokio::test]
    async fn list_users_parses_server_json() {
        let mut t = FakeTransport::new();
        t.on("user list --json", CommandOutput {
            code: 0,
            stdout: r#"[{"short_id":"0102030400000000","enabled":true,"used_up":10,"used_down":20},{"short_id":"aabbccdd00000000","enabled":false}]"#.into(),
            stderr: String::new(),
        });
        let rec = rec_with_one_client();
        let users = list_users(&mut t, &rec).await.unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].short_id, "0102030400000000");
        assert!(users[0].enabled);
        assert_eq!(users[0].used_up, 10);
        assert!(!users[1].enabled);
    }

    #[tokio::test]
    async fn delete_user_runs_rm_and_drops_client() {
        let mut t = FakeTransport::new();
        t.on(
            "user rm",
            CommandOutput {
                code: 0,
                stdout: "removed".into(),
                stderr: String::new(),
            },
        );
        let mut rec = rec_with_one_client();
        delete_user(&mut t, &mut rec, "0102030400000000")
            .await
            .unwrap();
        assert!(
            t.calls()
                .iter()
                .any(|c| c.contains("user rm 0102030400000000"))
        );
        assert!(rec.clients.is_empty());
    }

    #[tokio::test]
    async fn delete_user_propagates_rm_error() {
        let mut t = FakeTransport::new();
        t.on(
            "user rm",
            CommandOutput {
                code: 1,
                stdout: String::new(),
                stderr: "no such".into(),
            },
        );
        let mut rec = rec_with_one_client();
        let err = delete_user(&mut t, &mut rec, "0102030400000000")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::Error::Command { .. }));
        // client NOT dropped on failure
        assert_eq!(rec.clients.len(), 1);
    }

    #[tokio::test]
    async fn list_users_bad_json_is_parse_error() {
        let mut t = FakeTransport::new();
        t.on(
            "user list --json",
            CommandOutput {
                code: 0,
                stdout: "not json at all".into(),
                stderr: String::new(),
            },
        );
        let rec = rec_with_one_client();
        let err = list_users(&mut t, &rec).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Parse(_)));
    }

    #[tokio::test]
    async fn delete_user_rejects_non_hex_short_id() {
        let mut t = FakeTransport::new();
        let mut rec = rec_with_one_client();
        let err = delete_user(&mut t, &mut rec, "x; rm -rf /")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::Error::Parse(_)));
        // nothing executed, client retained
        assert!(t.calls().is_empty());
        assert_eq!(rec.clients.len(), 1);
    }

    #[test]
    fn valid_image_ref_accepts_registry_refs_rejects_injection() {
        assert!(valid_image_ref("ghcr.io/leshiy/leshiy:1.5.0"));
        assert!(valid_image_ref("localhost:5000/leshiy@sha256:abc"));
        assert!(!valid_image_ref("img; rm -rf /"));
        assert!(!valid_image_ref("img$(whoami)"));
        assert!(!valid_image_ref("img`whoami`"));
        assert!(!valid_image_ref("img|cat"));
        assert!(!valid_image_ref(""));
    }

    #[tokio::test]
    async fn provision_rejects_bad_image_ref() {
        let mut t = FakeTransport::new();
        let mut p = params();
        p.image_ref = "img; rm -rf /".into();
        let err = provision(&mut t, &p, &mut |_| {}).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Parse(_)));
        assert!(t.calls().is_empty());
    }

    #[tokio::test]
    async fn provision_rejects_bad_container_name() {
        let mut t = FakeTransport::new();
        let mut p = params();
        p.container = "x; reboot".into();
        let err = provision(&mut t, &p, &mut |_| {}).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Parse(_)));
        assert!(t.calls().is_empty());
    }

    #[tokio::test]
    async fn provision_exit_stores_connector_uri() {
        let mut t = FakeTransport::new();
        let uri = "leshiy://QUJD@1.2.3.4:443?sni=d&sid=0102030400000000&quic=1.2.3.4:443&qsni=cdn&qcert=ab";
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 0,
                stdout: format!("{uri}\n"),
                stderr: String::new(),
            },
        );
        let mut p = params();
        p.role = ProvisionRole::Exit;
        p.quic_port = Some(443);
        let rec = provision(&mut t, &p, &mut |_| {}).await.unwrap();
        assert_eq!(rec.role, "exit");
        assert_eq!(rec.connector_uri.as_deref(), Some(uri));
    }

    #[tokio::test]
    async fn provision_entry_sends_connector_env_and_no_connector_uri() {
        let mut t = FakeTransport::new();
        let uri = "leshiy://QUJD@1.2.3.4:443?sni=d&sid=0102030400000000";
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 0,
                stdout: format!("{uri}\n"),
                stderr: String::new(),
            },
        );
        let mut p = params();
        p.role = ProvisionRole::Entry;
        p.connector = Some("leshiy://EXIT@a:443?sni=d&sid=02&quic=a:443&qsni=cdn&qcert=ab".into());
        p.downstream = Some("exit-1".into());
        let rec = provision(&mut t, &p, &mut |_| {}).await.unwrap();
        assert_eq!(rec.role, "entry");
        assert_eq!(rec.downstream.as_deref(), Some("exit-1"));
        assert!(rec.connector_uri.is_none()); // entry exposes no upstream credential
        assert!(t.calls().iter().any(|c| c.contains("LESHIY_CONNECTOR=")));
    }

    #[tokio::test]
    async fn provision_exit_without_quic_uri_fails() {
        let mut t = FakeTransport::new();
        // issued URI has NO quic= endpoint
        let uri = "leshiy://QUJD@1.2.3.4:443?sni=d&sid=0102030400000000";
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "docker exec",
            CommandOutput {
                code: 0,
                stdout: format!("{uri}\n"),
                stderr: String::new(),
            },
        );
        let mut p = params();
        p.role = ProvisionRole::Exit;
        p.quic_port = Some(443);
        let err = provision(&mut t, &p, &mut |_| {}).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Parse(_)));
    }

    #[tokio::test]
    async fn teardown_with_purge_removes_config_dir() {
        let mut t = FakeTransport::new();
        let rec = ServerRecord {
            id: "s".into(),
            label: "v".into(),
            host: "h".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::None,
            host_key_fp: "fp".into(),
            public_host: "h:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "x".into(),
            quic: None,
            clients: vec![],
            created_at: 0,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
        };
        teardown(&mut t, &rec, true).await.unwrap();
        assert!(t.calls().iter().any(|c| c.contains("docker rm -f leshiy")));
        assert!(t.calls().iter().any(|c| c.contains("rm -rf /etc/leshiy")));
    }
}
