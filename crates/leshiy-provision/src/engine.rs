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
    pub reality_port: u16,
    pub user_label: String,
    pub now: u64,
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
    let pub_b64 = rest
        .split('@')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Parse("no pubkey".into()))?
        .to_string();
    let sid = uri
        .split("sid=")
        .nth(1)
        .map(|s| s.split(['&', ' ', '\n']).next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Parse("no sid".into()))?;
    Ok((sid, pub_b64))
}

/// Provision `target` into a running leshiy server and return its record.
pub async fn provision<T: Transport>(
    t: &mut T,
    p: &ProvisionParams,
    on_event: &mut dyn FnMut(ProgressEvent),
) -> Result<ServerRecord> {
    // 1. Connect + TOFU pin.
    on_event(ev(Step::Connect, Status::Started, &p.target.host));
    let host_key_fp = t.connect(&p.target, &p.secret).await?;
    on_event(ev(Step::Connect, Status::Done, &host_key_fp));

    // 2. Preflight + 3. Docker ready.
    on_event(ev(Step::Preflight, Status::Started, ""));
    let has_docker = t.run(docker::detect_docker_cmd()).await?.stdout.trim() == "yes";
    on_event(ev(
        Step::Preflight,
        Status::Done,
        format!("docker={has_docker}"),
    ));

    on_event(ev(Step::DockerReady, Status::Started, ""));
    if !has_docker {
        t.run(docker::install_docker_cmd()).await?.ok()?;
    }
    on_event(ev(Step::DockerReady, Status::Done, ""));

    // 4. Detect existing container (idempotent re-run).
    on_event(ev(Step::DetectExisting, Status::Started, ""));
    let names = docker::parse_ps_names(&t.run(docker::ps_names_cmd()).await?.stdout);
    let exists = names.iter().any(|n| n == &p.container);
    on_event(ev(
        Step::DetectExisting,
        Status::Done,
        format!("exists={exists}"),
    ));

    // 5. Pull + 6. Run (skipped if already running).
    if !exists {
        on_event(ev(Step::PullImage, Status::Started, &p.image_ref));
        t.run(&docker::pull_cmd(&p.image_ref)).await?.ok()?;
        on_event(ev(Step::PullImage, Status::Done, ""));

        on_event(ev(Step::RunContainer, Status::Started, ""));
        t.run(&docker::run_cmd(
            &p.container,
            &p.image_ref,
            p.reality_port,
            p.quic_port,
        ))
        .await?
        .ok()?;
        on_event(ev(Step::RunContainer, Status::Done, ""));
    } else {
        on_event(ev(
            Step::PullImage,
            Status::Done,
            "reusing existing container",
        ));
    }

    // 7. Issue the first user.
    on_event(ev(Step::IssueUser, Status::Started, &p.user_label));
    let add = exec_user_add(t, &p.container, &p.user_label).await?;
    let uri = add.trim().lines().next().unwrap_or("").to_string();
    let (short_id, reality_public_b64) = parse_uri_fields(&uri)?;
    on_event(ev(Step::IssueUser, Status::Done, &short_id));

    // 8. Build the record.
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
        quic: None,
        clients: vec![ClientConfig {
            short_id,
            label: p.user_label.clone(),
            uri,
        }],
        created_at: p.now,
    };
    on_event(ev(Step::Persist, Status::Done, &rec.id));
    Ok(rec)
}

/// Run `docker exec ... user add` and return captured stdout.
async fn exec_user_add<T: Transport>(t: &mut T, container: &str, label: &str) -> Result<String> {
    let cmd = docker::exec_user_add_cmd(container, &format!("--label {label}"));
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
            image_ref: "ghcr.io/x/leshiy:1.4.0".into(),
            container: "leshiy".into(),
            quic_port: None,
            reality_port: 443,
            user_label: "self".into(),
            now: 1_700_000_000,
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
}
