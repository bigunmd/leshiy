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
    Firewall,
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
    /// Persist that this server escalates via sudo, so day-2 ops prompt for the
    /// sudo password. The password itself is never stored.
    pub sudo: bool,
    /// Operator override for the container's DNS resolver (`--dns`). When set and
    /// valid it is used verbatim, skipping host detection and the public fallback.
    pub dns_override: Option<String>,
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

    // 3b. Firewall: open the listen port(s) when ufw is active. Best-effort and
    // idempotent — it runs on every provision (including idempotent re-runs, since
    // an unreachable server is a common reason to re-run) and never aborts an
    // otherwise-healthy provision. A firewall we can't manage must not fail the
    // build, but we report the outcome so the operator isn't left guessing about
    // reachability. Runs before the container so the port is open the moment it
    // starts listening.
    *current = Step::Firewall;
    on_event(ev(Step::Firewall, Status::Started, ""));
    let fw_detail = firewall_step(t, p.listen_port, p.quic_port).await;
    on_event(ev(Step::Firewall, Status::Done, fw_detail));

    // 4. Detect existing container (idempotent re-run). `docker ps` lists only RUNNING
    //    containers; a stopped/exited one still owns the name and would collide with
    //    `docker run --name`, so also consult `docker ps -a`. Reuse only a genuinely running
    //    container (the reuse path `docker exec`s into it); a stale stopped one is removed so we
    //    can recreate a working container (the data volume persists, so users/config survive).
    *current = Step::DetectExisting;
    on_event(ev(Step::DetectExisting, Status::Started, ""));
    let running = docker::parse_ps_names(&t.run(docker::ps_names_cmd()).await?.stdout);
    let all = docker::parse_ps_names(&t.run(docker::ps_all_names_cmd()).await?.stdout);
    let running_exists = running.iter().any(|n| n == &p.container);
    let stale = !running_exists && all.iter().any(|n| n == &p.container);
    on_event(ev(
        Step::DetectExisting,
        Status::Done,
        if stale {
            "exists=false (removing a stale stopped container of the same name)".to_string()
        } else {
            format!("exists={running_exists}")
        },
    ));

    // Remove a stale stopped container so `docker run --name` doesn't fail with a name conflict.
    if stale {
        t.run(&docker::container_rm_cmd(&p.container)).await?.ok()?;
    }

    // 5/6. Pull + run (skipped only when reusing a running container).
    if !running_exists {
        *current = Step::PullImage;
        on_event(ev(Step::PullImage, Status::Started, &p.image_ref));
        t.run(&docker::pull_cmd(&p.image_ref)).await?.ok()?;
        on_event(ev(Step::PullImage, Status::Done, ""));

        *current = Step::RunContainer;
        on_event(ev(Step::RunContainer, Status::Started, ""));
        // Compose the container's DNS resolvers so the REALITY server can resolve
        // `dest` from inside the container. Prefer the host's IPv4 upstream (works
        // on clouds that block external DNS), always backed by a public IPv4
        // fallback so an IPv6-only-resolver host still resolves on the IPv4-only
        // bridge (the v1.6.4 outage). An explicit `--dns` override wins outright.
        let host_dns = detect_host_dns(t).await;
        let dns = dns_servers(host_dns, p.dns_override.as_deref());
        let dns_refs: Vec<&str> = dns.iter().map(String::as_str).collect();
        // Publish the container port on the host's IPv6 wildcard too, but only when the host
        // has IPv6 — `-p '[::]:…'` otherwise fails the whole `docker run`. Best-effort: on any
        // probe hiccup we skip the v6 publish (v4 still works).
        let publish_v6 = matches!(
            t.run(docker::detect_host_ipv6_cmd()).await,
            Ok(o) if o.stdout.trim() == "yes"
        );
        // Bind dual-stack (`[::]`) so the server accepts both IPv4 (v4-mapped) and IPv6 clients
        // on one socket — but only when the host has IPv6, since binding `[::]` fails inside the
        // container on a kernel with IPv6 disabled (same kernel as the host). Fall back to
        // `0.0.0.0` there.
        let listen_host = if publish_v6 { "[::]" } else { "0.0.0.0" };
        let mut envs = vec![
            ("LESHIY_HOST".to_string(), p.public_host.clone()),
            ("LESHIY_DEST".to_string(), p.dest_sni.clone()),
            (
                "LESHIY_LISTEN".to_string(),
                format!("{listen_host}:{}", p.listen_port),
            ),
        ];
        if let Some(q) = p.quic_port {
            envs.push((
                "LESHIY_QUIC_LISTEN".to_string(),
                format!("{listen_host}:{q}"),
            ));
        }
        if let Some(conn) = &p.connector {
            envs.push(("LESHIY_CONNECTOR".to_string(), conn.clone()));
        }
        t.run(&docker::run_cmd(
            &p.container,
            &p.image_ref,
            p.listen_port,
            p.quic_port,
            publish_v6,
            &dns_refs,
            &envs,
        ))
        .await?
        .ok()?;
        on_event(ev(
            Step::RunContainer,
            Status::Done,
            format!("dns={}", dns.join(",")),
        ));
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
        sudo: p.sudo,
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
        // Remove the persistent data volume (server identity + config) so a
        // subsequent provision regenerates from scratch — the container's `boot`
        // skips config generation whenever server.toml already exists on the
        // volume, so a surviving volume silently reuses the old dest/keys.
        t.run(&docker::volume_rm_cmd()).await?;
        // Also clear the native/install.sh bind-mount path, harmless for the
        // docker path (nonexistent → no-op).
        t.run("sudo rm -rf /etc/leshiy").await?;
    }
    Ok(())
}

/// Detect a container-usable **IPv4** DNS server on the host (the real upstream,
/// never a loopback stub). Returns `None` when nothing usable is found or on any
/// transport hiccup — [`dns_servers`] then relies on the public fallback. The
/// result is validated as a bare IP literal before it can reach a shell.
async fn detect_host_dns<T: Transport>(t: &mut T) -> Option<String> {
    let out = t.run(docker::detect_host_dns_cmd()).await.ok()?;
    let candidate = out.stdout.trim();
    if docker::valid_dns_addr(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

/// Compose the ordered `--dns` list Docker will try in order.
///
/// - A valid explicit operator override wins outright (no fallback appended).
/// - Otherwise the host's detected IPv4 resolver (if any) leads, always backed by
///   the public IPv4 fallback(s) so resolution works even when the host has no
///   container-usable IPv4 resolver (an IPv6-only `resolv.conf` on the IPv4-only
///   bridge — the v1.6.4 outage).
fn dns_servers(host_ipv4: Option<String>, override_dns: Option<&str>) -> Vec<String> {
    if let Some(o) = override_dns
        && docker::valid_dns_addr(o)
    {
        return vec![o.to_string()];
    }
    let mut list = Vec::new();
    list.extend(host_ipv4);
    list.extend(docker::DNS_PUBLIC_FALLBACK.iter().map(|s| s.to_string()));
    list
}

/// Detect ufw and, when it is active, open the listen (and QUIC) port(s).
///
/// Returns a human-readable detail describing what happened. Best-effort: any
/// error (ufw absent, transport hiccup, or the `ufw allow` itself failing) is
/// folded into the returned detail rather than propagated, so a firewall we
/// can't manage never aborts an otherwise-successful provision.
async fn firewall_step<T: Transport>(
    t: &mut T,
    listen_port: u16,
    quic_port: Option<u16>,
) -> String {
    let active = match t.run(docker::detect_ufw_active_cmd()).await {
        Ok(out) => out.stdout.trim() == "active",
        // A transport-level failure here isn't fatal to firewalling; if the SSH
        // channel is truly dead the next real step's `?` will surface it.
        Err(e) => return format!("firewall check skipped ({e})"),
    };
    if !active {
        return "ufw inactive or not installed — left unchanged".to_string();
    }
    let ports = match quic_port {
        Some(q) => format!("{listen_port}/tcp, {q}/udp"),
        None => format!("{listen_port}/tcp"),
    };
    match t.run(&docker::ufw_allow_cmd(listen_port, quic_port)).await {
        Ok(out) if out.code == 0 => format!("ufw active — opened {ports}"),
        Ok(out) => format!(
            "ufw active but opening {ports} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ),
        Err(e) => format!("ufw active but opening {ports} failed ({e})"),
    }
}

/// A freshly `docker run` server takes a moment to generate its config and bind
/// its control socket. `user add` issued too early fails with "connect to control
/// socket … is the server running?". Bound the wait so a genuinely-broken boot
/// still fails in reasonable time.
const USER_ADD_ATTEMPTS: usize = 15;
const USER_ADD_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Whether a `user add` failure is the transient "server not up yet" race
/// (control socket missing) rather than a genuine error. Only these are retried,
/// so a real misconfiguration fails fast instead of spinning for the full budget.
fn is_control_socket_unready(stderr: &str) -> bool {
    stderr.contains("control socket") || stderr.contains("is the server running")
}

/// Run `docker exec ... user add` and return captured stdout, retrying while the
/// server's control socket is not yet up (fresh-container startup race).
///
/// The `_label` parameter is intentionally unused here: it is stored locally in
/// `ClientConfig.label` by the caller. The remote `leshiy user add` subcommand
/// has no `--label` flag, so we must not pass it on the wire.
async fn exec_user_add<T: Transport>(t: &mut T, container: &str, _label: &str) -> Result<String> {
    let cmd = docker::exec_user_add_cmd(container, "");
    let mut last_err = None;
    for attempt in 0..USER_ADD_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(USER_ADD_RETRY_DELAY).await;
        }
        // A transport-level error (`?`) is not retried — a dead SSH channel won't
        // heal. Only a command failure whose stderr is the control-socket race is.
        match t.run(&cmd).await?.ok() {
            Ok(out) => return Ok(out.stdout),
            Err(e) => {
                let transient = matches!(&e, Error::Command { stderr, .. } if is_control_socket_unready(stderr));
                if !transient {
                    return Err(e);
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("loop body runs at least once"))
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
            sudo: false,
            dns_override: None,
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

    #[test]
    fn control_socket_unready_recognizes_the_startup_race() {
        assert!(is_control_socket_unready(
            "error: connect to control socket \"/etc/leshiy/leshiy.sock\" — is the server running?"
        ));
        assert!(is_control_socket_unready(
            "connect to control socket failed"
        ));
        assert!(!is_control_socket_unready("error: invalid dest"));
        assert!(!is_control_socket_unready("boom"));
    }

    #[tokio::test(start_paused = true)]
    async fn provision_retries_user_add_until_control_socket_ready() {
        // First `user add` races the not-yet-bound control socket; the second
        // succeeds. `start_paused` makes the retry delay instant.
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on_seq(
            "docker exec",
            vec![
                CommandOutput {
                    code: 1,
                    stdout: String::new(),
                    stderr: "error: connect to control socket \"/etc/leshiy/leshiy.sock\" — is the server running?\n  caused by: No such file or directory".into(),
                },
                CommandOutput {
                    code: 0,
                    stdout: format!("{}\n", issued_uri()),
                    stderr: String::new(),
                },
            ],
        );
        let rec = provision(&mut t, &params(), &mut |_| {}).await.unwrap();
        assert_eq!(rec.clients.len(), 1);
        let execs = t
            .calls()
            .iter()
            .filter(|c| c.contains("docker exec"))
            .count();
        assert_eq!(
            execs, 2,
            "must retry the socket race exactly once then succeed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn provision_does_not_retry_non_socket_user_add_errors() {
        // A genuine (non-race) failure must fail immediately, not spin for the
        // whole retry budget.
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
                stderr: "error: some real failure".into(),
            },
        );
        let err = provision(&mut t, &params(), &mut |_| {}).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Command { .. }));
        let execs = t
            .calls()
            .iter()
            .filter(|c| c.contains("docker exec"))
            .count();
        assert_eq!(execs, 1, "non-transient error must not retry");
    }

    #[tokio::test]
    async fn provision_passes_host_dns_to_docker_run() {
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
            "systemd/resolve/resolv.conf",
            CommandOutput {
                code: 0,
                stdout: "10.130.0.2\n".into(),
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
        // The detected host resolver leads, always backed by the public fallback.
        assert!(
            t.calls().iter().any(|c| c.contains("docker run")
                && c.contains("--dns 10.130.0.2")
                && c.contains("--dns 1.1.1.1")),
            "docker run must carry the detected host resolver and a public fallback"
        );
    }

    #[tokio::test]
    async fn provision_falls_back_to_public_dns_when_host_has_no_resolver() {
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        // DNS probe returns empty (host resolv.conf is IPv6-only or loopback-only,
        // the v1.6.4 incident) → the container still gets a public IPv4 fallback so
        // it can resolve `dest` on the IPv4-only bridge.
        .on(
            "systemd/resolve/resolv.conf",
            CommandOutput {
                code: 0,
                stdout: "\n".into(),
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
            t.calls()
                .iter()
                .any(|c| c.contains("docker run") && c.contains("--dns 1.1.1.1")),
            "docker run must carry the public DNS fallback when the host has none"
        );
    }

    #[tokio::test]
    async fn provision_dns_override_wins_and_skips_fallback() {
        let mut t = FakeTransport::new();
        let mut p = params();
        p.dns_override = Some("9.9.9.9".into());
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
        provision(&mut t, &p, &mut |_| {}).await.unwrap();
        assert!(
            t.calls()
                .iter()
                .any(|c| c.contains("docker run") && c.contains("--dns 9.9.9.9")),
            "an explicit --dns override must be used"
        );
        // The override is authoritative — no fallback is appended.
        assert!(!t.calls().iter().any(|c| c.contains("--dns 1.1.1.1")));
    }

    #[tokio::test]
    async fn provision_binds_and_publishes_dual_stack_when_host_has_ipv6() {
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
            "if_inet6", // the host-IPv6 probe reads /proc/net/if_inet6
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
        let run = t
            .calls()
            .into_iter()
            .find(|c| c.contains("docker run"))
            .expect("a docker run");
        assert!(run.contains("-p '[::]:443:443'"), "v6 publish: {run}");
        assert!(
            run.contains("LESHIY_LISTEN='[::]:443'"),
            "dual-stack bind: {run}"
        );
    }

    #[tokio::test]
    async fn provision_stays_v4_only_when_host_has_no_ipv6() {
        let mut t = FakeTransport::new();
        // detect_host_ipv6 is not mocked → empty → treated as no IPv6.
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
        let run = t
            .calls()
            .into_iter()
            .find(|c| c.contains("docker run"))
            .expect("a docker run");
        assert!(!run.contains("[::]"), "must stay IPv4-only: {run}");
        assert!(
            run.contains("LESHIY_LISTEN='0.0.0.0:443'"),
            "v4 bind: {run}"
        );
    }

    #[test]
    fn dns_servers_prefers_host_then_fallback() {
        let list = dns_servers(Some("10.0.0.1".to_string()), None);
        assert_eq!(list[0], "10.0.0.1");
        assert!(list[1..].contains(&"1.1.1.1".to_string()));
    }

    #[test]
    fn dns_servers_uses_only_fallback_when_no_host() {
        let list = dns_servers(None, None);
        assert_eq!(list, docker::DNS_PUBLIC_FALLBACK);
    }

    #[test]
    fn dns_servers_override_wins() {
        assert_eq!(
            dns_servers(Some("10.0.0.1".to_string()), Some("9.9.9.9")),
            vec!["9.9.9.9".to_string()]
        );
    }

    #[test]
    fn dns_servers_ignores_invalid_override() {
        // A garbage override (shell metachars) is dropped; we fall back to the
        // safe host+public list rather than splice something dangerous.
        let list = dns_servers(Some("10.0.0.1".to_string()), Some("bad; rm -rf /"));
        assert_eq!(list[0], "10.0.0.1");
        assert!(list.iter().all(|s| s != "bad; rm -rf /"));
    }

    #[tokio::test]
    async fn provision_opens_firewall_when_ufw_active() {
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
            "ufw status",
            CommandOutput {
                code: 0,
                stdout: "active".into(),
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
        let mut statuses = Vec::new();
        provision(&mut t, &params(), &mut |e| {
            statuses.push((e.step, e.status))
        })
        .await
        .unwrap();
        // ufw active → the listen port is opened.
        assert!(
            t.calls().iter().any(|c| c.contains("ufw allow 443/tcp")),
            "expected a ufw allow for the listen port"
        );
        assert!(
            statuses
                .iter()
                .any(|(s, st)| *s == Step::Firewall && *st == Status::Done)
        );
    }

    #[tokio::test]
    async fn provision_skips_firewall_when_ufw_inactive() {
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
            "ufw status",
            CommandOutput {
                code: 0,
                stdout: "inactive".into(),
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
        // ufw inactive → leave the firewall untouched.
        assert!(!t.calls().iter().any(|c| c.contains("ufw allow")));
    }

    #[tokio::test]
    async fn provision_opens_quic_udp_port_when_ufw_active_and_quic_set() {
        let mut t = FakeTransport::new();
        let uri = "leshiy://QUJD@1.2.3.4:443?sni=d&sid=0102030400000000&quic=1.2.3.4:8443&qsni=cdn&qcert=abc";
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        .on(
            "ufw status",
            CommandOutput {
                code: 0,
                stdout: "active".into(),
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
        provision(&mut t, &p, &mut |_| {}).await.unwrap();
        assert!(t.calls().iter().any(|c| c.contains("ufw allow 8443/udp")));
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
    async fn provision_removes_stale_stopped_container_before_run() {
        // A container named `leshiy` exists but is STOPPED: `docker ps` (running) does not list
        // it, while `docker ps -a` (all) does. `docker run --name` would collide with it, so
        // provision must force-remove the stale container first, then recreate.
        let mut t = FakeTransport::new();
        t.on(
            super::super::docker::detect_docker_cmd(),
            CommandOutput {
                code: 0,
                stdout: "yes".into(),
                stderr: String::new(),
            },
        )
        // Most-specific first: `docker ps -a` lists the stopped container...
        .on(
            "docker ps -a",
            CommandOutput {
                code: 0,
                stdout: "leshiy\n".into(),
                stderr: String::new(),
            },
        )
        // ...while `docker ps` (running only) is empty.
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
        provision(&mut t, &params(), &mut |_| {}).await.unwrap();
        let calls = t.calls();
        // The stale container is force-removed before a fresh one is created.
        let rm = calls
            .iter()
            .position(|c| c.contains("docker rm -f") && c.contains("leshiy"));
        let run = calls.iter().position(|c| c.contains("docker run"));
        assert!(
            rm.is_some(),
            "expected stale container removal; calls: {calls:?}"
        );
        assert!(
            run.is_some(),
            "expected a fresh docker run; calls: {calls:?}"
        );
        assert!(
            rm < run,
            "stale removal must precede docker run; calls: {calls:?}"
        );
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
            sudo: false,
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
            sudo: false,
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
            sudo: false,
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
            sudo: false,
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
            sudo: false,
        };
        teardown(&mut t, &rec, true).await.unwrap();
        assert!(t.calls().iter().any(|c| c.contains("docker rm -f leshiy")));
        assert!(
            t.calls()
                .iter()
                .any(|c| c.contains("docker volume rm leshiy-data"))
        );
        assert!(t.calls().iter().any(|c| c.contains("rm -rf /etc/leshiy")));
    }
}
