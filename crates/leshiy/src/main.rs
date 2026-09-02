mod cli;
mod client;
mod client_wizard;
mod elevate;
mod host;
mod lifecycle;
mod quickstart;
mod reality_config;
mod remote_cli;
mod remote_wizard;
mod sdnotify;
mod server;
mod server_wizard;
mod service;
mod signals;
mod tun;
mod ui;
mod user_cli;
mod vpn;
mod wizard;

use clap::Parser;

/// Format an anyhow error as `error: <top>` + an indented `caused by:` chain.
fn render_error(e: &anyhow::Error) -> String {
    use std::fmt::Write;
    let color = ui::color_stderr();
    let mut s = format!(
        "{} {}",
        ui::paint("error:", anstyle::AnsiColor::Red.on_default().bold(), color),
        e
    );
    for cause in e.chain().skip(1) {
        let _ = write!(s, "\n  {} {cause}", ui::label("caused by:"));
    }
    s
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            ui::eline(&render_error(&e));
            std::process::ExitCode::FAILURE
        }
    }
}

/// Resolve a server-side plan from flags, asking for the rest when `-i` is set.
async fn server_plan(
    flags: server_wizard::ServerFlags,
    mode: server_wizard::ServerMode,
    interactive: bool,
) -> anyhow::Result<server_wizard::ServerPlan> {
    if interactive {
        wizard::require_tty()?;
        server_wizard::plan_interactively(flags, mode).await
    } else {
        server_wizard::plan_from_flags(flags, mode)
    }
}

/// Resolve a client-side plan from flags, asking for the rest when `-i` is set.
fn client_plan(
    flags: client_wizard::ClientFlags,
    mode: client_wizard::Mode,
    interactive: bool,
) -> anyhow::Result<client_wizard::ClientPlan> {
    if interactive {
        wizard::require_tty()?;
        client_wizard::plan_interactively(flags, mode)
    } else {
        client_wizard::plan_from_flags(flags, mode)
    }
}

/// Gain root for a full tunnel.
///
/// The interactive path cannot replay this process's argv — it still contains `-i`, so the
/// elevated child would re-open the wizard after the sudo prompt. It re-execs the resolved
/// flags instead, passing the URI as a 0600 file because a bearer credential in argv is
/// readable by every local user through `ps`.
async fn elevate_for_tunnel(
    plan: &client_wizard::ClientPlan,
    mode: client_wizard::Mode,
    interactive: bool,
    already_elevated: bool,
) -> anyhow::Result<Option<std::process::ExitCode>> {
    if !interactive {
        return elevate::ensure_root(already_elevated).await;
    }
    if elevate::have_privileges() || already_elevated {
        return Ok(None);
    }
    let cred = client_wizard::CredentialHandoff::new(&plan.uri)?;
    let args = client_wizard::elevated_args(plan, mode, cred.path());
    elevate::ensure_root_with_args(already_elevated, args).await
}

/// Execute a resolved plan in whichever mode was chosen.
///
/// One runner for all five entry points, because `connect -i` can route to any of them:
/// the mode the operator picked, not the subcommand they typed, decides what runs.
/// `Some(code)` means the work was handed to an elevated re-exec that has already finished.
async fn run_client_plan(
    plan: client_wizard::ClientPlan,
    mode: client_wizard::Mode,
    interactive: bool,
    already_elevated: bool,
) -> anyhow::Result<Option<std::process::ExitCode>> {
    use client_wizard::Mode;
    match mode {
        Mode::Proxy | Mode::Connect => {
            client::run(&plan.uri, &plan.socks_or_default(), plan.transport).await?
        }
        Mode::Tun => {
            // Elevate before anything touches the network, so a password prompt cannot
            // appear midway through bringing a tunnel up.
            if let Some(code) =
                elevate_for_tunnel(&plan, mode, interactive, already_elevated).await?
            {
                return Ok(Some(code));
            }
            tun::run(
                &plan.uri,
                plan.transport,
                plan.mtu,
                &plan.tun_name,
                &plan.dns,
                plan.ipv6,
                plan.socks.as_deref(),
            )
            .await?
        }
        Mode::Vpn => {
            vpn::run(
                &plan.uri,
                plan.transport,
                plan.mtu,
                &plan.tun_name,
                &plan.dns,
                &plan.socket,
                plan.ipv6,
            )
            .await?
        }
        Mode::Service { tun } => {
            // Interactively the wizard already warned and asked to confirm.
            if tun && plan.transport != cli::Transport::Tcp && !interactive {
                ui::warn(
                    "a full tunnel needs UDP and ICMP, which only --transport tcp \
                     carries today; DNS and ping will not work inside the tunnel",
                );
            }
            // A system unit writes to /etc and drives `systemctl` without --user, so it
            // needs root just as the tunnel itself does.
            if tun
                && let Some(code) =
                    elevate_for_tunnel(&plan, mode, interactive, already_elevated).await?
            {
                return Ok(Some(code));
            }
            service::start(&service::StartOpts {
                uri: &plan.uri,
                transport: plan.transport.as_flag(),
                socks: plan.socks.as_deref(),
                tun,
                tun_name: &plan.tun_name,
                dns: &plan.dns,
                mtu: plan.mtu,
                ipv6: plan.ipv6,
            })?
        }
    }
    Ok(None)
}

async fn run() -> anyhow::Result<std::process::ExitCode> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "leshiy=info".into()),
        )
        .init();
    let cli = cli::Cli::parse();
    let already_elevated = cli.already_elevated;
    match cli.cmd {
        cli::Cmd::Keygen => {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            use std::io::IsTerminal;
            let kp = leshiy_core::handshake::generate_keypair()?;
            println!(
                "{} {}",
                ui::label("public: "),
                URL_SAFE_NO_PAD.encode(&kp.public)
            );
            println!(
                "{} {}",
                ui::label("private:"),
                URL_SAFE_NO_PAD.encode(&*kp.private)
            );
            if std::io::stdout().is_terminal() {
                ui::warn(
                    "the 'private' line is SECRET — do not share, log, screenshot, or commit it.",
                );
            } else {
                ui::warn(
                    "a SECRET private key was written to redirected output — restrict it (chmod 600).",
                );
            }
        }
        cli::Cmd::ServerInit {
            host,
            dest,
            interactive,
            listen,
            out,
            quic_listen,
            quic_domain,
            quic_cert,
            quic_key,
            connector,
        } => {
            let plan = server_plan(
                server_wizard::ServerFlags {
                    host,
                    dest,
                    listen,
                    // `server-init`'s --out is still a defaulted String, so it is always
                    // "given"; only the wizard-facing commands needed the tri-state.
                    out: Some(out),
                    quic_listen,
                    // One field, two spellings: --quic-domain here, --quic-sni on
                    // quickstart. Both name the SNI on the QUIC endpoint.
                    quic_sni: quic_domain,
                    quic_cert,
                    quic_key,
                    // `server-init` has no --role; carrying a downstream credential is
                    // what makes it an entry.
                    role: connector.as_ref().map(|_| cli::Role::Entry),
                    exit_uri: connector,
                    no_probe: true,
                },
                server_wizard::ServerMode::Init,
                interactive,
            )
            .await?;
            server::init(server::InitOptions {
                host: &plan.host,
                dest: &plan.dest,
                listen: plan.listen.as_deref(),
                out: &plan.out,
                quic_listen: plan.quic_listen.as_deref(),
                quic_domain: plan.quic_sni.as_deref(),
                quic_cert: plan.quic_cert.as_deref(),
                quic_key: plan.quic_key.as_deref(),
                connector: plan.exit_uri.as_deref(),
            })?;
        }
        cli::Cmd::Quickstart {
            host,
            dest,
            interactive,
            out,
            listen,
            quic_listen,
            quic_sni,
            no_probe,
            summary_json,
            role,
            exit_uri,
        } => {
            let plan = server_plan(
                server_wizard::ServerFlags {
                    host,
                    dest,
                    listen,
                    out,
                    quic_listen,
                    quic_sni,
                    quic_cert: None,
                    quic_key: None,
                    role,
                    exit_uri,
                    no_probe,
                },
                server_wizard::ServerMode::Quickstart,
                interactive,
            )
            .await?;
            quickstart::run(quickstart::QuickstartOpts {
                host: &plan.host,
                dest: &plan.dest,
                out: &plan.out,
                listen: plan.listen.as_deref(),
                quic_listen: plan.quic_listen.as_deref(),
                quic_sni: plan.quic_sni.as_deref(),
                // The wizard already probed the dest and made the operator confirm it, so
                // re-probing here would only cost a second round trip to the same site.
                no_probe: plan.no_probe || interactive,
                summary_json,
                role: plan.role,
                exit_uri: plan.exit_uri.as_deref(),
            })
            .await?
        }
        cli::Cmd::Server { config } => server::run(&config).await?,
        cli::Cmd::Client {
            uri,
            uri_file,
            socks,
            transport,
            interactive,
        } => {
            let plan = client_plan(
                client_wizard::ClientFlags {
                    uri,
                    uri_file,
                    socks,
                    transport,
                    ..Default::default()
                },
                client_wizard::Mode::Proxy,
                interactive,
            )?;
            if let Some(code) = run_client_plan(
                plan,
                client_wizard::Mode::Proxy,
                interactive,
                already_elevated,
            )
            .await?
            {
                return Ok(code);
            }
        }
        cli::Cmd::Connect {
            uri,
            socks,
            transport,
            interactive,
        } => {
            // The one entry point that does not assume a mode: `connect -i` is where
            // someone lands before they know `tun`, `vpn` and `service` are different
            // things, so it asks, then runs whichever they picked.
            let mode = if interactive {
                wizard::require_tty()?;
                client_wizard::pick_mode()?
            } else {
                client_wizard::Mode::Connect
            };
            let plan = client_plan(
                client_wizard::ClientFlags {
                    uri,
                    socks,
                    transport,
                    ..Default::default()
                },
                mode,
                interactive,
            )?;
            if let Some(code) = run_client_plan(plan, mode, interactive, already_elevated).await? {
                return Ok(code);
            }
        }
        cli::Cmd::Tun {
            uri,
            uri_file,
            transport,
            mtu,
            tun_name,
            dns,
            ipv6,
            socks,
            interactive,
        } => {
            let plan = client_plan(
                client_wizard::ClientFlags {
                    uri,
                    uri_file,
                    transport,
                    socks,
                    mtu,
                    tun_name,
                    dns,
                    ipv6,
                    ..Default::default()
                },
                client_wizard::Mode::Tun,
                interactive,
            )?;
            if let Some(code) = run_client_plan(
                plan,
                client_wizard::Mode::Tun,
                interactive,
                already_elevated,
            )
            .await?
            {
                return Ok(code);
            }
        }
        cli::Cmd::Vpn {
            uri,
            transport,
            mtu,
            tun_name,
            dns,
            socket,
            ipv6,
            interactive,
        } => {
            let plan = client_plan(
                client_wizard::ClientFlags {
                    uri,
                    transport,
                    mtu,
                    tun_name,
                    dns,
                    socket,
                    ipv6,
                    ..Default::default()
                },
                client_wizard::Mode::Vpn,
                interactive,
            )?;
            if let Some(code) = run_client_plan(
                plan,
                client_wizard::Mode::Vpn,
                interactive,
                already_elevated,
            )
            .await?
            {
                return Ok(code);
            }
        }
        cli::Cmd::User { cmd } => user_cli::run(cmd).await?,
        cli::Cmd::Status { config } => {
            lifecycle::status(&config, &host::RealHostOps)?;
        }
        cli::Cmd::Uninstall { config, purge } => {
            lifecycle::uninstall(&config, purge, &host::RealHostOps)?
        }
        cli::Cmd::Upgrade { repo, version } => {
            let v = match version {
                Some(v) => v,
                None => lifecycle::latest_version(&repo)?,
            };
            lifecycle::upgrade(&repo, &v, &host::RealHostOps)?
        }
        cli::Cmd::Update {
            repo,
            version,
            force,
        } => {
            let v = match version {
                Some(v) => v,
                None => lifecycle::latest_version(&repo)?,
            };
            let dest = lifecycle::self_path()?;
            lifecycle::update(&repo, &v, &dest, force, &host::RealHostOps)?
        }
        cli::Cmd::Remote { cmd, interactive } => remote_cli::run(cmd, interactive).await?,
        cli::Cmd::Service { cmd, interactive } => match cmd {
            cli::ServiceCmd::Start {
                uri,
                uri_file,
                transport,
                socks,
                tun,
                tun_name,
                dns,
                mtu,
                ipv6,
                no_socks,
            } => {
                if interactive {
                    wizard::require_tty()?;
                }
                // `--tun` decides the unit's scope, so it has to be settled before the
                // wizard can ask scope-dependent questions.
                let tun = tun
                    || (interactive
                        && wizard::confirm(
                            "Route the whole device (full tunnel, needs root)?",
                            false,
                        )?);
                let mode = client_wizard::Mode::Service { tun };
                let plan = client_plan(
                    client_wizard::ClientFlags {
                        uri,
                        uri_file,
                        transport,
                        socks,
                        no_socks,
                        mtu,
                        tun_name,
                        dns,
                        ipv6,
                        ..Default::default()
                    },
                    mode,
                    interactive,
                )?;
                if let Some(code) =
                    run_client_plan(plan, mode, interactive, already_elevated).await?
                {
                    return Ok(code);
                }
            }
            cli::ServiceCmd::Stop => {
                // Stopping a system unit is polkit-gated, so escalate first rather than
                // let systemctl fail with "Interactive authentication required".
                if service::stop_needs_root()?
                    && let Some(code) = elevate::ensure_root(already_elevated).await?
                {
                    return Ok(code);
                }
                service::stop()?
            }
            cli::ServiceCmd::Status => service::status()?,
            cli::ServiceCmd::Logs { follow } => {
                let follow = follow
                    || (interactive && {
                        wizard::require_tty()?;
                        wizard::confirm("Follow the log as it grows?", true)?
                    });
                service::logs(follow)?
            }
        },
        cli::Cmd::Boot => server::boot().await?,
    }
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    #[test]
    fn render_error_shows_message_and_cause_chain() {
        let base = anyhow::anyhow!("socket missing");
        let wrapped = base.context("connect to control socket");
        let out = super::render_error(&wrapped);
        assert!(out.contains("error:"));
        assert!(out.contains("connect to control socket"));
        assert!(out.contains("socket missing"));
    }
}
