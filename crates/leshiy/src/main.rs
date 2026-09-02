mod cli;
mod client;
mod elevate;
mod host;
mod lifecycle;
mod quickstart;
mod reality_config;
mod remote_cli;
mod sdnotify;
mod server;
mod service;
mod signals;
mod tun;
mod ui;
mod user_cli;
mod vpn;

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
            listen,
            out,
            quic_listen,
            quic_domain,
            quic_cert,
            quic_key,
            connector,
        } => {
            server::init(server::InitOptions {
                host: &host,
                dest: &dest,
                listen: listen.as_deref(),
                out: &out,
                quic_listen: quic_listen.as_deref(),
                quic_domain: quic_domain.as_deref(),
                quic_cert: quic_cert.as_deref(),
                quic_key: quic_key.as_deref(),
                connector: connector.as_deref(),
            })?;
        }
        cli::Cmd::Quickstart {
            host,
            dest,
            out,
            listen,
            quic_listen,
            quic_sni,
            no_probe,
            summary_json,
            role,
            exit_uri,
        } => {
            quickstart::run(quickstart::QuickstartOpts {
                host: &host,
                dest: &dest,
                out: &out,
                listen: listen.as_deref(),
                quic_listen: quic_listen.as_deref(),
                quic_sni: quic_sni.as_deref(),
                no_probe,
                summary_json,
                role,
                exit_uri: exit_uri.as_deref(),
            })
            .await?
        }
        cli::Cmd::Server { config } => server::run(&config).await?,
        cli::Cmd::Client {
            uri,
            uri_file,
            socks,
            transport,
        } => {
            let uri = service::resolve_uri(uri.as_deref(), uri_file.as_deref())?;
            client::run(&uri, &socks, transport).await?
        }
        cli::Cmd::Connect {
            uri,
            socks,
            transport,
        } => client::run(&uri, &socks, transport).await?,
        cli::Cmd::Tun {
            uri,
            uri_file,
            transport,
            mtu,
            tun_name,
            dns,
            ipv6,
            socks,
        } => {
            let uri = service::resolve_uri(uri.as_deref(), uri_file.as_deref())?;
            // Elevate before anything touches the network, so a password prompt cannot
            // appear midway through bringing a tunnel up.
            if let Some(code) = elevate::ensure_root(already_elevated).await? {
                return Ok(code);
            }
            tun::run(
                &uri,
                transport,
                mtu,
                &tun_name,
                &dns,
                ipv6,
                socks.as_deref(),
            )
            .await?
        }
        cli::Cmd::Vpn {
            uri,
            transport,
            mtu,
            tun_name,
            dns,
            socket,
            ipv6,
        } => vpn::run(&uri, transport, mtu, &tun_name, &dns, &socket, ipv6).await?,
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
        cli::Cmd::Remote { cmd } => remote_cli::run(cmd).await?,
        cli::Cmd::Service { cmd } => match cmd {
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
                let uri = service::resolve_uri(uri.as_deref(), uri_file.as_deref())?;
                let transport = cli::Transport::for_service(transport, tun);
                if tun && transport != cli::Transport::Tcp {
                    crate::ui::warn(
                        "a full tunnel needs UDP and ICMP, which only --transport tcp \
                         carries today; DNS and ping will not work inside the tunnel",
                    );
                }
                // A system unit writes to /etc and drives `systemctl` without --user, so it
                // needs root just as the tunnel itself does.
                if tun && let Some(code) = elevate::ensure_root(already_elevated).await? {
                    return Ok(code);
                }
                service::start(&service::StartOpts {
                    uri: &uri,
                    transport: transport.as_flag(),
                    socks: (!no_socks).then_some(socks.as_str()),
                    tun,
                    tun_name: &tun_name,
                    dns: &dns,
                    mtu,
                    ipv6,
                })?
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
            cli::ServiceCmd::Logs { follow } => service::logs(follow)?,
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
