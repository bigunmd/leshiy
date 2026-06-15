mod cli;
mod client;
mod host;
mod lifecycle;
mod quickstart;
mod reality_config;
mod server;
mod tun;
mod user_cli;
mod vpn;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "leshiy=info".into()),
        )
        .init();
    match cli::Cli::parse().cmd {
        cli::Cmd::Keygen => {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            use std::io::IsTerminal;
            let kp = leshiy_core::handshake::generate_keypair()?;
            println!("public:  {}", URL_SAFE_NO_PAD.encode(&kp.public));
            println!("private: {}", URL_SAFE_NO_PAD.encode(&*kp.private));
            // M5: the private line is secret key material. Warn on stderr so that
            // capturing it (scrollback, shell history, CI logs, a redirected file)
            // is a conscious choice rather than a silent leak.
            if std::io::stdout().is_terminal() {
                eprintln!(
                    "warning: the 'private' line is SECRET — do not share, log, screenshot, or commit it."
                );
            } else {
                eprintln!(
                    "warning: a SECRET private key was written to the redirected output — restrict it (chmod 600)."
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
            socks,
            transport,
        } => client::run(&uri, &socks, transport).await?,
        cli::Cmd::Connect {
            uri,
            socks,
            transport,
        } => client::run(&uri, &socks, transport).await?,
        cli::Cmd::Tun {
            uri,
            transport,
            mtu,
            tun_name,
            dns,
        } => tun::run(&uri, transport, mtu, &tun_name, &dns).await?,
        cli::Cmd::Vpn {
            uri,
            transport,
            mtu,
            tun_name,
            dns,
            socket,
        } => vpn::run(&uri, transport, mtu, &tun_name, &dns, &socket).await?,
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
    }
    Ok(())
}
