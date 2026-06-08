mod cli;
mod client;
mod reality_config;
mod server;
mod user_cli;

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
            let kp = leshiy_core::handshake::generate_keypair()?;
            println!("public:  {}", URL_SAFE_NO_PAD.encode(&kp.public));
            println!("private: {}", URL_SAFE_NO_PAD.encode(&*kp.private));
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
        } => server::init(server::InitOptions {
            host: &host,
            dest: &dest,
            listen: listen.as_deref(),
            out: &out,
            quic_listen: quic_listen.as_deref(),
            quic_domain: quic_domain.as_deref(),
            quic_cert: quic_cert.as_deref(),
            quic_key: quic_key.as_deref(),
        })?,
        cli::Cmd::Server { config } => server::run(&config).await?,
        cli::Cmd::Client {
            uri,
            socks,
            transport,
        } => client::run(&uri, &socks, transport).await?,
        cli::Cmd::User { cmd } => user_cli::run(cmd).await?,
    }
    Ok(())
}
