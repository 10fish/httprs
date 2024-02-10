use std::{
    env,
    error::Error,
    ffi::OsString,
    path::PathBuf
};
use clap::Parser;
use colored::*;
use hyper::{
    server::conn::http1,
    service::service_fn
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, info};
use super::http::{file_service, local_address};

/// global environment variable for serving root directory. default to current directory [.]
pub(crate) const ROOT_KEY: &'static str = "HTTPRS_ROOT";

/// Simple cli http server for static files
#[derive(Debug, Parser)]
#[command(name = "httprs", author = "10fish", version = "0.1.0")]
#[command(version, about, long_about = None, after_long_help = "./after-help.md")]
struct Config {
    /// path of toml config file
    #[arg(short, long)]
    config: Option<OsString>,

    /// default binding host [default: 127.0.0.1]
    #[arg(short = 'H', long)]
    host: Option<String>,

    /// default binding port [default: 9000]
    #[arg(short = 'P', long)]
    port: Option<u16>,

    /// the directory where serve from [default: ./]
    root: Option<OsString>,

    /// Enable Cross-Origin Resource Sharing allowing any origin
    #[arg(long)]
    cors: bool,

    /// Waits for all requests to fulfill before shutting down the server
    #[arg(long)]
    graceful_shutdown: bool,

    /// Enable GZip compression for HTTP Responses
    #[arg(long)]
    gzip: bool,

    /// Enables HTTPS serving using TLS
    #[arg(long)]
    tls: bool,

    /// Enables quiet mode
    #[arg(short, long)]
    quiet: bool,
}

pub(crate) async fn cli() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_ansi(true)
        .with_level(false)
        .init();

    let config = Config::parse();
    let host = config.host.unwrap_or("127.0.0.1".to_string());
    let port = config.port.unwrap_or(9900);
    let root_path = config.root.unwrap_or(PathBuf::from(".").into());
    env::set_var(ROOT_KEY, PathBuf::from(&root_path).as_path());
    debug!("set global ROOT_KEY environment variable to {}", root_path.to_str().unwrap());

    if let Ok(listener) = TcpListener::bind(format!("{}:{}", host, port)).await {
        let protocol = if config.tls { "HTTPS" } else { "HTTP" };

        // TODO: simplify printing
        println!(
            "Serving {} on: {}",
            protocol.green(),
            format!(
                "{}://{}",
                protocol.to_lowercase(),
                listener.local_addr().unwrap()
            )
                .green()
        );
        if host == "0.0.0.0".to_string() {
            if let Some(ip) = local_address() {
                println!(
                    "Local Network {} on: {}",
                    protocol.green(),
                    format!("{}://{}:{}", protocol.to_lowercase(), ip, port).green()
                );
            }
        }

        loop {
            let (tcp, _) = listener.accept().await?;

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service_fn(file_service))
                    .await
                {
                    info!("Error serving connection: {:?}", err);
                }
            });
        }
    }
    Ok(())
}

