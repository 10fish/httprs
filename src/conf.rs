use clap::{Args, Parser, ValueEnum};
use serde::Deserialize;
use std::{error::Error, ffi::OsString};

#[derive(Debug, Clone, Eq, PartialEq, Args, Deserialize)]
pub struct Secure {
    /// enable https mode, adds an TLS layer for data transfer between server and clients
    #[arg(long, requires_all = ["cert", "key"])]
    pub secure: bool,

    /// cert file path for server in https mode
    #[arg(long, required = false)]
    pub cert: OsString,

    /// private key file path for server in https mode
    #[arg(long, required = false)]
    pub key: OsString,
}

#[derive(Debug, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
#[clap(rename_all = "snake_case")]
pub enum Compression {
    Gzip,
    Deflate,
    Other,
}

#[derive(Debug, Clone, Default, Parser, Deserialize)]
#[command(name = "httprs", author = "10fish", version = "0.2.5")]
#[command(version, about, long_about = None)]
#[serde(default)]
pub struct Configuration {
    /// Path of configuration file.
    #[arg(short, long)]
    pub config: Option<OsString>,

    /// Binding IP address of server.
    #[arg(short = 'H', long, default_value = "0.0.0.0")]
    pub host: Option<String>,

    /// Binding port of service.
    #[arg(short = 'P', long, default_value = "9900")]
    pub port: Option<u16>,

    /// Base directory, default to current directory where service starts.
    #[arg(default_value = ".")]
    pub home: Option<OsString>,

    /// Enable Cross-Origin Resource Sharing allowing any origin.
    #[arg(long)]
    pub cors: bool,

    /// Enable gracefully shutting down the running server.
    #[arg(short, long, action)]
    pub graceful_shutdown: bool,

    /// Enable data transmission security between server and clients(HTTPS/TLS).
    #[command(flatten)]
    pub secure: Option<Secure>,

    /// Enable data compression between server and clients.
    #[arg(short = 'C', long)]
    pub compression: Option<Compression>,

    /// Enable server run in silent mode
    #[arg(short, long, action)]
    pub quiet: bool,
}

impl Configuration {
    pub async fn init(self) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut configuration = if let Some(path) = &self.config {
            let content = tokio::fs::read_to_string(path).await?;
            self.merge_from(toml::from_str(&content)?)
        } else {
            self
        };
        configuration.host.get_or_insert_with(|| "0.0.0.0".into());
        configuration.port.get_or_insert(9900);
        configuration.home.get_or_insert_with(|| ".".into());
        Ok(configuration)
    }

    fn merge_from(self, mut config: Configuration) -> Configuration {
        config.host = self.host.or(config.host);
        config.port = self.port.or(config.port);
        config.home = self.home.or(config.home);
        config.config = self.config;
        config.quiet |= self.quiet;
        config.secure = self.secure.or(config.secure);
        config.graceful_shutdown |= self.graceful_shutdown;
        config.cors |= self.cors;
        config.compression = self.compression.or(config.compression);
        config
    }

    pub(crate) fn protocol(&self) -> &'static str {
        if self.secure.is_some() {
            "https"
        } else {
            "http"
        }
    }
}
