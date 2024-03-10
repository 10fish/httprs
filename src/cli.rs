use std::{
    ffi::OsString,
    error::Error,
};
use clap::Parser;
use tokio::{
    fs::File,
    io::AsyncReadExt,
};
use tracing::error;
use serde::Deserialize;

/// global environment variable for serving root directory. default to current directory [.]
pub(crate) const ROOT_PATH_KEY: &'static str = "HTTPRS_ROOT";

/// default binding host.
pub(crate) const DEFAULT_HOST: &'static str = "127.0.0.1";

/// default binding port.
pub(crate) const DEFAULT_PORT: u16 = 9900;

/// default serving directory.
pub(crate) const DEFAULT_ROOT_PATH: &'static str = ".";

/// Simple cli http server for static files
#[derive(Debug, Parser, Deserialize)]
#[command(name = "httprs", author = "10fish", version = "0.2.1")]
#[command(version, about, long_about = None, after_long_help = "./after-help.md")]
pub struct Config {
    /// path of toml config file
    #[arg(short, long)]
    pub config: Option<OsString>,

    /// default binding host [default: 127.0.0.1]
    #[arg(short = 'H', long)]
    pub host: Option<String>,

    /// default binding port [default: 9000]
    #[arg(short = 'P', long)]
    pub port: Option<u16>,

    /// the directory where serve from [default: ./]
    pub root: Option<OsString>,

    //// Enable Cross-Origin Resource Sharing allowing any origin
    // #[arg(long)]
    // pub cors: bool,

    /// Waits for all requests to fulfill before shutting down the server
    #[arg(long)]
    pub graceful_shutdown: bool,

    //// Enable GZip compression for HTTP Responses
    // #[arg(long)]
    // pub gzip: bool,

    /// Enables HTTPS serving using TLS (NOT AVAILABLE CURRENTLY)
    #[arg(long)]
    pub tls: bool,

    /// Enables quiet mode
    #[arg(short, long)]
    pub quiet: bool,
}

impl Config {
    pub async fn merged(self) -> Result<Self, Box<dyn Error>> {
        if let Some(config_file) = &self.config {
            match File::open(config_file).await {
                Ok(mut file) => {
                    let mut content = String::new();
                    let _res = file.read_to_string(&mut content).await;
                    let result = toml::from_str::<Config>(content.as_str());
                    match result {
                        // merge parameters from cmd(with higher priorities) to that from file
                        Ok(config) => {
                            let conf = self.merge_from(config);
                            Ok(conf)
                        }
                        Err(err) => {
                            error!("error parse from configuration file {}: {}",
                                config_file.to_str().unwrap(), err);
                            Err(Box::new(err))
                        }
                    }
                }
                Err(err) => {
                    error!("error access to configuration file {}", config_file.to_str().unwrap());
                    Err(Box::new(err))
                }
            }
        } else {
            Ok(self)
        }
    }

    fn merge_from(self, config: Config) -> Config {
        let mut conf = config;
        if self.host.is_some() {
            conf.host = self.host;
        }
        if self.port.is_some() {
            conf.port = self.port;
        }
        if self.root.is_some() {
            conf.root = self.root;
        }
        conf.config = self.config;
        conf.quiet |= self.quiet;
        conf.tls |= self.tls;
        conf.graceful_shutdown |= self.graceful_shutdown;
        conf
    }

    pub(crate) fn display(&self) -> String {
        format!(r###"
        Configuration:
            {{
                host: {},
                port: {},
                config: {},
                root: {},
                graceful_shutdown: {},
                tls: {},
                quiet: {},
            }}
        "###,
                self.host.as_ref().unwrap_or(&DEFAULT_HOST.to_string()),
                self.port.unwrap_or(DEFAULT_PORT),
                self.config.as_ref().unwrap_or(&OsString::from("-")).to_str().unwrap(),
                self.root.as_ref().unwrap_or(&OsString::from(".")).to_str().unwrap(),
                self.graceful_shutdown,
                self.tls,
                self.quiet
        )
    }
}