use clap::builder::ArgPredicate;
use clap::{Args, Parser, ValueEnum};
use serde::Deserialize;
use std::path::PathBuf;
use std::{env, error::Error, ffi::OsString};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{debug, error};

/// global environment variable for serving root directory. default to current directory [.]
pub(crate) const HOME_PATH_KEY: &str = "HTTPRS_HOME";

#[derive(Debug, Clone, Eq, PartialEq, Args, Deserialize)]
pub struct Secure {
    /// enable https mode, adds an TLS layer for data transfer between server and clients
    #[arg(
        long,
        action,
        required = false,
        requires_if(ArgPredicate::IsPresent, "cert"),
        requires_if(ArgPredicate::IsPresent, "key")
    )]
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

#[derive(Debug, Clone, Parser, Deserialize)]
#[command(name = "httprs", author = "10fish", version = "0.2.5")]
#[command(version, about, long_about = None, after_long_help = "./after-help.md")]
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
    pub async fn init(self) -> Result<Self, Box<dyn Error>> {
        if let Some(config_file) = &self.config {
            match File::open(config_file).await {
                Ok(mut file) => {
                    let mut content = String::new();
                    let _res = file.read_to_string(&mut content).await;
                    let result = toml::from_str::<Configuration>(content.as_str());
                    match result {
                        // merge parameters from cmd(with higher priorities) to that from file
                        Ok(config) => {
                            let conf = self.merge_from(config);
                            conf.set_env();
                            Ok(conf)
                        }
                        Err(err) => {
                            error!(
                                "error parse from configuration file {}: {}",
                                config_file.to_str().unwrap(),
                                err
                            );
                            Err(Box::new(err))
                        }
                    }
                }
                Err(err) => {
                    error!(
                        "error access to configuration file {}",
                        config_file.to_str().unwrap()
                    );
                    Err(Box::new(err))
                }
            }
        } else {
            self.set_env();
            Ok(self)
        }
    }

    fn merge_from(self, config: Configuration) -> Configuration {
        let mut conf = config;
        if self.host.is_some() {
            conf.host = self.host;
        }
        if self.port.is_some() {
            conf.port = self.port;
        }
        if self.home.is_some() {
            conf.home = self.home;
        }
        conf.config = self.config;
        conf.quiet |= self.quiet;
        conf.secure = self.secure;
        conf.graceful_shutdown |= self.graceful_shutdown;
        conf
    }

    pub(crate) fn display(&self) -> String {
        format!(
            r###"
        Configuration:
            {{
                host: {},
                port: {},
                config: {},
                root: {},
                cors: {},
                compression: {:?},
                graceful_shutdown: {},
                secure: {},
                quiet: {},
            }}
        "###,
            self.host.as_ref().unwrap(),
            self.port.as_ref().unwrap(),
            self.config
                .as_ref()
                .unwrap_or(&OsString::from("-"))
                .to_str()
                .unwrap(),
            self.home.as_ref().unwrap().to_str().unwrap(),
            self.cors,
            self.compression,
            self.graceful_shutdown,
            self.protocol(),
            self.quiet
        )
    }

    pub(crate) fn protocol(&self) -> &'static str {
        if self.secure.is_some() {
            "https"
        } else {
            "http"
        }
    }

    pub(crate) fn set_env(&self) {
        let home_path = self.home.as_ref().unwrap();
        unsafe {
            env::set_var(HOME_PATH_KEY, PathBuf::from(&home_path).as_path());
        }
        debug!(
            "Setting HTTPRS_HOME environment variable to {}",
            home_path.to_str().unwrap()
        );
    }
}
