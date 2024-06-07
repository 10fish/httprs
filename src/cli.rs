use clap::{Args, Parser, ValueEnum};
use serde::Deserialize;
use std::{error::Error, ffi::OsString};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::error;

/// global environment variable for serving root directory. default to current directory [.]
pub(crate) const ROOT_PATH_KEY: &'static str = "HTTPRS_ROOT";

/// default binding host.
pub(crate) const DEFAULT_HOST: &'static str = "127.0.0.1";

/// default binding port.
pub(crate) const DEFAULT_PORT: u16 = 9900;

/// default serving directory.
pub(crate) const DEFAULT_ROOT_PATH: &'static str = ".";

#[derive(Debug, Clone, Eq, PartialEq, Args, Deserialize)]
pub struct Protocol {
    /// whether to enable https mode, that data transfer between server to clients will use encryption
    #[arg(long, requires = "cert")]
    pub secure: bool,

    /// whether https use SSL encryption, by default use TLS
    #[arg(long)]
    pub ssl: bool,

    /// cert to be used for encryption with https mode
    #[arg(long)]
    pub cert: Option<OsString>,
}

#[derive(Debug, Clone, Eq, PartialEq, Default, ValueEnum, Deserialize)]
#[clap(rename_all = "snake_case")]
pub enum Compression {
    #[default]
    None,
    Gzip,
    Deflate,
    Other,
}

/// Simple cli http server for static files
#[derive(Debug, Parser, Deserialize)]
#[command(name = "httprs", author = "10fish", version = "0.2.3")]
#[command(version, about, long_about = None, after_long_help = "./after-help.md")]
pub struct Config {
    /// path of toml config file
    #[arg(short, long)]
    pub config: Option<OsString>,

    /// default binding host
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: Option<String>,

    /// default binding port
    #[arg(short = 'P', long, default_value = "9900")]
    pub port: Option<u16>,

    /// the directory where serve from
    #[arg(default_value = ".")]
    pub root: Option<OsString>,

    /// Enable Cross-Origin Resource Sharing allowing any origin
    #[arg(long)]
    pub cors: bool,

    /// Waits for all requests to fulfill before shutting down the server
    #[arg(short, long)]
    pub graceful_shutdown: bool,

    /// default binding port [default: http]
    #[command(flatten)]
    pub protocol: Option<Protocol>,

    /// Enable compression for HTTP(S) data transfers
    #[arg(short = 'C', long, default_value = "none")]
    pub compression: Compression,

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
        conf.protocol = self.protocol;
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
                protocol: {},
                quiet: {},
            }}
        "###,
            self.host.as_ref().unwrap_or(&DEFAULT_HOST.to_string()),
            self.port.unwrap_or(DEFAULT_PORT),
            self.config
                .as_ref()
                .unwrap_or(&OsString::from("-"))
                .to_str()
                .unwrap(),
            self.root
                .as_ref()
                .unwrap_or(&OsString::from("."))
                .to_str()
                .unwrap(),
            self.cors,
            self.compression,
            self.graceful_shutdown,
            self.protocol(),
            self.quiet
        )
    }

    fn protocol(&self) -> &'static str {
        if let Some(p) = self.protocol.as_ref() {
            if p.ssl {
                "https[ssl]"
            } else {
                "https[tls]"
            }
        } else {
            "http"
        }
    }
}


#[cfg(test)]
mod test {
    use std::ffi::OsString;
    use std::str::FromStr;
    use clap::Parser;
    use crate::cli::{Compression, Config, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_ROOT_PATH};

    #[test]
    fn should_run_with_defaults() {
        let config = Config::parse_from([""]);
        assert_eq!(config.config, None);
        assert_eq!(config.host, Some(DEFAULT_HOST.to_string()));
        assert_eq!(config.port, Some(DEFAULT_PORT));
        assert_eq!(config.root, Some(OsString::from_str(DEFAULT_ROOT_PATH).unwrap()));
        assert_eq!(config.compression, Compression::None);
        assert_eq!(config.protocol, None);
        assert_eq!(config.graceful_shutdown, false);
        assert_eq!(config.cors, false);
        assert_eq!(config.quiet, false);
    }

    /// must add "--" because tests run by cargo
    #[test]
    fn should_set_host() {
        let config = Config::parse_from(["--", "-H", "192.168.1.1"]);
        assert_eq!(config.host, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn should_set_port() {
        let config = Config::parse_from(["--", "-P", "3000"]);
        assert_eq!(config.port, Some(3000));
    }

    #[test]
    fn should_https_requires_cert() {
        let result = Config::try_parse_from(["--", "--secure"]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("--cert <CERT>"));
    }

    #[test]
    fn should_https_run_with_cert() {
        let config = Config::parse_from(["--", "--secure", "--cert", "https.cert"]);
        assert!(config.protocol.is_some());
        assert_eq!(config.protocol.as_ref().unwrap().secure, true);
        assert_eq!(config.protocol.as_ref().unwrap().ssl, false);
        assert_eq!(config.protocol.as_ref().unwrap().cert, Some(OsString::from_str("https.cert").unwrap()));
    }

    #[test]
    fn should_https_run_with_cert_ssl() {
        let config = Config::parse_from(["--", "--secure", "--cert", "https.cert", "--ssl"]);
        assert!(config.protocol.is_some());
        assert_eq!(config.protocol.as_ref().unwrap().secure, true);
        assert_eq!(config.protocol.as_ref().unwrap().ssl, true);
        assert_eq!(config.protocol.as_ref().unwrap().cert, Some(OsString::from_str("https.cert").unwrap()));
    }

    #[test]
    fn should_set_compression_gzip() {
        let config = Config::parse_from(["--", "-C", "gzip"]);
        assert_eq!(config.compression, Compression::Gzip);
    }

    #[test]
    fn should_set_compression_deflate() {
        let config = Config::parse_from(["--", "-C", "deflate"]);
        assert_eq!(config.compression, Compression::Deflate);
    }

    #[test]
    fn should_not_set_compression_unknown() {
        let result = Config::try_parse_from(["--", "-C", "unknown"]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("unknown"));
    }

    #[test]
    fn should_set_cors() {
        let config = Config::parse_from(["--", "--cors"]);
        assert_eq!(config.cors, true);
    }

    #[test]
    fn should_set_graceful_shutdown() {
        let config = Config::parse_from(["--", "--graceful-shutdown"]);
        assert_eq!(config.graceful_shutdown, true);
    }
}