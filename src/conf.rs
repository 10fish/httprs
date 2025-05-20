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
#[command(name = "httprs", author = "10fish", version = "0.2.4")]
#[command(version, about, long_about = None, after_long_help = "./after-help.md")]
pub struct Configuration {
    /// Path of configuration file.
    #[arg(short, long)]
    pub config: Option<OsString>,

    /// Binding IP address of server.
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
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

#[cfg(test)]
mod test {
    use crate::conf::{Compression, Configuration};
    use clap::Parser;
    use clap::error::ErrorKind::MissingRequiredArgument;
    use regex::Regex;
    use std::ffi::OsString;
    use std::str::FromStr;

    /// default binding host.
    const DEFAULT_HOST: &str = "127.0.0.1";

    /// default binding port.
    const DEFAULT_PORT: u16 = 9900;

    /// default serving directory.
    const DEFAULT_ROOT_PATH: &str = ".";

    #[test]
    fn should_run_with_defaults() {
        let config = Configuration::parse_from([""]);
        assert_eq!(config.config, None);
        assert!(!config.graceful_shutdown);
        assert!(!config.cors);
        assert!(!config.quiet);
        assert_eq!(config.host, Some(DEFAULT_HOST.to_string()));
        assert_eq!(config.port, Some(DEFAULT_PORT));
        assert_eq!(
            config.home,
            Some(OsString::from_str(DEFAULT_ROOT_PATH).unwrap())
        );
    }

    #[test]
    fn should_set_host() {
        let config = Configuration::parse_from(["--", "-H", "192.168.1.1"]);
        assert_eq!(config.host, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn should_set_port() {
        let config = Configuration::parse_from(["--", "-P", "3000"]);
        assert_eq!(config.port, Some(3000));
    }

    #[test]
    fn should_complain_https_missing_key_and_cert() {
        let result = Configuration::try_parse_from(["--", "--secure"]);
        assert_eq!(
            result.as_ref().err().unwrap().kind(),
            MissingRequiredArgument
        );
        let error_string = result.as_ref().err().unwrap().to_string();
        // Usage prompt will print full args required
        let error_hint = Regex::new(r"Usage:.*")
            .unwrap()
            .replace_all(&error_string, "");
        // println!("{}", error_hint);
        assert!(error_hint.contains("--cert <CERT>"));
        assert!(error_hint.contains("--key <KEY>"));
    }

    #[test]
    fn should_complain_https_missing_key() {
        let result = Configuration::try_parse_from(["--", "--secure", "--cert", "server.pem"]);
        assert_eq!(
            result.as_ref().err().unwrap().kind(),
            MissingRequiredArgument
        );
        let error_string = result.as_ref().err().unwrap().to_string();
        // Usage prompt will print full args required
        let error_hint = Regex::new(r"Usage:.*")
            .unwrap()
            .replace_all(&error_string, "");
        // println!("{}", error_hint);
        assert!(!error_hint.contains("--cert <CERT>"));
        assert!(error_hint.contains("--key <KEY>"));
    }

    #[test]
    fn should_complain_https_missing_cert() {
        let result = Configuration::try_parse_from(["--", "--secure", "--key", "key.pem"]);
        assert_eq!(
            result.as_ref().err().unwrap().kind(),
            MissingRequiredArgument
        );
        let error_string = result.as_ref().err().unwrap().to_string();
        // Usage prompt will print full args required
        let error_hint = Regex::new(r"Usage:.*")
            .unwrap()
            .replace_all(&error_string, "");
        // println!("{}", error_hint);
        assert!(error_hint.contains("--cert <CERT>"));
        assert!(!error_hint.contains("--key <KEY>"));
    }

    #[test]
    fn should_https_run_with_cert_and_key() {
        let config = Configuration::parse_from([
            "--",
            "--secure",
            "--cert",
            "server.pem",
            "--key",
            "key.pem",
        ]);
        assert!(config.secure.as_ref().unwrap().secure);
        assert_eq!(
            config.secure.as_ref().unwrap().cert,
            OsString::from_str("server.pem").unwrap()
        );
        assert_eq!(
            config.secure.as_ref().unwrap().key,
            OsString::from_str("key.pem").unwrap()
        );
    }

    #[test]
    fn should_run_with_secure_mode() {
        let config =
            Configuration::parse_from(["", "--secure", "--cert", "cert.pem", "--key", "key.pem"]);
        assert!(config.secure.as_ref().unwrap().secure);
        assert_eq!(
            config.secure.as_ref().unwrap().cert,
            OsString::from("cert.pem")
        );
        assert_eq!(
            config.secure.as_ref().unwrap().key,
            OsString::from("key.pem")
        );
    }

    #[test]
    fn should_run_with_cors() {
        let config = Configuration::parse_from(["", "--cors"]);
        assert!(config.cors);
    }

    #[test]
    fn should_run_with_graceful_shutdown() {
        let config = Configuration::parse_from(["", "--graceful-shutdown"]);
        assert!(config.graceful_shutdown);
    }

    #[test]
    fn should_set_compression_gzip() {
        let config = Configuration::parse_from(["--", "-C", "gzip"]);
        assert_eq!(config.compression, Some(Compression::Gzip));
    }

    #[test]
    fn should_set_compression_deflate() {
        let config = Configuration::parse_from(["--", "-C", "deflate"]);
        assert_eq!(config.compression, Some(Compression::Deflate));
    }

    #[test]
    fn should_not_set_compression_unknown() {
        let result = Configuration::try_parse_from(["--", "-C", "unknown"]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("unknown"));
    }
}
