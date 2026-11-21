#[cfg(feature = "cli")]
use clap::{Args, Parser, ValueEnum};
#[cfg(feature = "toml-config")]
use serde::{Deserialize, Deserializer};
use std::{error::Error, ffi::OsString};

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "toml-config", derive(Deserialize))]
#[cfg_attr(feature = "cli", derive(Args))]
pub struct Secure {
    /// enable https mode, adds an TLS layer for data transfer between server and clients
    #[cfg_attr(feature = "cli", arg(long, requires_all = ["cert", "key"]))]
    pub secure: bool,

    /// cert file path for server in https mode
    #[cfg_attr(feature = "cli", arg(long, required = false))]
    #[cfg_attr(feature = "toml-config", serde(deserialize_with = "deserialize_path"))]
    pub cert: OsString,

    /// private key file path for server in https mode
    #[cfg_attr(feature = "cli", arg(long, required = false))]
    #[cfg_attr(feature = "toml-config", serde(deserialize_with = "deserialize_path"))]
    pub key: OsString,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "toml-config", derive(Deserialize))]
#[cfg_attr(feature = "cli", derive(ValueEnum))]
#[cfg_attr(feature = "cli", clap(rename_all = "snake_case"))]
#[cfg_attr(feature = "toml-config", serde(rename_all = "lowercase"))]
pub enum Compression {
    #[cfg_attr(feature = "toml-config", serde(alias = "Gzip"))]
    Gzip,
    #[cfg_attr(feature = "toml-config", serde(alias = "Deflate"))]
    Deflate,
    #[cfg_attr(feature = "toml-config", serde(alias = "Other"))]
    #[cfg_attr(feature = "cli", value(skip))]
    Other,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "toml-config", derive(Deserialize))]
#[cfg_attr(feature = "cli", derive(Parser))]
#[cfg_attr(feature = "cli", command(name = "httprs", author = "10fish"))]
#[cfg_attr(feature = "cli", command(version, about, long_about = None))]
#[cfg_attr(feature = "toml-config", serde(default))]
pub struct Configuration {
    /// Path of configuration file.
    #[cfg_attr(feature = "cli", arg(short, long))]
    #[cfg_attr(
        feature = "toml-config",
        serde(deserialize_with = "deserialize_optional_path")
    )]
    pub config: Option<OsString>,

    /// Binding IP address of server.
    #[cfg_attr(feature = "cli", arg(short = 'H', long, default_value = "0.0.0.0"))]
    pub host: Option<String>,

    /// Binding port of service.
    #[cfg_attr(feature = "cli", arg(short = 'P', long, default_value = "9900"))]
    pub port: Option<u16>,

    /// Base directory, default to current directory where service starts.
    #[cfg_attr(feature = "cli", arg(default_value = "."))]
    #[cfg_attr(
        feature = "toml-config",
        serde(deserialize_with = "deserialize_optional_path")
    )]
    pub home: Option<OsString>,

    /// Enable Cross-Origin Resource Sharing allowing any origin.
    #[cfg_attr(feature = "cli", arg(long))]
    pub cors: bool,

    /// Enable gracefully shutting down the running server.
    #[cfg_attr(feature = "cli", arg(short, long, action))]
    pub graceful_shutdown: bool,

    /// Enable data transmission security between server and clients(HTTPS/TLS).
    #[cfg_attr(feature = "cli", command(flatten))]
    pub secure: Option<Secure>,

    /// Enable data compression between server and clients.
    #[cfg_attr(feature = "cli", arg(short = 'C', long))]
    pub compression: Option<Compression>,

    /// Enable server run in silent mode
    #[cfg_attr(feature = "cli", arg(short, long, action))]
    pub quiet: bool,
}

impl Configuration {
    pub async fn init(mut self) -> Result<Self, Box<dyn Error + Send + Sync>> {
        #[cfg(feature = "toml-config")]
        if let Some(path) = &self.config {
            let content = tokio::fs::read_to_string(path).await?;
            self = self.merge_from(toml::from_str(&content)?);
        }

        #[cfg(not(feature = "toml-config"))]
        if self.config.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "configuration files require the toml-config Cargo feature",
            )
            .into());
        }

        self.host.get_or_insert_with(|| "0.0.0.0".into());
        self.port.get_or_insert(9900);
        self.home.get_or_insert_with(|| ".".into());
        Ok(self)
    }

    #[cfg(feature = "toml-config")]
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

#[cfg(feature = "toml-config")]
#[derive(Deserialize)]
#[serde(untagged)]
enum ConfigPath {
    String(String),
    Native(OsString),
}

#[cfg(feature = "toml-config")]
impl From<ConfigPath> for OsString {
    fn from(value: ConfigPath) -> Self {
        match value {
            ConfigPath::String(path) => path.into(),
            ConfigPath::Native(path) => path,
        }
    }
}

#[cfg(feature = "toml-config")]
fn deserialize_path<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OsString, D::Error> {
    ConfigPath::deserialize(deserializer).map(Into::into)
}

#[cfg(feature = "toml-config")]
fn deserialize_optional_path<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<OsString>, D::Error> {
    Option::<ConfigPath>::deserialize(deserializer).map(|path| path.map(Into::into))
}
