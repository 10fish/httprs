use std::ffi::OsString;
use clap::Parser;

/// global environment variable for serving root directory. default to current directory [.]
pub const ROOT_PATH_KEY: &'static str = "HTTPRS_ROOT";

/// Simple cli http server for static files
#[derive(Debug, Parser)]
#[command(name = "httprs", author = "10fish", version = "0.1.0")]
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

    /// Enable Cross-Origin Resource Sharing allowing any origin
    #[arg(long)]
    pub cors: bool,

    /// Waits for all requests to fulfill before shutting down the server
    #[arg(long)]
    pub graceful_shutdown: bool,

    /// Enable GZip compression for HTTP Responses
    #[arg(long)]
    pub gzip: bool,

    /// Enables HTTPS serving using TLS
    #[arg(long)]
    pub tls: bool,

    /// Enables quiet mode
    #[arg(short, long)]
    pub quiet: bool,
}