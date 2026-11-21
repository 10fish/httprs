#![cfg(feature = "cli")]

use clap::Parser;
use clap::error::ErrorKind::MissingRequiredArgument;
use httprs::{Compression, Configuration};
use std::ffi::OsString;
use std::str::FromStr;

/// default binding host.
const DEFAULT_HOST: &str = "0.0.0.0";

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
    let error_hint = error_string.split("\nUsage:").next().unwrap();
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
    let error_hint = error_string.split("\nUsage:").next().unwrap();
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
    let error_hint = error_string.split("\nUsage:").next().unwrap();
    assert!(error_hint.contains("--cert <CERT>"));
    assert!(!error_hint.contains("--key <KEY>"));
}

#[test]
fn should_https_run_with_cert_and_key() {
    let config =
        Configuration::parse_from(["--", "--secure", "--cert", "server.pem", "--key", "key.pem"]);
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

#[cfg(not(feature = "toml-config"))]
#[test]
fn cli_reports_that_config_files_require_toml_support() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_httprs"))
        .args(["--config", "config.toml"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("configuration files require the toml-config Cargo feature"));
}
