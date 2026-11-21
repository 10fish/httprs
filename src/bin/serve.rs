use clap::{CommandFactory, FromArgMatches, parser::ValueSource};
use httprs::{Configuration, Server};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut matches = Configuration::command().get_matches();
    let defaults = ["host", "port", "home"]
        .map(|id| matches.value_source(id) == Some(ValueSource::DefaultValue));
    let mut config =
        Configuration::from_arg_matches_mut(&mut matches).unwrap_or_else(|error| error.exit());
    if defaults[0] {
        config.host = None;
    }
    if defaults[1] {
        config.port = None;
    }
    if defaults[2] {
        config.home = None;
    }

    let server = Server::try_new(config).await?;
    let level = if server.configuration.quiet {
        tracing::Level::ERROR
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_ansi(true)
        .with_level(false)
        .init();
    server.run().await
}
