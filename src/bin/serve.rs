use std::error::Error;
use clap::Parser;
use httprs::{
    cli::Config,
    server::Server
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Config::parse();
    let mut server = Server::new(config).await;
    server.run().await
}
