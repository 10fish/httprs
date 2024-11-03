use std::error::Error;
use clap::Parser;
use httprs::{
    conf::Configuration,
    server::Server
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Configuration::parse();
    let server = Server::new(config).await;
    server.run().await
}
