use clap::Parser;
use httprs::{Configuration, Server};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Configuration::parse();
    let server = Server::new(config).await;
    server.run().await
}
