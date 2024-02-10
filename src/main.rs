use std::error::Error;
use crate::cli::cli;

mod cli;
mod http;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    cli().await
}
