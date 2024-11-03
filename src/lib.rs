use lazy_static::lazy_static;

pub mod conf;
mod http;
pub mod server;

lazy_static! {
    static ref VERSION_STRING: String = format!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}