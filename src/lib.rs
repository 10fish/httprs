use lazy_static::lazy_static;

mod conf;
mod http;
mod server;
mod mime;

pub use conf::Configuration;
pub use server::Server;
pub(crate) use mime::{
    MIME_TYPES,
    DEFAULT_MIME_TYPE,
};

lazy_static! {
    static ref VERSION_STRING: String = format!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}