use lazy_static::lazy_static;

mod conf;
mod http;
mod mime;
mod server;

pub use conf::Configuration;
pub(crate) use mime::{DEFAULT_MIME_TYPE, MIME_TYPES};
pub use server::Server;

lazy_static! {
    static ref VERSION_STRING: String =
        format!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}
