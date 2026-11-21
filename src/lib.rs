use lazy_static::lazy_static;

mod conf;
mod http;
mod listing;
mod mime;
mod range;
mod server;

pub use conf::Compression;
pub use conf::Configuration;
pub use http::{StaticBody, StaticFiles, get_all_local_ips};
pub use listing::{BREADCRUMBS_ITEM, BREADCRUMBS_TEMPLATE, breadcrumbs};
pub(crate) use mime::{DEFAULT_MIME_TYPE, MIME_TYPES};
pub use range::{HEADER_RANGE_VALUE_REGEX, MultipartByteRanges, Range, Segment};
pub use server::Server;

lazy_static! {
    static ref VERSION_STRING: String =
        format!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}
