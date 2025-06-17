use lazy_static::lazy_static;

mod conf;
mod http;
mod mime;
mod server;

pub use conf::Compression;
pub use conf::Configuration;
pub use http::{
    BREADCRUMBS_ITEM, BREADCRUMBS_TEMPLATE, HEADER_RANGE_VALUE_REGEX, MultipartByteRanges, Range,
    Segment, breadcrumbs, get_all_local_ips,
};
pub(crate) use mime::{DEFAULT_MIME_TYPE, MIME_TYPES};
pub use server::Server;

lazy_static! {
    static ref VERSION_STRING: String =
        format!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}
