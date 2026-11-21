mod conf;
mod http;
mod listing;
mod mime;
mod range;
mod server;

pub use conf::Compression;
pub use conf::Configuration;
#[cfg(feature = "local-ips")]
pub use http::get_all_local_ips;
pub use http::{StaticBody, StaticFiles};
pub use listing::{BREADCRUMBS_ITEM, BREADCRUMBS_TEMPLATE, breadcrumbs};
pub(crate) use mime::{DEFAULT_MIME_TYPE, MIME_TYPES};
pub use range::{HEADER_RANGE_VALUE_REGEX, MultipartByteRanges, Range, Segment};
pub use server::Server;

const VERSION_STRING: &str = concat!(env!("CARGO_PKG_NAME"), " v", env!("CARGO_PKG_VERSION"));
