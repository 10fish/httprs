use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::Frame;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
#[cfg(feature = "local-ips")]
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{self, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tracing::debug;

use crate::{
    DEFAULT_MIME_TYPE, MIME_TYPES, VERSION_STRING,
    listing::directory_listing,
    range::{MultipartByteRanges, RANGE_UNIT, Segment, coalesce, multipart_boundary, parse_ranges},
};

/// get all local network interfaces and their IP addresses
#[cfg(feature = "local-ips")]
pub fn get_all_local_ips() -> Vec<String> {
    let mut ips = HashSet::new();

    for interface in netdev::get_interfaces() {
        for ip in interface.ipv4_addrs() {
            ips.insert(ip.to_string());
        }
    }

    ips.into_iter().collect()
}

/// Response body produced by the static file service.
pub type StaticBody = UnsyncBoxBody<Bytes, io::Error>;

/// Serve a directory with GET and HEAD requests.
#[derive(Clone, Debug)]
pub struct StaticFiles {
    root: PathBuf,
}

impl StaticFiles {
    /// Resolve and validate the serving root.
    pub async fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = fs::canonicalize(root).await?;
        if !fs::metadata(&root).await?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                root.display().to_string(),
            ));
        }
        Ok(Self { root })
    }

    /// Handle a request. Request bodies are unused by the static file service.
    pub async fn handle<B>(&self, request: Request<B>) -> Response<StaticBody> {
        let start = Instant::now();
        let request = request.map(|_| ());
        let mut response = self.respond(&request).await.unwrap_or_else(|error| {
            let status = match error.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => StatusCode::NOT_FOUND,
                io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            if status.is_server_error() {
                tracing::warn!(%error, "Unable to serve file");
            }
            text_response(status)
        });
        if request.method() == Method::HEAD {
            *response.body_mut() = empty_body();
        }
        response
            .headers_mut()
            .insert(header::SERVER, HeaderValue::from_static(VERSION_STRING));
        debug!(method = %request.method(), uri = %request.uri(), status = %response.status(), elapsed_us = start.elapsed().as_micros(), "Static file request");
        response
    }

    async fn respond(&self, request: &Request<()>) -> io::Result<Response<StaticBody>> {
        match *request.method() {
            Method::OPTIONS => {
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header(header::ALLOW, "GET, HEAD, OPTIONS")
                    .body(empty_body())
                    .unwrap());
            }
            Method::GET | Method::HEAD => {}
            Method::POST
            | Method::PUT
            | Method::DELETE
            | Method::PATCH
            | Method::CONNECT
            | Method::TRACE => {
                let mut response = text_response(StatusCode::METHOD_NOT_ALLOWED);
                response.headers_mut().insert(
                    header::ALLOW,
                    HeaderValue::from_static("GET, HEAD, OPTIONS"),
                );
                return Ok(response);
            }
            _ => return Ok(text_response(StatusCode::NOT_IMPLEMENTED)),
        }

        let Some(relative) = relative_path(request.uri().path()) else {
            return Ok(text_response(StatusCode::BAD_REQUEST));
        };
        let path = fs::canonicalize(self.root.join(&relative)).await?;
        if !path.starts_with(&self.root) {
            return Ok(text_response(StatusCode::NOT_FOUND));
        }
        let metadata = fs::metadata(&path).await?;

        if metadata.is_dir() {
            if let Some(response) = precondition_response(request.headers(), None) {
                return Ok(response);
            }
            let body = directory_listing(&path, &relative).await?;
            return Ok(Response::builder()
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header(header::CONTENT_LENGTH, body.len())
                .body(full_body(body))
                .unwrap());
        }
        if !metadata.is_file() {
            return Ok(text_response(StatusCode::NOT_FOUND));
        }

        let file = File::open(&path).await?;
        let metadata = file.metadata().await?;
        let size = metadata.len();
        let modified = metadata.modified().ok().and_then(|time| {
            let seconds = time
                .min(SystemTime::now())
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs();
            Some(UNIX_EPOCH + std::time::Duration::from_secs(seconds))
        });
        if let Some(response) = precondition_response(request.headers(), modified) {
            return Ok(response);
        }
        let content_type = resolve_content_type(&relative);
        let mut range_fields = request.headers().get_all(header::RANGE).iter();
        let ranges = if request.method() == Method::GET
            && !request.headers().contains_key(header::IF_RANGE)
        {
            range_fields
                .next()
                .filter(|_| range_fields.next().is_none())
                .and_then(parse_ranges)
        } else {
            None
        };
        let mut response = file_response(
            file,
            content_type,
            size,
            ranges,
            request.method() == Method::HEAD,
        )
        .await?;
        if let Some(modified) = modified {
            response
                .headers_mut()
                .insert(header::LAST_MODIFIED, modified_header(modified));
        }
        Ok(response)
    }
}

fn modified_header(time: SystemTime) -> HeaderValue {
    HeaderValue::from_str(&httpdate::fmt_http_date(time)).unwrap()
}

// The service exposes Last-Modified but does not issue entity tags. Only the
// wildcard entity-tag preconditions can match an existing representation.
fn precondition_response(
    headers: &HeaderMap,
    modified: Option<SystemTime>,
) -> Option<Response<StaticBody>> {
    let date_matches = |name: HeaderName, compare: fn(SystemTime, SystemTime) -> bool| {
        let mut dates = headers.get_all(name).iter();
        let date = dates
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok());
        if dates.next().is_some() {
            return false;
        }
        modified
            .zip(date)
            .is_some_and(|(modified, date)| compare(modified, date))
    };
    let wildcard = |name: HeaderName| {
        let mut values = headers.get_all(name).iter();
        values
            .next()
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim() == "*")
            && values.next().is_none()
    };

    let failed = if headers.contains_key(header::IF_MATCH) {
        !wildcard(header::IF_MATCH)
    } else {
        date_matches(header::IF_UNMODIFIED_SINCE, |modified, date| {
            modified > date
        })
    };
    if failed {
        return Some(text_response(StatusCode::PRECONDITION_FAILED));
    }

    let not_modified = if headers.contains_key(header::IF_NONE_MATCH) {
        wildcard(header::IF_NONE_MATCH)
    } else {
        date_matches(header::IF_MODIFIED_SINCE, |modified, date| modified <= date)
    };
    not_modified.then(|| {
        let mut response = Response::builder().status(StatusCode::NOT_MODIFIED);
        if let Some(modified) = modified {
            response = response.header(header::LAST_MODIFIED, modified_header(modified));
        }
        response.body(empty_body()).unwrap()
    })
}

async fn file_response(
    mut file: File,
    content_type: &'static str,
    size: u64,
    ranges: Option<Vec<Segment>>,
    head: bool,
) -> io::Result<Response<StaticBody>> {
    let mut response = Response::builder().header(header::ACCEPT_RANGES, RANGE_UNIT);

    if let Some(segments) = ranges {
        let mut regions = coalesce(&segments, size);
        regions.sort_unstable_by_key(|&(_, _, index)| index);
        let ranges: Vec<_> = regions
            .into_iter()
            .map(|(start, end, _)| (start, end))
            .collect();

        let body = match ranges.as_slice() {
            [] => {
                return Ok(response
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                    .header(header::CONTENT_LENGTH, 0)
                    .body(empty_body())
                    .unwrap());
            }
            &[(start, end)] => {
                let length = end - start + 1;
                file.seek(SeekFrom::Start(start)).await?;
                response = response
                    .header(header::CONTENT_TYPE, content_type)
                    .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"))
                    .header(header::CONTENT_LENGTH, length);
                stream_body(file.take(length))
            }
            _ => {
                let boundary = multipart_boundary();
                response = response.header(
                    header::CONTENT_TYPE,
                    format!("multipart/byteranges; boundary={boundary}"),
                );
                stream_body(MultipartByteRanges::new(
                    file,
                    content_type,
                    &ranges,
                    size,
                    &boundary,
                ))
            }
        };
        return Ok(response
            .status(StatusCode::PARTIAL_CONTENT)
            .body(body)
            .unwrap());
    }

    let body = if head {
        empty_body()
    } else {
        stream_body(file.take(size))
    };
    Ok(response
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, size)
        .body(body)
        .unwrap())
}

fn stream_body(reader: impl AsyncRead + Send + 'static) -> StaticBody {
    StreamBody::new(ReaderStream::new(reader).map_ok(Frame::data)).boxed_unsync()
}

fn full_body(content: impl Into<Bytes>) -> StaticBody {
    Full::new(content.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn empty_body() -> StaticBody {
    full_body(Bytes::new())
}

pub(crate) fn text_response(status: StatusCode) -> Response<StaticBody> {
    let message = status.canonical_reason().unwrap_or_default();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, message.len())
        .body(full_body(message))
        .unwrap()
}

fn relative_path(path: &str) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for segment in path
        .strip_prefix('/')?
        .split('/')
        .filter(|part| !part.is_empty())
    {
        let decoded = urlencoding::decode_binary(segment.as_bytes());
        let segment = std::str::from_utf8(&decoded).ok()?;
        if segment.contains(['/', '\\', '\0']) {
            return None;
        }
        let mut components = Path::new(segment).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(name)), None) => relative.push(name),
            (Some(Component::CurDir), None) => {}
            _ => return None,
        }
    }
    Some(relative)
}

fn resolve_content_type(path: &Path) -> &'static str {
    let extension = path.extension().and_then(OsStr::to_str).unwrap_or("");
    MIME_TYPES
        .get(extension.to_ascii_lowercase().as_str())
        .unwrap_or(&DEFAULT_MIME_TYPE)
}
