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

#[cfg(feature = "compression")]
use crate::{Compression, encoding::Encoding};

use crate::{
    DEFAULT_MIME_TYPE, MIME_TYPES, VERSION_STRING,
    listing::directory_listing,
    path_encoding::decode_segment,
    range::{MultipartByteRanges, RANGE_UNIT, Segment, coalesce, multipart_boundary, parse_ranges},
    validators,
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
    cors: bool,
    #[cfg(feature = "compression")]
    compression: Option<Compression>,
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
        Ok(Self {
            root,
            cors: false,
            #[cfg(feature = "compression")]
            compression: None,
        })
    }

    /// Enable public, credential-free cross-origin access.
    pub fn with_cors(mut self, enabled: bool) -> Self {
        self.cors = enabled;
        self
    }

    /// Enable streaming response compression for a supported coding.
    #[cfg(feature = "compression")]
    pub fn with_compression(mut self, compression: Compression) -> io::Result<Self> {
        if compression == Compression::Other {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported compression coding",
            ));
        }
        self.compression = Some(compression);
        Ok(self)
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
        if self.cors {
            let headers = response.headers_mut();
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            );
            headers.insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static("Accept-Ranges, Content-Range, ETag"),
            );
            if request.method() == Method::OPTIONS {
                headers.insert(
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_static("GET, HEAD, OPTIONS"),
                );
                for value in request
                    .headers()
                    .get_all(header::ACCESS_CONTROL_REQUEST_HEADERS)
                {
                    headers.append(header::ACCESS_CONTROL_ALLOW_HEADERS, value.clone());
                }
            }
        }
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
            if let Some(response) = precondition_response(request.headers(), None, None) {
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

        let mut file = File::open(&path).await?;
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
        #[cfg(feature = "compression")]
        let encoding = if let Some(compression) = &self.compression {
            let Some(encoding) = Encoding::select(
                compression,
                request.headers(),
                request.method() == Method::GET && request.headers().contains_key(header::RANGE),
            ) else {
                let mut response = text_response(StatusCode::NOT_ACCEPTABLE);
                response
                    .headers_mut()
                    .append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                return Ok(response);
            };
            encoding
        } else {
            Encoding::Identity
        };
        #[cfg(feature = "compression")]
        let coding = (encoding != Encoding::Identity).then(|| encoding.name());
        #[cfg(not(feature = "compression"))]
        let coding = None;

        let tag = validators::file_tag(&mut file, &metadata, coding).await?;
        let mut response = if let Some(response) =
            precondition_response(request.headers(), modified, Some(&tag))
        {
            response
        } else {
            let content_type = resolve_content_type(&relative);
            let head = request.method() == Method::HEAD;
            #[cfg(feature = "compression")]
            if let Some(coding) = coding {
                let body = if head {
                    empty_body()
                } else {
                    encoding.encode(file.take(size))
                };
                let mut response = Response::builder()
                    .header(header::CONTENT_TYPE, content_type)
                    .header(header::CONTENT_ENCODING, coding)
                    .body(body)
                    .unwrap();
                set_file_headers(&mut response, tag, modified);
                response
                    .headers_mut()
                    .append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                return Ok(response);
            }

            let mut range_fields = request.headers().get_all(header::RANGE).iter();
            let mut if_range = request.headers().get_all(header::IF_RANGE).iter();
            let range_matches = if_range.next().is_none_or(|value| {
                value.as_bytes().trim_ascii() == tag.as_bytes() && if_range.next().is_none()
            });
            let ranges = if !head && range_matches {
                range_fields
                    .next()
                    .filter(|_| range_fields.next().is_none())
                    .and_then(parse_ranges)
            } else {
                None
            };
            file_response(file, content_type, size, ranges, head).await?
        };
        if response.status() != StatusCode::PRECONDITION_FAILED {
            set_file_headers(&mut response, tag, modified);
        }
        #[cfg(feature = "compression")]
        if self.compression.is_some() {
            response
                .headers_mut()
                .append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        }
        Ok(response)
    }
}

fn modified_header(time: SystemTime) -> HeaderValue {
    HeaderValue::from_str(&httpdate::fmt_http_date(time)).unwrap()
}

fn set_file_headers(
    response: &mut Response<StaticBody>,
    tag: HeaderValue,
    modified: Option<SystemTime>,
) {
    let headers = response.headers_mut();
    headers.insert(header::ETAG, tag);
    if let Some(modified) = modified {
        headers.insert(header::LAST_MODIFIED, modified_header(modified));
    }
}

fn precondition_response(
    headers: &HeaderMap,
    modified: Option<SystemTime>,
    tag: Option<&HeaderValue>,
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
    let failed = if headers.contains_key(header::IF_MATCH) {
        !validators::matches(headers, header::IF_MATCH, tag, false)
    } else {
        date_matches(header::IF_UNMODIFIED_SINCE, |modified, date| {
            modified > date
        })
    };
    if failed {
        return Some(text_response(StatusCode::PRECONDITION_FAILED));
    }

    let not_modified = if headers.contains_key(header::IF_NONE_MATCH) {
        validators::matches(headers, header::IF_NONE_MATCH, tag, true)
    } else {
        date_matches(header::IF_MODIFIED_SINCE, |modified, date| modified <= date)
    };
    not_modified.then(|| {
        Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(empty_body())
            .unwrap()
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

pub(crate) fn stream_body(reader: impl AsyncRead + Send + 'static) -> StaticBody {
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
        let decoded = decode_segment(segment)?;
        let segment = decoded.as_ref();
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
