use bytes::Bytes;
use chrono::{DateTime, Local};
use colored::Colorize;
use futures_util::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderValue, RANGE};
use hyper::{Request, Response, StatusCode};
use lazy_static::lazy_static;
use regex::Regex;
use std::cmp::min;
use std::convert::Infallible;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::fs::File;
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::io::ReaderStream;
use tracing::{debug, trace, warn, Level};
use urlencoding::decode;
use walkdir::WalkDir;

use crate::{DEFAULT_MIME_TYPE, MIME_TYPES, VERSION_STRING};

const HTML_TEMPLATE: &str = include_str!("../static/index.html");

const FILE_LIST_TABLE_TEMPLATE: &str = r###"
<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Size</th>
        </tr>
    </thead>
    <tbody>
        {{file_list}}
    </tbody>
</table>"###;

const EMPTY_LIST: &str = "<tr><td><i>&lt;empty&gt;</i><td></tr>";

const FILE_LIST_TABLE_ROW: &str = r###"
<tr>
    <td><a href="{{href}}">{{name}}</a></td>
    <td>{{size}}</td>
</tr>"###;

const BREADCRUMBS_TEMPLATE: &str = r###"
<div class="breadcrumbs">
    {{items}}
</div>"###;

const BREADCRUMBS_ITEM: &str = r###"
<span class="breadcrumb-item">
    <a href="{{href}}">{{name}}</a>
</span>"###;

/// response with partial content when body size larger than 50MB
const RESPONSE_BODY_SIZE_LIMIT_IN_BYTES: u64 = 50 * 1024 * 1024;

/// HTTP request header `RANGE` value regex. usually it can be one of following forms:
/// ```text
/// Range: <unit>=<range-start>-
/// Range: <unit>=<range-start>-<range-end>
/// Range: <unit>=<range-start>-<range-end>, <range-start>-<range-end>
/// Range: <unit>=<range-start>-<range-end>, <range-start>-<range-end>, <range-start>-<range-end>
/// Range: <unit>=-<suffix-length>
/// ```
const HEADER_RANGE_VALUE_REGEX: &str = r"^(bytes)=(.+)$";

const RANGE_REGEX: &str = r"(\d+-\d*|-\d+|\d+-\d+)";

const DEFAULT_RANGE_UNIT: &str = "bytes";
const DEFAULT_REQUEST_RANGE_VALUE: &str = "bytes=0-";
const MULTIPART_BYTERANGES_MULTIPART_BOUNDARY: &str = "THIS_SEPARATES";

lazy_static! {
    static ref HEADER_SERVER_VALUE: HeaderValue = HeaderValue::from_static(VERSION_STRING.as_str());
    static ref MULTIPART_BYTERANGES_HEADER_VALUE: HeaderValue = HeaderValue::from_str(
        format!(
            "multipart/byteranges; boundary={}",
            MULTIPART_BYTERANGES_MULTIPART_BOUNDARY
        )
        .as_str(),
    )
    .unwrap();
}

/// consists of a range with a start or an end(if not, it means to the start or end of the target file).
#[derive(Debug, PartialEq, Eq, Clone)]
enum Segment {
    RemainingFrom(u64),
    Regional(u64, u64),
    RemainingSize(u64),
}

/// represents the HTTP Request Header value of `header::RANGE`.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Range {
    unit: String,
    segments: Vec<Segment>,
    combined: bool,
    filesize: Option<u64>,
}

#[derive(Debug)]
struct FileSegment {
    file: PathBuf,
    offset: u64,
    size: u64,
}

#[derive(Debug)]
struct MultipartByteRanges {
    file: PathBuf,
    content_type: String,
    segments: Vec<(u64, u64)>,
    pos: (usize, u64, bool),
}

/// file service
pub(crate) async fn file_service(
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let timer = SystemTime::now();
    let path = request.uri().path();
    let root =
        env::var(super::conf::ROOT_PATH_KEY).expect("environment variable HTTPRS_ROOT not set!");
    let root_path = PathBuf::from(root);
    // strip the prefix of '/' because path join will get to system root if not
    let full_path = root_path.join(decode(path).unwrap().strip_prefix("/").unwrap());
    // debug!("requesting file path: {}", full_path.to_str().unwrap());
    if tracing::enabled!(Level::TRACE) {
        for hn in request.headers().keys() {
            trace!(
                "HEADER: {} -> {}",
                hn,
                request.headers().get(hn).unwrap().to_str().unwrap()
            )
        }
    }

    if full_path.exists() {
        if full_path.is_dir() {
            let html_title = full_path.to_str().unwrap();
            let mut file_list = String::new();

            let mut empty_content = EMPTY_LIST;
            for entry in WalkDir::new(full_path.clone()).max_depth(1) {
                let p = entry.unwrap().clone();

                let r_path = p
                    .path()
                    .to_str()
                    .unwrap()
                    .strip_prefix(root_path.to_str().unwrap())
                    .unwrap_or(p.path().to_str().unwrap());
                // debug!("relative path (to ROOT): {}", r_path);
                // skip current path showing
                if full_path.starts_with(p.path()) {
                    continue;
                }
                let meta = &p.metadata().unwrap();
                let modified: DateTime<Local> = meta.modified().unwrap().into();
                file_list += String::from(FILE_LIST_TABLE_ROW)
                    .replace("{{href}}", r_path)
                    .replace("{{name}}", p.file_name().to_str().unwrap())
                    .replace("{{size}}", format!("{}", meta.len()).as_str())
                    .replace(
                        "{{modified}}",
                        modified.format("%b %d %Y - %H:%M").to_string().as_str(),
                    )
                    .as_str();
            }
            if !file_list.is_empty() {
                empty_content = "";
            }
            let html_body = String::from(FILE_LIST_TABLE_TEMPLATE)
                .replace("{{file_list}}", file_list.as_str())
                .replace("{{placeholder}}", empty_content);

            let response_body = HTML_TEMPLATE
                .replace("{{version}}", VERSION_STRING.as_str())
                .replace(
                    "{{header}}",
                    breadcrumbs(full_path.as_path(), root_path.as_path()).as_str(),
                )
                .replace(
                    "{{title}}",
                    format!("File list under {}", html_title).as_str(),
                )
                .replace("{{body}}", html_body.as_str());

            log_request(
                &request,
                timer.elapsed().unwrap().as_micros(),
                StatusCode::OK,
            );
            Ok(Response::builder()
                .header(header::SERVER, HEADER_SERVER_VALUE.clone())
                .status(StatusCode::OK)
                .body(BoxBody::new(response_body))
                .unwrap())
        } else {
            // Resolve file extension to HTTP Content-Type
            let content_type = resolve_content_type(path);
            let decoded_path = decode(full_path.to_str().unwrap()).unwrap().to_string();
            let file = File::open(decoded_path).await.expect("read file error");
            let file_size = get_size_bytes(&file).await;

            if file_size > RESPONSE_BODY_SIZE_LIMIT_IN_BYTES {
                let default_range = HeaderValue::from_static(DEFAULT_REQUEST_RANGE_VALUE);
                let range_header = request.headers().get(RANGE).unwrap_or(&default_range);
                let mut range = Range::from(range_header);
                range.adjust(file_size).combine_segments();

                // debug only
                if tracing::enabled!(Level::TRACE) {
                    let ranges_display = range
                        .segments
                        .iter()
                        .map(|v| match v {
                            Segment::RemainingFrom(a) => format!("[{},E)", a),
                            Segment::Regional(a, b) => format!("[{},{}]", a, b),
                            Segment::RemainingSize(a) => format!("[E-{},E)", a),
                        })
                        .reduce(|a, b| a + "," + b.as_str())
                        .unwrap();
                    trace!("accessing file segments: < {} >", ranges_display);
                }

                // respond with multipart byte-ranges body parts if more than several ranges requested
                if range.multipart() {
                    let range_values = range.segments.clone();
                    let byte_ranges =
                        MultipartByteRanges::new(full_path.as_path(), content_type, &range_values);

                    let body_stream = ReaderStream::new(byte_ranges);
                    let body = BodyExt::map_err(
                        StreamBody::new(body_stream.map_ok(Frame::data)),
                        infallible,
                    )
                    .boxed();
                    log_request(
                        &request,
                        timer.elapsed().unwrap().as_micros(),
                        StatusCode::PARTIAL_CONTENT,
                    );
                    let response = Response::builder()
                        .header(header::SERVER, HEADER_SERVER_VALUE.clone())
                        .header(
                            header::CONTENT_TYPE,
                            MULTIPART_BYTERANGES_HEADER_VALUE.clone(),
                        )
                        .status(StatusCode::PARTIAL_CONTENT);
                    Ok(response.body(body).unwrap())
                } else {
                    let range_value = range.segments[0].clone();
                    let (file_segment, length, content_range) =
                        read_segment(&full_path, &range_value).await;

                    let body_stream = ReaderStream::new(file_segment);
                    let body = BodyExt::map_err(
                        StreamBody::new(body_stream.map_ok(Frame::data)),
                        infallible,
                    )
                    .boxed();

                    let status = match range.integrality() {
                        true => StatusCode::OK,
                        false => StatusCode::PARTIAL_CONTENT,
                    };
                    log_request(&request, timer.elapsed().unwrap().as_micros(), status);
                    Ok(Response::builder()
                        .header(header::SERVER, HEADER_SERVER_VALUE.clone())
                        .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
                        .header(header::CONTENT_RANGE, content_range)
                        .header(header::CONTENT_LENGTH, HeaderValue::from(length))
                        .header(
                            header::ACCEPT_RANGES,
                            HeaderValue::from_static(DEFAULT_RANGE_UNIT),
                        )
                        .status(status)
                        .body(body)
                        .unwrap())
                }
            } else {
                let body_stream = ReaderStream::new(file);
                let body =
                    BodyExt::map_err(StreamBody::new(body_stream.map_ok(Frame::data)), infallible)
                        .boxed();

                log_request(
                    &request,
                    timer.elapsed().unwrap().as_micros(),
                    StatusCode::OK,
                );
                Ok(Response::builder()
                    .header(header::SERVER, HEADER_SERVER_VALUE.clone())
                    .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
                    .header(
                        header::ACCEPT_RANGES,
                        HeaderValue::from_static(DEFAULT_RANGE_UNIT),
                    )
                    .header(header::CONTENT_LENGTH, HeaderValue::from(file_size))
                    .status(StatusCode::OK)
                    .body(body)
                    .unwrap())
            }
        }
    } else {
        let response_body = HTML_TEMPLATE
            .replace("{{version}}", VERSION_STRING.as_str())
            .replace("{{header}}", "")
            .replace("{{title}}", "file not found")
            .replace("{{file_list}}", "");

        log_request(
            &request,
            timer.elapsed().unwrap().as_micros(),
            StatusCode::NOT_FOUND,
        );
        Ok(Response::builder()
            .header(header::SERVER, HEADER_SERVER_VALUE.clone())
            .status(StatusCode::NOT_FOUND)
            .body(response_body.boxed())
            .unwrap())
    }
}

fn resolve_content_type(path: &str) -> &'static str {
    let ext = Path::new(path)
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or("");
    MIME_TYPES.get(ext).unwrap_or(&DEFAULT_MIME_TYPE)
}

async fn read_segment(path: &Path, seg: &Segment) -> (FileSegment, u64, HeaderValue) {
    let file = File::open(path).await.expect("read file error");
    let file_size = get_size_bytes(&file).await;
    let seg_start;
    let mut seg_end = file_size - 1;
    match seg {
        Segment::RemainingFrom(start) => {
            seg_start = *start;
        }
        Segment::Regional(start, end) => {
            seg_start = *start;
            seg_end = *end;
        }
        Segment::RemainingSize(size) => {
            seg_start = file_size - size;
        }
    };

    let segment_size = seg_end - seg_start + 1;

    // println!("from: {}, to: {}, read: {}, bytes: {:?}", range_from, range_to, actual_size, buf);
    (
        FileSegment {
            file: PathBuf::from(path),
            offset: seg_start,
            size: segment_size,
        },
        segment_size,
        HeaderValue::from_str(
            format!(
                "{} {}-{}/{}",
                DEFAULT_RANGE_UNIT, seg_start, seg_end, file_size
            )
            .as_str(),
        )
        .unwrap(),
    )
}

#[inline]
fn log_request(request: &Request<Incoming>, time: u128, status_code: StatusCode) {
    match status_code {
        success if success.lt(&StatusCode::BAD_REQUEST) => {
            debug!(
                "{} {} {:?} {}µs {} {:?}",
                request.method().to_string().blue(),
                request.uri(),
                request.version(),
                time,
                success.to_string().green(),
                request.headers().get(header::USER_AGENT).unwrap()
            );
        }
        fail if fail.ge(&StatusCode::BAD_REQUEST) => {
            warn!(
                "{} {} {:?} {}µs {} {:?}",
                request.method().to_string().blue(),
                request.uri(),
                request.version(),
                time,
                fail.to_string().red(),
                request.headers().get(header::USER_AGENT).unwrap()
            );
        }
        _other => {}
    };
}

#[allow(dead_code)]
impl Range {
    fn new() -> Self {
        Self {
            unit: DEFAULT_RANGE_UNIT.to_string(),
            segments: vec![],
            combined: false,
            filesize: None,
        }
    }

    /// parse value from http header value.
    fn from(val: &HeaderValue) -> Self {
        let range = val.to_str().unwrap();
        let mut unit: String = String::from(DEFAULT_RANGE_UNIT);
        let mut ranges = vec![];
        let regex = Regex::new(HEADER_RANGE_VALUE_REGEX).unwrap();
        match regex.captures(range) {
            None => {
                warn!("not a valid HTTP Range header value: {}", range);
            }
            Some(caps) => {
                unit = String::from(caps.get(1).unwrap().as_str());
                let range_regex = Regex::new(RANGE_REGEX).unwrap();
                for m in range_regex.find_iter(caps.get(2).unwrap().as_str()) {
                    let pair = m.as_str();
                    if pair.contains('-') {
                        let idx = pair.find('-').unwrap();
                        if idx == 0 {
                            // Format: -N (last N bytes)
                            ranges.push(Segment::RemainingSize(pair[1..].parse::<u64>().unwrap()));
                        } else if idx == pair.len() - 1 {
                            // Format: N- (from N to end)
                            ranges
                                .push(Segment::RemainingFrom(pair[..idx].parse::<u64>().unwrap()));
                        } else {
                            // Format: N-M (from N to M)
                            let start = pair[..idx].parse::<u64>().unwrap();
                            let end = pair[idx + 1..].parse::<u64>().unwrap();
                            ranges.push(Segment::Regional(start, end));
                        }
                    }
                }
            }
        }
        Self {
            unit,
            segments: ranges,
            combined: false,
            filesize: None,
        }
    }

    /// attach range to an existing file context
    fn adjust(&mut self, filesize: u64) -> &mut Self {
        self.filesize = Some(filesize);
        self
    }

    /// sort range pairs, remove overlapped ones if exist
    fn combine_segments(&mut self) {
        if self.segments.is_empty() {
            return;
        }

        let filesize = self
            .filesize
            .expect("filesize must be set before combining segments");

        // Convert all segments to Regional type
        let mut segments: Vec<Segment> = self
            .segments
            .iter()
            .map(|seg| match seg {
                Segment::RemainingSize(size) => Segment::Regional(filesize - size, filesize - 1),
                Segment::RemainingFrom(start) => Segment::Regional(*start, filesize - 1),
                Segment::Regional(start, end) => Segment::Regional(*start, *end),
            })
            .collect();

        // Sort segments by start position
        segments.sort_by(|a, b| {
            if let (Segment::Regional(a_start, _), Segment::Regional(b_start, _)) = (a, b) {
                a_start.cmp(b_start)
            } else {
                unreachable!("all segments should be Regional at this point")
            }
        });

        let mut combined = Vec::new();
        let mut current = if let Segment::Regional(start, end) = segments[0] {
            (start, end)
        } else {
            unreachable!("all segments should be Regional at this point")
        };

        for segment in segments.iter().skip(1) {
            if let Segment::Regional(start, end) = segment {
                if current.1 + 1 >= *start {
                    // Ranges overlap or are adjacent, merge them
                    current.1 = current.1.max(*end);
                } else {
                    // No overlap, add current range and start a new one
                    combined.push(Segment::Regional(current.0, current.1));
                    current = (*start, *end);
                }
            }
        }
        combined.push(Segment::Regional(current.0, current.1));

        self.segments = combined;
        self.combined = true;
    }

    /// check if http body should be multipart byte-ranges form or normal form
    fn multipart(&mut self) -> bool {
        if !self.combined {
            self.combine_segments();
        }
        self.segments.len() > 1
    }

    /// check if the range actually covers the full file.
    fn integrality(&self) -> bool {
        self.segments.is_empty()
            || self.segments[0].eq(&Segment::Regional(0, self.filesize.unwrap() - 1))
    }

    fn is_valid(&self) -> bool {
        !self.segments.is_empty()
    }
}

impl AsyncRead for FileSegment {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut file = std::fs::File::open(self.file.as_path()).expect("read file error");
        file.seek(SeekFrom::Start(self.offset)).unwrap();
        let segment_size = min(self.size as usize, buf.remaining());
        let mut read_buf = vec![0u8; segment_size];
        file.read_exact(&mut read_buf).unwrap();
        buf.put_slice(read_buf.as_slice());
        let self_mut = self.get_mut();
        self_mut.offset += segment_size as u64;
        self_mut.size -= segment_size as u64;
        Poll::Ready(Ok(()))
    }
}

impl MultipartByteRanges {
    fn new(file: &Path, content_type: &str, range_values: &[Segment]) -> Self {
        Self {
            file: PathBuf::from(file),
            content_type: String::from(content_type),
            segments: range_values
                .iter()
                .map(|v| match v {
                    Segment::Regional(from, to) => (*from, (*to - *from + 1)),
                    Segment::RemainingFrom(_) | Segment::RemainingSize(_) => (0, 0),
                })
                .collect(),
            pos: (0, 0, false),
        }
    }

    fn segment_required_length(&self, part_headers: &[u8]) -> u64 {
        let next_seg_len = self.segments[self.pos.0].1;
        // +2 because part should add en extra '\r\n' after the bytes array load
        if self.pos.1 == 0 {
            part_headers.len() as u64 + next_seg_len + 2
        } else {
            next_seg_len + 2
        }
    }

    fn fill_part_headers(&self, filesize: u64) -> Vec<u8> {
        let segment = self.segments[self.pos.0];
        let mut part_buf = String::new();
        part_buf.push_str(format!("--{}\r\n", MULTIPART_BYTERANGES_MULTIPART_BOUNDARY).as_str());
        part_buf.push_str(format!("Content-Type: {}\r\n", self.content_type).as_str());
        part_buf.push_str(
            format!(
                "Content-Range: {} {}-{}/{}\r\n",
                DEFAULT_RANGE_UNIT,
                segment.0,
                segment.0 + segment.1 - 1,
                filesize
            )
            .as_str(),
        );
        part_buf.push_str(format!("Content-Length: {}\r\n", segment.1).as_str());
        part_buf.push_str("\r\n");
        part_buf.into_bytes()
    }

    fn get_segment_size(&self) -> Option<(u64, u64)> {
        self.segments.get(self.pos.0).map(|segment| {
            let remaining = segment.1 - self.pos.1;
            if remaining > 0 {
                (segment.0 + self.pos.1, remaining)
            } else {
                (0, 0)
            }
        })
    }
}

impl AsyncRead for MultipartByteRanges {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos.0 >= self.segments.len() || self.pos.2 {
            return Poll::Ready(Ok(()));
        }
        let mut file = std::fs::File::open(self.file.as_path()).expect("read file error");
        let filesize = file.metadata().unwrap().len();

        while self.pos.0 < self.segments.len() {
            // 1. body_stream.append(MULTIPART_BYTERANGES_MULTIPART_BOUNDARY)
            // 2. body_stream.append(content_type)
            // 3. body_stream.append(content_range)
            // 4. body_stream.append(bytes)
            let segment = self.segments[self.pos.0];
            let part_headers = self.fill_part_headers(filesize);

            let capacity_needed = self.segment_required_length(&part_headers);
            let available_size = min(capacity_needed, buf.remaining() as u64);

            // first time read this segment
            if self.pos.1 == 0 {
                // remaining buffer size is not enough even for only non load content
                if available_size < part_headers.len() as u64 {
                    return Poll::Ready(Ok(()));
                } else {
                    buf.put_slice(part_headers.as_slice());
                }
            }
            if buf.remaining() as u64 >= segment.1 - self.pos.1 + 2 {
                let mut read_buf = vec![0u8; (segment.1 - self.pos.1) as usize];
                file.seek(SeekFrom::Start(segment.0 + self.pos.1)).unwrap();
                file.read_exact(&mut read_buf).unwrap();
                buf.put_slice(read_buf.as_slice());
                buf.put_slice(b"\r\n");

                self.pos.0 += 1;
                self.pos.1 = 0;
            } else {
                let mut read_buf = vec![0u8; buf.remaining()];
                file.seek(SeekFrom::Start(segment.0 + self.pos.1)).unwrap();
                file.read_exact(&mut read_buf)
                    .expect("read file to buffer error");
                buf.put_slice(read_buf.as_slice());

                self.pos.1 += read_buf.len() as u64;
                break;
            }
        }

        // end of processing
        let end_boundary = format!("--{}--\r\n", MULTIPART_BYTERANGES_MULTIPART_BOUNDARY);
        if self.pos.0 == self.segments.len() && !self.pos.2 && buf.remaining() >= end_boundary.len()
        {
            buf.put_slice(end_boundary.as_bytes());
            self.pos.2 = true;
        }
        Poll::Ready(Ok(()))
    }
}

/// get the binding in the local network context
pub(crate) fn local_address() -> Option<String> {
    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };

    match socket.connect("8.8.8.8:80") {
        Ok(()) => (),
        Err(_) => return None,
    };

    match socket.local_addr() {
        Ok(addr) => Some(addr.ip().to_string()),
        Err(_) => None,
    }
}

/// get file size bytes count. implementations should be different on different platforms.
async fn get_size_bytes(file: &File) -> u64 {
    file.metadata().await.unwrap().len()
}

fn breadcrumbs(parent: &Path, root: &Path) -> String {
    let mut cur = parent;
    let mut dirs: Vec<OsString> = vec![];
    while cur.starts_with(root) && !root.starts_with(cur) {
        dirs.push(cur.file_name().unwrap().to_os_string());
        if let Some(p) = cur.parent() {
            cur = p;
        } else {
            break;
        }
    }

    let mut link = String::from("/");
    let mut label = String::from("ROOT");
    let mut items = String::new();
    loop {
        items += String::from(BREADCRUMBS_ITEM)
            .replace("{{link}}", link.as_str())
            .replace("{{name}}", label.as_str())
            .as_str();
        if dirs.is_empty() {
            break;
        }
        let p = dirs.pop().unwrap();
        label = p.to_str().unwrap().to_string();
        link += label.as_str();
        link += "/";
    }
    String::from(BREADCRUMBS_TEMPLATE).replace("{{items}}", items.as_str())
}

fn infallible(error: std::io::Error) -> Infallible {
    panic!("io error: {}", error)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FILE_SIZE: u64 = 2560000;

    #[test]
    fn should_get_local_address() {
        let option = local_address();
        println!("{:?}", option);
    }

    #[test]
    fn should_generate_breadcrumbs_header() {
        let root = PathBuf::from("/test/1/2");
        let parent = PathBuf::from("/test/1/2/3/4/5/6/7");
        let links: Vec<(&str, &str)> = vec![
            ("/", "ROOT"),
            ("/3/", "3"),
            ("/3/4/", "4"),
            ("/3/4/5/", "5"),
            ("/3/4/5/6/", "6"),
            ("/3/4/5/6/7/", "7"),
        ];
        let actual = breadcrumbs(parent.as_path(), root.as_path());
        let mut items = String::new();
        for (link, label) in links {
            items += String::from(BREADCRUMBS_ITEM)
                .replace("{{link}}", link)
                .replace("{{name}}", label)
                .as_str();
        }
        let expected = String::from(BREADCRUMBS_TEMPLATE).replace("{{items}}", items.as_str());

        // remove all spaces to compare
        let regex = Regex::new(r"[\s]").unwrap();
        assert_eq!(
            regex.replace_all(actual.as_str(), ""),
            regex.replace_all(expected.as_str(), "")
        );
    }

    #[test]
    fn should_match_range_header() {
        let regex = Regex::new(HEADER_RANGE_VALUE_REGEX).unwrap();

        let range_value1 = "bytes=1024-65335";
        assert!(
            regex.captures(range_value1).is_some(),
            "regex should range value1"
        );

        let range_value2 = "bytes=-65335, 102400-";
        assert!(
            regex.captures(range_value2).is_some(),
            "regex should range value2"
        );

        let range_value3 = "bytes=-65335,102400-";
        assert!(
            regex.captures(range_value3).is_some(),
            "regex should range value3"
        );

        let range_value4 = "bytes=-612233";
        assert!(
            regex.captures(range_value4).is_some(),
            "regex should range value4"
        );

        let range_value5 = "bytes=1024-2048, 3072-4096, 6172-102400";
        assert!(
            regex.captures(range_value5).is_some(),
            "regex should range value5"
        );
    }

    #[test]
    fn should_parse_range0() {
        let range_header = HeaderValue::from_static("bytes=1024-65535");
        let expected_ranges = [Segment::Regional(1024, 65535)];
        let actual = Range::from(&range_header);
        assert_eq!(actual.unit, String::from("bytes"));
        assert_eq!(actual.segments[0], expected_ranges[0]);
    }

    #[test]
    fn should_parse_range1() {
        let range_header = HeaderValue::from_static("bytes=-1024, 23345-");
        let expected_ranges = [Segment::RemainingSize(1024), Segment::RemainingFrom(23345)];
        let actual = Range::from(&range_header);
        assert_eq!(actual.unit, String::from("bytes"));
        assert_eq!(actual.segments, expected_ranges);
    }

    #[test]
    fn should_parse_range2() {
        let range_header = HeaderValue::from_static("bytes=1-12, 102400-, 12-24,24-96,96-1024");
        let expected_ranges = [
            Segment::Regional(1, 12),
            Segment::RemainingFrom(102400),
            Segment::Regional(12, 24),
            Segment::Regional(24, 96),
            Segment::Regional(96, 1024),
        ];
        let actual = Range::from(&range_header);
        assert_eq!(actual.unit, String::from("bytes"));
        assert_eq!(actual.segments, expected_ranges);
    }

    #[test]
    fn should_ranges_combined0() {
        let mut range = Range::new();
        range.segments = vec![
            Segment::Regional(10, 36),
            Segment::Regional(72, 144),
            Segment::Regional(8, 512),
            Segment::RemainingSize(96),
            Segment::RemainingFrom(1024),
        ];
        let mut expected = Range::new();
        expected.combined = true;
        expected.filesize = Some(TEST_FILE_SIZE);
        expected.segments = vec![
            Segment::Regional(8, 512),
            Segment::Regional(1024, TEST_FILE_SIZE - 1),
        ];

        range.adjust(TEST_FILE_SIZE).combine_segments();

        assert_eq!(
            range, expected,
            "ranges should be combined and not overlapping"
        );
    }

    #[test]
    fn should_ranges_combined1() {
        let mut range = Range::new();
        range.segments = vec![Segment::RemainingSize(1024), Segment::RemainingFrom(512)];
        let mut expected = Range::new();
        expected.combined = true;
        expected.filesize = Some(TEST_FILE_SIZE);
        expected.segments = vec![Segment::Regional(512, TEST_FILE_SIZE - 1)];

        range.adjust(TEST_FILE_SIZE).combine_segments();

        assert_eq!(
            range, expected,
            "ranges should be combined and not overlapping"
        );
    }

    #[test]
    fn should_ranges_not_combined() {
        let mut range = Range::new();
        range.segments = vec![
            Segment::Regional(512, 1024),
            Segment::RemainingFrom(10240),
            Segment::RemainingSize(256),
            Segment::Regional(2048, 5120),
            Segment::Regional(6172, 8192),
        ];
        let mut expected = Range::new();
        expected.combined = true;
        expected.filesize = Some(TEST_FILE_SIZE);
        expected.segments = vec![
            Segment::Regional(512, 1024),
            Segment::Regional(2048, 5120),
            Segment::Regional(6172, 8192),
            Segment::Regional(10240, TEST_FILE_SIZE - 1),
        ];

        range.adjust(TEST_FILE_SIZE).combine_segments();

        assert_eq!(
            range, expected,
            "ranges should be combined and not overlapping"
        );
    }

    #[tokio::test]
    async fn bytes_stream_async_read() {
        // let text = "this is line 1\nthis is line 2\nthis is line 3";
        // let mut stream = BytesStream(text.as_bytes().to_vec());
        //
        // let mut buf = Vec::new();
        // let actual = stream.read_to_end(&mut buf).await;
        // assert!(actual.is_ok());
        // assert_eq!(actual.unwrap(), text.len());
    }

    #[test]
    fn test_parse_range_values() {
        let expected_ranges = [Segment::Regional(1024, 65535)];
        let actual = Range::from(&HeaderValue::from_static("bytes=1024-65535")).segments;
        assert_eq!(actual, expected_ranges);
    }
}
