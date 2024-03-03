use std::{
    env,
    convert::Infallible,
    ffi::OsString,
    path::{Path, PathBuf},
    time::SystemTime,
    cmp::{max, min, Ordering}
};
use bytes::Bytes;
use colored::Colorize;
use futures_util::TryStreamExt;
use http_body_util::{
    BodyExt,
    StreamBody,
    combinators::BoxBody,
};
use hyper::{
    header,
    Request,
    Response,
    StatusCode,
    body::{Frame, Incoming},
    header::HeaderValue,
    header::RANGE
};
use regex::Regex;
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use tracing::{debug, warn};
use urlencoding::decode;
use walkdir::WalkDir;

const HTML_TEMPLATE: &'static str = r###"
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>{{title}}</title>
</head>
<body>
{{header}}
<hr>
{{body}}
<hr>
<p style="text-align: center;"><i>Powered by httprs v0.2.1 © 2024</i></p>
</body>
</html>
"###;

const HEADER_SERVER_VALUE: HeaderValue = HeaderValue::from_static("httprs v0.2.1");

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
const HEADER_RANGE_VALUE_REGEX: &'static str = "^([\\w]+)\\s*=\\s*(-\\d+|\\d+-\\d+|\\d+-)(,\\s*(-\\d+|\\d+-\\d+|\\d+-))*";
const RANGE_REGEX: &'static str = "((-\\d+)|(\\d+-\\d+)|(\\d+-))";

const DEFAULT_RANGE_UNIT: &'static str = "bytes";
const DEFAULT_REQUEST_RANGE_VALUE: &'static str = "bytes=0-";

#[derive(Debug, PartialEq, Eq, Clone)]
struct RangeValue(Option<u64>, Option<u64>);

#[derive(Debug, PartialEq, Eq, Clone)]
struct Range {
    unit: String,
    ranges: Vec<RangeValue>,
}

/// file service
pub(crate) async fn file_service(request: Request<Incoming>) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let timer = SystemTime::now();
    let path = request.uri().path();
    // for hn in request.headers().keys() {
    //     debug!("HEADER: {} -> {}", hn, request.headers().get(hn).unwrap().to_str().unwrap())
    // }
    let root = env::var(super::cli::ROOT_PATH_KEY).expect("environment variable HTTPRS_ROOT not set!");
    let root_path = PathBuf::from(root);
    // strip the prefix of '/' because path join will get to system root if not
    let full_path = root_path.join(decode(path).unwrap().strip_prefix("/").unwrap());
    // debug!("requesting file path: {}", full_path.to_str().unwrap());

    if full_path.exists() {
        if full_path.is_dir() {
            let html_title = full_path.to_str().unwrap();
            let mut html_body = String::from("<ul id=\"file-list\" style=\"list-style-type: none;\">\n");

            let mut empty_content = "&lt;empty&gt;";
            for entry in WalkDir::new(full_path.clone()).max_depth(1) {
                let p = entry.unwrap().clone();

                let r_path = p.path().to_str().unwrap().strip_prefix(root_path.to_str().unwrap())
                    .unwrap_or(p.path().to_str().unwrap());
                // debug!("relative path (to ROOT): {}", r_path);
                // skip current path showing
                if full_path.starts_with(p.path()) {
                    continue;
                }
                html_body += format!(
                    "<li><a href=\"{}\">{}</a></li>\n", r_path, p.file_name().to_str().unwrap()
                ).as_str();
                empty_content = "";
            }
            html_body += "</ul>\n";
            html_body += empty_content;


            let response_body = HTML_TEMPLATE
                .replace("{{header}}", breadcrumbs(full_path.as_path(), root_path.as_path()).as_str())
                .replace("{{title}}", format!("File list on {}", html_title).as_str())
                .replace("{{body}}", html_body.as_str());

            log_request(&request, timer.elapsed().unwrap().as_micros(), StatusCode::OK);
            Ok(Response::builder()
                .header(header::SERVER, HEADER_SERVER_VALUE)
                .status(StatusCode::OK)
                .body(BoxBody::new(response_body)).unwrap())
        } else {
            // Resolve file extension to HTTP Content-Type
            let content_type = match path.rsplit_once('.') {
                Some((_, ext)) => {
                    match ext.to_lowercase().as_str() {
                        // text
                        "css" => "text/css; charset=utf8",
                        "js" => "text/javascript; charset=utf8",
                        "html" | "htm" | "xhtml" | "xml" => "text/html; charset=utf8",
                        "csv" | "txt" | "text" | "md" | "json" | "toml" | "cfg" | "config" | "yaml" | "yml" => {
                            "text/plain; charset=utf8"
                        }
                        // image
                        "gif" => "image/gif",
                        "jpeg" | "jpg" => "image/jpeg",
                        "png" => "image/png",
                        "tiff" => "image/tiff",
                        "ico" => "image/vnd.microsoft.icon",
                        // TODO: confirmation
                        "icon" => "image/x-icon",
                        "djvu" => "image/vnd.djvu",
                        "svg" => "image/svg+xml",
                        // audio
                        // "mpeg" => "video/mpeg",
                        "wma" => "audio/x-ms-wma",
                        "wav" => "audio/x-wav",
                        "mp3" => "audio/x-wav",
                        "flac" => "audio/x-wav",
                        // video
                        "mpeg" => "video/mpeg",
                        "mp4" => "video/mp4",
                        "mov" => "video/quicktime",
                        "wmv" => "video/x-ms-wmv",
                        "flv" => "video/x-flv",
                        "webm" => "video/webm",
                        _ => "application/octet-stream"
                    }
                }
                _ => "application/octet-stream"
            };
            let decoded_path = decode(full_path.to_str().unwrap()).unwrap().to_string();
            let file = File::open(decoded_path).await.expect("read file error");
            let file_size = get_size_bytes(&file).await;

            if file_size > RESPONSE_BODY_SIZE_LIMIT_IN_BYTES {
                let default_range = HeaderValue::from_static(DEFAULT_REQUEST_RANGE_VALUE);
                let range_value = request.headers().get(RANGE).unwrap_or(&default_range);
                let _range = Range::from(range_value).combined();
                // file.seek(SeekFrom::Start())

                let body_stream = ReaderStream::new(file);
                let body = BodyExt::map_err(
                    StreamBody::new(body_stream.map_ok(Frame::data)), infallible).boxed();

                log_request(&request, timer.elapsed().unwrap().as_micros(), StatusCode::OK);
                Ok(Response::builder()
                    .header(header::SERVER, HEADER_SERVER_VALUE)
                    .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
                    .header(header::ACCEPT_RANGES, HeaderValue::from_static(DEFAULT_RANGE_UNIT))
                    .header(header::CONTENT_LENGTH, HeaderValue::from(file_size))
                    .status(StatusCode::OK)
                    .body(body).unwrap())
            } else {
                let body_stream = ReaderStream::new(file);
                let body = BodyExt::map_err(
                    StreamBody::new(body_stream.map_ok(Frame::data)), infallible).boxed();

                log_request(&request, timer.elapsed().unwrap().as_micros(), StatusCode::OK);
                Ok(Response::builder()
                    .header(header::SERVER, HEADER_SERVER_VALUE)
                    .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
                    .header(header::ACCEPT_RANGES, HeaderValue::from_static(DEFAULT_RANGE_UNIT))
                    .header(header::CONTENT_LENGTH, HeaderValue::from(file_size))
                    .status(StatusCode::OK)
                    .body(body).unwrap())
            }
        }
    } else {
        let response_body = HTML_TEMPLATE
            .replace("{{header}}", "")
            .replace("{{title}}", format!("{}", "file not found").as_str())
            .replace("{{body}}", format!("file not found: {}", path).as_str());

        log_request(&request, timer.elapsed().unwrap().as_micros(), StatusCode::NOT_FOUND);
        Ok(Response::builder()
            .header(header::SERVER, HEADER_SERVER_VALUE)
            .status(StatusCode::NOT_FOUND)
            .body(response_body.boxed()).unwrap())
    }
}

#[inline]
fn log_request(request: &Request<Incoming>, time: u128, status_code: StatusCode) {
    match status_code {
        success if success.lt(&StatusCode::BAD_REQUEST) => {
            debug!("{} {} {:?} {}µs {} {:?}", request.method().to_string().blue(), request.uri(),
                request.version(),time, success.to_string().green(),request.headers().get(header::USER_AGENT).unwrap());
        }
        fail if fail.ge(&StatusCode::BAD_REQUEST) => {
            warn!("{} {} {:?} {}µs {} {:?}", request.method().to_string().blue(), request.uri(),
                request.version(),time, fail.to_string().red(),request.headers().get(header::USER_AGENT).unwrap());
        }
        _other => {}
    };
}


impl Range {
    fn new() -> Self {
        Self {
            unit: DEFAULT_RANGE_UNIT.to_string(),
            ranges: vec![],
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
                for m in range_regex.find_iter(range) {
                    let pair = m.as_str();
                    if pair.contains('-') {
                        let idx = pair.find('-').unwrap();
                        if idx == 0 {
                            ranges.push(RangeValue(None, Some((&pair[1..]).parse::<u64>().unwrap())));
                        } else if idx == pair.len() - 1 {
                            ranges.push(RangeValue(Some(pair[..idx].parse::<u64>().unwrap()), None));
                        } else {
                            ranges.push(RangeValue(Some(pair[..idx].parse::<u64>().unwrap()),
                                                   Some(pair[idx + 1..].parse::<u64>().unwrap())))
                        }
                    }
                }
            }
        }
        Self { unit, ranges }
    }

    /// sort range pairs, remove overlapped ones if exist
    fn combined(mut self) -> Self {
        if self.ranges.len() < 1 {
            return Self {
                unit: self.unit,
                ranges: vec![],
            };
        }
        // sort RangeValue by start, and combine that overlapped
        self.ranges.sort();
        let mut ranges = vec![];
        let mut r = self.ranges[0].clone();
        for i in 1..self.ranges.len() {
            if r.overlapping(&self.ranges[i]) {
                r = r.combine(&self.ranges[i])
            } else {
                ranges.push(r.normalize());
                r = self.ranges[i].clone();
            }
        }
        ranges.push(r.normalize());
        Self {
            unit: self.unit,
            ranges,
        }
    }
}

impl RangeValue {
    pub(crate) fn new(start: Option<u64>, end: Option<u64>) -> Self {
        if start.is_some() && end.is_some() {
            if start.as_ref().unwrap() > end.as_ref().unwrap() {
                warn!("invalid parameters: start should be no large than end, start {:?}, end {:?}",
                    start, end);
                return Self(Some(0), Some(0));
            }
        }
        if start.is_none() && end.is_none() {
            warn!("invalid parameters: non sense with both start and end be None");
            return Self(Some(0), Some(0));
        }
        Self(start, end)
    }

    /// combine two overlapped ranges into one. e.g. (64, 512) and (256, 1024) combining into (64, 1024).
    pub(crate) fn combine(self, other: &Self) -> Self {
        if self.overlapping(other) {
            let self_norm = self.normalize();
            let other_norm = other.normalize();
            return Self::new(Some(min(self_norm.0.unwrap(), other_norm.0.unwrap())),
                             Some(max(self_norm.1.unwrap(), other_norm.1.unwrap())));
        }
        warn!("range is not overlapping with parameter, staying not combined: {:?} <-> {:?}", self, other);
        self
    }

    /// check if the two are overlapping. e.g. [64-512] and [256, 1024] are overlapping.
    pub(crate) fn overlapping(&self, other: &Self) -> bool {
        let self_norm = self.normalize();
        let other_norm = other.normalize();
        (other_norm.0.unwrap() >= self_norm.0.unwrap() && other_norm.0.unwrap() <= self_norm.1.unwrap()) ||
            (other_norm.1.unwrap() >= self_norm.0.unwrap() && other_norm.1.unwrap() <= self_norm.1.unwrap())
    }

    /// fix range value with a start or en end None value
    fn normalize(&self) -> Self {
        Self(Some(self.0.unwrap_or(0)), Some(self.1.unwrap_or(i64::MAX as u64)))
    }

    /// generate content-range value for this bytes range
    fn content_range(&self, total: u64) -> String {
        let norm = self.normalize();
        format!("{}-{}/{}", norm.0.unwrap(), min(norm.1.unwrap(), total), total)
    }
}

impl PartialOrd<Self> for RangeValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let self_norm = self.normalize();
        let other_norm = other.normalize();
        match self_norm.0.unwrap().partial_cmp(&other_norm.1.unwrap()) {
            Some(Ordering::Equal) => self_norm.1.unwrap().partial_cmp(&other_norm.1.unwrap()),
            other => other
        }
    }
}

impl Ord for RangeValue {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_norm = self.normalize();
        let other_norm = other.normalize();
        match self_norm.0.unwrap().cmp(&other_norm.1.unwrap()) {
            Ordering::Equal => self_norm.1.unwrap().cmp(&other_norm.1.unwrap()),
            other => other
        }
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
        // println!("cur: {}", cur.display());
        dirs.push(cur.file_name().unwrap().to_os_string());
        if let Some(p) = cur.parent() {
            cur = p;
        } else {
            break;
        }
    }
    // println!("dirs: {:?}", dirs);

    let mut breadcrumbs: String = String::from("<ul id=\"breadcrumbs\" style=\"display: flex;list-style-type: none;align-items: center;\">\n");
    let mut link_path = String::from("/");
    let mut link_name = String::from("ROOT");
    loop {
        breadcrumbs += format!("<li class=\"breadcrums-item\"><a href=\"{}\">\
        <span class=\"separator\" style=\"padding: 0 5px 0 5px;\">/</span><span>{}</span></a></li>\n",
                               link_path, link_name).as_str();
        if dirs.is_empty() {
            break;
        }
        let p = dirs.pop().unwrap();
        link_name = p.to_str().unwrap().to_string();
        link_path += link_name.as_str();
        link_path += "/";
    }
    breadcrumbs += "</ul>\n";
    breadcrumbs
}

fn infallible(error: std::io::Error) -> Infallible {
    panic!("io error: {}", error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_get_local_address() {
        let option = local_address();
        println!("{:?}", option);
    }

    #[test]
    fn should_generate_breadcrumbs_header() {
        let root = PathBuf::from("/test/1/2");
        let parent = PathBuf::from("/test/1/2/3/4/5/6/7");
        let actual = breadcrumbs(parent.as_path(), root.as_path());
        let expected = String::from(r###"<ul id="breadcrumbs" style="display: flex;list-style-type: none;align-items: center;">
<li class="breadcrums-item"><a href="/"><span class="separator" style="padding: 0 5px 0 5px;">/</span><span>ROOT</span></a></li>
<li class="breadcrums-item"><a href="/3/"><span class="separator" style="padding: 0 5px 0 5px;">/</span><span>3</span></a></li>
<li class="breadcrums-item"><a href="/3/4/"><span class="separator" style="padding: 0 5px 0 5px;">/</span><span>4</span></a></li>
<li class="breadcrums-item"><a href="/3/4/5/"><span class="separator" style="padding: 0 5px 0 5px;">/</span><span>5</span></a></li>
<li class="breadcrums-item"><a href="/3/4/5/6/"><span class="separator" style="padding: 0 5px 0 5px;">/</span><span>6</span></a></li>
<li class="breadcrums-item"><a href="/3/4/5/6/7/"><span class="separator" style="padding: 0 5px 0 5px;">/</span><span>7</span></a></li>
</ul>
"###);
        assert_eq!(actual, expected);
    }

    #[test]
    fn should_match_range_header() {
        let regex = Regex::new(HEADER_RANGE_VALUE_REGEX).unwrap();

        let range_value1 = "bytes=1024-65335";
        assert!(regex.captures(range_value1).is_some(), "regex should range value1");

        let range_value2 = "bytes=-65335, 102400-";
        assert!(regex.captures(range_value2).is_some(), "regex should range value2");

        let range_value3 = "bytes=-65335,102400-";
        assert!(regex.captures(range_value3).is_some(), "regex should range value3");

        let range_value4 = "bytes=-612233";
        assert!(regex.captures(range_value4).is_some(), "regex should range value4");

        let range_value5 = "bytes=1024-2048, 3072-4096, 6172-102400";
        assert!(regex.captures(range_value5).is_some(), "regex should range value5");
    }

    #[test]
    fn should_parse_range0() {
        let range_header = HeaderValue::from_static("bytes=1024-65535");
        let expected_ranges = vec![RangeValue::new(Some(1024), Some(65535))];
        let range = Range::from(&range_header);
        assert_eq!(range.unit, String::from("bytes"));
        assert_eq!(range.ranges[0], expected_ranges[0]);
    }

    #[test]
    fn should_parse_range1() {
        let range_header = HeaderValue::from_static("bytes=-1024, 23345-");
        let expected_ranges = vec![
            RangeValue::new(None, Some(1024)),
            RangeValue::new(Some(23345), None),
        ];
        let range = Range::from(&range_header);
        assert_eq!(range.unit, String::from("bytes"));
        assert_eq!(range.ranges, expected_ranges);
    }

    #[test]
    fn should_parse_range2() {
        let range_header = HeaderValue::from_static("bytes=1-12, 102400-, 12-24,24-96,96-1024");
        let expected_ranges = vec![
            RangeValue::new(Some(1), Some(12)),
            RangeValue::new(Some(102400), None),
            RangeValue::new(Some(12), Some(24)),
            RangeValue::new(Some(24), Some(96)),
            RangeValue::new(Some(96), Some(1024)),
        ];
        let range = Range::from(&range_header);
        assert_eq!(range.unit, String::from("bytes"));
        assert_eq!(range.ranges, expected_ranges);
    }

    #[test]
    fn should_ranges_combined0() {
        let mut range = Range::new();
        range.ranges = vec![
            RangeValue::new(Some(10), Some(36)),
            RangeValue::new(Some(72), Some(144)),
            RangeValue::new(Some(8), Some(512)),
            RangeValue::new(None, Some(96)),
            RangeValue::new(Some(1024), None),
        ];
        let mut expected = Range::new();
        expected.ranges = vec![
            RangeValue::new(Some(0), Some(512)),
            RangeValue::new(Some(1024), Some(i64::MAX as u64)),
        ];

        let actual = range.combined();

        assert_eq!(actual, expected, "ranges should be combined and not overlapping");
    }

    #[test]
    fn should_ranges_combined1() {
        let mut range = Range::new();
        range.ranges = vec![
            RangeValue::new(None, Some(1024)),
            RangeValue::new(Some(512), None),
        ];
        let mut expected = Range::new();
        expected.ranges = vec![
            RangeValue::new(Some(0), Some(i64::MAX as u64)),
        ];

        let actual = range.combined();

        assert_eq!(actual, expected, "ranges should be combined and not overlapping");
    }


    #[test]
    fn should_ranges_not_combined() {
        let mut range = Range::new();
        range.ranges = vec![
            RangeValue::new(Some(512), Some(1024)),
            RangeValue::new(Some(10240), None),
            RangeValue::new(None, Some(256)),
            RangeValue::new(Some(2048), Some(5120)),
            RangeValue::new(Some(6172), Some(8192)),
        ];
        let mut expected = Range::new();
        expected.ranges = vec![
            RangeValue::new(Some(0), Some(256)),
            RangeValue::new(Some(512), Some(1024)),
            RangeValue::new(Some(2048), Some(5120)),
            RangeValue::new(Some(6172), Some(8192)),
            RangeValue::new(Some(10240), Some(i64::MAX as u64)),
        ];

        let actual = range.combined();

        assert_eq!(actual, expected, "ranges should be combined and not overlapping");
    }
}