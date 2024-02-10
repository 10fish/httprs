use std::{
    env,
    convert::Infallible,
    ffi::OsString,
    io::SeekFrom,
    path::{Path, PathBuf},
};
use std::cmp::Ordering;
use std::ops::Index;
use std::thread::park;
use bytes::Bytes;
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
};
use hyper::header::RANGE;
use regex::{Captures, Regex};
use tokio::{
    fs::File,
    io::AsyncSeekExt,
};
use tokio_util::io::ReaderStream;
use tracing::debug;
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
<p style="text-align: center;"><i>Powered by httprs v0.1.0 © 2024</i></p>
</body>
</html>
"###;

const HEADER_SERVER_VALUE: HeaderValue = HeaderValue::from_static("httprs v0.1.0");

// HTTP response body max size set to 50MB
const RESPONSE_BODY_SIZE_LIMIT_IN_BYTES: u64 = 50 * 1024 * 1024;

/// HTTP request header `RANGE` value regex. usually it can be one of following forms:
/// ```text
/// Range: <unit>=<range-start>-
/// Range: <unit>=<range-start>-<range-end>
/// Range: <unit>=<range-start>-<range-end>, <range-start>-<range-end>
/// Range: <unit>=<range-start>-<range-end>, <range-start>-<range-end>, <range-start>-<range-end>
/// Range: <unit>=-<suffix-length>
/// ```
const HTTP_HEADER_RANGE_REGEX: &'static str = "^([\\w\\W]+)\\s*=\\s*(((-\\d+)|(\\d+-\\d+)|(\\d+-)),\\s*)+";

struct RangePair(Option<u64>, Option<u64>);

struct Range {
    unit: String,
    ranges: Vec<RangePair>,
}

/// file service
pub(crate) async fn file_service(request: Request<Incoming>) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let path = request.uri().path();
    for hn in request.headers().keys() {
        debug!("HEADER: {} -> {}", hn, request.headers().get(hn).unwrap().to_str().unwrap())
    }
    let root = env::var(super::cli::ROOT_KEY).expect("variable HTTPRS_ROOT not set!");
    let root_path = PathBuf::from(root);
    // strip the prefix of '/' because path join will get to system root if not
    let full_path = root_path.join(decode(path).unwrap().strip_prefix("/").unwrap());
    debug!("requesting file path: {}", full_path.to_str().unwrap());

    if full_path.exists() {
        if full_path.is_dir() {
            let html_title = full_path.to_str().unwrap();
            let mut html_body = String::from("<ul id=\"file-list\" style=\"list-style-type: none;\">\n");

            let mut empty_content = "&lt;empty&gt;";
            for entry in WalkDir::new(full_path.clone()).max_depth(1) {
                let p = entry.unwrap().clone();

                let r_path = p.path().to_str().unwrap().strip_prefix(root_path.to_str().unwrap())
                    .unwrap_or(p.path().to_str().unwrap());
                debug!("relative path (to ROOT): {}", r_path);
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
                        "csv" | "txt" | "text" | "md" | "json" | "toml" | "cfg" | "config" | "yaml" => {
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
            let mut file = File::open(decoded_path)
                .await.expect("read file error");

            //
            if get_size_bytes(&file) > RESPONSE_BODY_SIZE_LIMIT_IN_BYTES {
                let range_value = request.headers().get(RANGE).unwrap();
                let range = Range::from(range_value).norm();
                // file.seek(SeekFrom::Start())

                let body_stream = ReaderStream::new(file);
                let body = BodyExt::map_err(
                    StreamBody::new(body_stream.map_ok(Frame::data)), infallible).boxed();
                Ok(Response::builder()
                    .header(header::SERVER, HEADER_SERVER_VALUE)
                    .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
                    .header(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"))
                    .status(StatusCode::OK)
                    .body(body).unwrap())
            } else {
                let body_stream = ReaderStream::new(file);
                let body = BodyExt::map_err(
                    StreamBody::new(body_stream.map_ok(Frame::data)), infallible).boxed();
                Ok(Response::builder()
                    .header(header::SERVER, HEADER_SERVER_VALUE)
                    .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
                    .header(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"))
                    .status(StatusCode::OK)
                    .body(body).unwrap())
            }
        }
    } else {
        let response_body = HTML_TEMPLATE
            .replace("{{header}}", "")
            .replace("{{title}}", format!("{}", "file not found").as_str())
            .replace("{{body}}", format!("file not found: {}", path).as_str());

        Ok(Response::builder()
            .header(header::SERVER, HEADER_SERVER_VALUE)
            .status(StatusCode::NOT_FOUND)
            .body(response_body.boxed()).unwrap())
    }
}


impl Range {
    fn new() -> Self {
        Self {
            unit: "".to_string(),
            ranges: vec![],
        }
    }

    /// parse value from http header value.
    fn from(val: &HeaderValue) -> Self {
        let range = val.to_str().unwrap();
        let mut unit: String = String::new();
        let mut ranges = vec![];
        let regex = Regex::new(HTTP_HEADER_RANGE_REGEX).unwrap();
        match regex.captures(range) {
            None => {}
            Some(caps) => {
                for cap in caps.iter() {
                    if let Some(cont) = cap {
                        let pair = cont.as_str();
                        if pair.contains('-') {
                            let idx = pair.find('-').unwrap();
                            if idx == 0 {
                                ranges.push(RangePair(None, Some((&pair[1..]).parse::<u64>().unwrap())));
                            } else if idx == pair.len() - 1 {
                                ranges.push(RangePair(Some(pair[..idx].parse::<u64>().unwrap()), None));
                            } else {
                                ranges.push(RangePair(Some(pair[idx + 1..].parse::<u64>().unwrap()),
                                                      Some(pair[idx + 1..].parse::<u64>().unwrap())))
                            }
                        } else {
                            unit = String::from(pair);
                        }
                    }
                }
            }
        }
        Self { unit, ranges }
    }

    /// sort range pairs, remove overlapped ones if exist
    fn norm(self) -> Self {
        let mut ranges = self.ranges;
        Self {
            unit: self.unit,
            ranges: vec![],
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
fn get_size_bytes(file: &File) -> u64 {
    0
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

    //#[test]
    fn should_generate_breadcrumbs_header() {
        let root = PathBuf::from("/test/1/2");
        let parent = PathBuf::from("/test/1/2/3/4/5/6/7");
        let actual = breadcrumbs(parent.as_path(), root.as_path());
        let expected = String::from(r###"<ul id="breadcrumbs">
<li class="breadcrums-item"><a href="/"><span class="separator">/</span>ROOT</a></li>
<li class="breadcrums-item"><a href="/3/"><span class="separator">/</span>3</a></li>
<li class="breadcrums-item"><a href="/3/4/"><span class="separator">/</span>4</a></li>
<li class="breadcrums-item"><a href="/3/4/5/"><span class="separator">/</span>5</a></li>
<li class="breadcrums-item"><a href="/3/4/5/6/"><span class="separator">/</span>6</a></li>
<li class="breadcrums-item"><a href="/3/4/5/6/7/"><span class="separator">/</span>7</a></li>
</ul>
"###);
        assert_eq!(actual, expected);
    }
}