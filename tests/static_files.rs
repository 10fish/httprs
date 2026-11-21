use bytes::Bytes;
use http_body_util::BodyExt;
use httprs::{Configuration, StaticBody, StaticFiles};
use hyper::{Request, Response, StatusCode, header};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: AtomicU32 = AtomicU32::new(0);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "httprs-{}-{}-{}",
            std::process::id(),
            now.as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("sample.TXT"), b"0123456789").unwrap();
        Self(path)
    }

    async fn service(&self) -> StaticFiles {
        StaticFiles::new(&self.0).await.unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn request(
    service: &StaticFiles,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Response<StaticBody> {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    service.handle(request.body(()).unwrap()).await
}

async fn body(response: Response<StaticBody>) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn get_and_head_share_metadata() {
    let fixture = Fixture::new();
    let service = fixture.service().await;
    let get = request(&service, "GET", "/sample.TXT?download=1", &[]).await;
    let head = request(&service, "HEAD", "/sample.TXT", &[("range", "bytes=2-4")]).await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(get.headers(), head.headers());
    assert_eq!(get.headers()[header::CONTENT_TYPE], "text/plain");
    assert_eq!(get.headers()[header::CONTENT_LENGTH], "10");
    assert_eq!(get.headers()[header::ACCEPT_RANGES], "bytes");
    assert!(!get.headers().contains_key(header::CONTENT_RANGE));
    assert_eq!(body(get).await, "0123456789");
    assert!(body(head).await.is_empty());
}

#[tokio::test]
async fn serves_single_ranges_on_small_files() {
    let fixture = Fixture::new();
    let service = fixture.service().await;
    for (range, content_range, expected) in [
        ("bytes=2-4", "bytes 2-4/10", "234"),
        ("Bytes=8-", "bytes 8-9/10", "89"),
        ("bytes=-2", "bytes 8-9/10", "89"),
        ("bytes=-99", "bytes 0-9/10", "0123456789"),
        ("bytes=8-9999999999999999999999", "bytes 8-9/10", "89"),
        ("bytes=10-20, 0-1", "bytes 0-1/10", "01"),
        ("bytes=1-3, 3-4, 5-5", "bytes 1-5/10", "12345"),
    ] {
        let response = request(&service, "GET", "/sample.TXT", &[("range", range)]).await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(response.headers()[header::CONTENT_RANGE], content_range);
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            expected.len().to_string()
        );
        assert_eq!(body(response).await, expected, "{range}");
    }
}

#[tokio::test]
async fn returns_full_response_for_ignored_ranges() {
    let fixture = Fixture::new();
    let service = fixture.service().await;
    for headers in [
        vec![("range", "items=1-2")],
        vec![("range", "bytes=2-3, invalid")],
        vec![("range", "bytes=4-2")],
        vec![("range", "bytes=1-2"), ("range", "bytes=4-5")],
        vec![("range", "bytes=1-2"), ("if-range", "\"unavailable\"")],
    ] {
        let response = request(&service, "GET", "/sample.TXT", &headers).await;
        assert_eq!(response.status(), StatusCode::OK, "{headers:?}");
        assert!(!response.headers().contains_key(header::CONTENT_RANGE));
        assert_eq!(body(response).await, "0123456789");
    }
}

#[tokio::test]
async fn returns_representation_size_for_unsatisfiable_ranges() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("empty"), []).unwrap();
    let service = fixture.service().await;

    for (path, range, content_range) in [
        ("/sample.TXT", "bytes=10-", "bytes */10"),
        ("/sample.TXT", "bytes=-0", "bytes */10"),
        ("/sample.TXT", "bytes=9999999999999999999999-", "bytes */10"),
        ("/empty", "bytes=0-", "bytes */0"),
    ] {
        let response = request(&service, "GET", path, &[("range", range)]).await;
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()[header::CONTENT_RANGE], content_range);
        assert!(body(response).await.is_empty());
    }
}

#[tokio::test]
async fn streams_multipart_bodies_with_complete_boundaries() {
    let fixture = Fixture::new();
    let payload = vec![b'a'; 48_000];
    fs::write(fixture.0.join("data.bin"), &payload).unwrap();
    let service = fixture.service().await;
    let response = request(
        &service,
        "GET",
        "/data.bin",
        &[("range", "bytes=47000-47999,0-39999")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert!(!response.headers().contains_key(header::CONTENT_RANGE));
    let boundary = response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .strip_prefix("multipart/byteranges; boundary=")
        .unwrap()
        .to_owned();
    let mut expected = Vec::new();
    for (start, end) in [(47_000, 47_999), (0, 39_999)] {
        let headers = format!(
            "--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {start}-{end}/48000\r\n\r\n"
        );
        expected.extend_from_slice(headers.as_bytes());
        expected.extend_from_slice(&payload[start..=end]);
        expected.extend_from_slice(b"\r\n");
    }
    expected.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    assert_eq!(body(response).await.as_ref(), expected);
}

#[tokio::test]
async fn conditional_requests_are_evaluated_before_ranges() {
    let fixture = Fixture::new();
    let service = fixture.service().await;
    let initial = request(&service, "HEAD", "/sample.TXT", &[]).await;
    let modified = initial.headers()[header::LAST_MODIFIED].to_str().unwrap();
    for (headers, status) in [
        (
            vec![("if-modified-since", modified), ("range", "bytes=1-2")],
            StatusCode::NOT_MODIFIED,
        ),
        (vec![("if-none-match", "*")], StatusCode::NOT_MODIFIED),
        (
            vec![("if-match", "\"other\""), ("if-none-match", "*")],
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            vec![("if-unmodified-since", "Thu, 01 Jan 1970 00:00:00 GMT")],
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            vec![
                ("if-match", "*"),
                ("if-unmodified-since", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ],
            StatusCode::OK,
        ),
        (
            vec![
                ("if-none-match", "\"other\""),
                ("if-modified-since", modified),
            ],
            StatusCode::OK,
        ),
    ] {
        let response = request(&service, "GET", "/sample.TXT", &headers).await;
        assert_eq!(response.status(), status, "{headers:?}");
        if status == StatusCode::NOT_MODIFIED {
            assert_eq!(response.headers()[header::LAST_MODIFIED], modified);
            assert!(!response.headers().contains_key(header::CONTENT_RANGE));
            assert!(body(response).await.is_empty());
        }
    }
}

#[tokio::test]
async fn directory_links_encode_file_names_and_round_trip() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("A & B")).unwrap();
    fs::write(fixture.0.join("A & B/100% literal.txt"), "ok").unwrap();
    let service = fixture.service().await;
    let listing = request(&service, "GET", "/A%20%26%20B/", &[]).await;
    assert_eq!(
        listing.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let listing = String::from_utf8(body(listing).await.to_vec()).unwrap();
    assert!(listing.contains("A &amp; B"));
    let link = "/A%20%26%20B/100%25%20literal.txt";
    assert!(listing.contains(&format!("href=\"{link}\"")));
    assert_eq!(body(request(&service, "GET", link, &[]).await).await, "ok");
}

#[tokio::test]
async fn reports_missing_resources_and_unsupported_methods() {
    let fixture = Fixture::new();
    let service = fixture.service().await;
    let missing = request(&service, "HEAD", "/missing", &[("if-match", "*")]).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert!(body(missing).await.is_empty());

    let post = request(&service, "POST", "/sample.TXT", &[]).await;
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(post.headers()[header::ALLOW], "GET, HEAD, OPTIONS");

    let options = request(&service, "OPTIONS", "*", &[]).await;
    assert_eq!(options.status(), StatusCode::NO_CONTENT);
    assert!(!options.headers().contains_key(header::CONTENT_LENGTH));
    assert!(body(options).await.is_empty());
}

#[tokio::test]
async fn service_instances_keep_independent_roots() {
    let first = Fixture::new();
    let second = Fixture::new();
    fs::write(second.0.join("sample.TXT"), "another root").unwrap();
    let (first_service, second_service) = (first.service().await, second.service().await);
    let (first, second) = tokio::join!(
        request(&first_service, "GET", "/sample.TXT", &[]),
        request(&second_service, "GET", "/sample.TXT", &[]),
    );
    assert_eq!(body(first).await, "0123456789");
    assert_eq!(body(second).await, "another root");
}

#[tokio::test]
async fn configuration_merges_file_values_explicit_overrides_and_defaults() {
    let fixture = Fixture::new();
    let path = fixture.0.join("config.toml");
    fs::write(&path, "host = 'localhost'\nport = 1234\ncors = true\n").unwrap();
    let configuration = Configuration {
        config: Some(path.into_os_string()),
        port: Some(4321),
        ..Configuration::default()
    }
    .init()
    .await
    .unwrap();
    assert_eq!(configuration.host.as_deref(), Some("localhost"));
    assert_eq!(configuration.port, Some(4321));
    assert_eq!(
        configuration.home.as_deref(),
        Some(std::ffi::OsStr::new("."))
    );
    assert!(configuration.cors);
}

#[tokio::test]
async fn large_file_without_range_has_full_representation_metadata() {
    let fixture = Fixture::new();
    let path = fixture.0.join("large.bin");
    let size = 50 * 1024 * 1024 + 1;
    fs::File::create(path).unwrap().set_len(size).unwrap();
    let service = fixture.service().await;
    let response = request(&service, "GET", "/large.bin", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], size.to_string());
    assert!(!response.headers().contains_key(header::CONTENT_RANGE));
}

#[tokio::test]
async fn directory_listing_formats_modified_times_in_gmt() {
    let fixture = Fixture::new();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(fixture.0.join("sample.TXT"))
        .unwrap();
    file.set_modified(UNIX_EPOCH + std::time::Duration::from_secs(946_684_800))
        .unwrap();
    let service = fixture.service().await;
    let listing = body(request(&service, "GET", "/", &[]).await).await;
    let listing = std::str::from_utf8(&listing).unwrap();
    assert!(listing.contains("Last Modified (GMT)"));
    assert!(listing.contains("Sat, 01 Jan 2000 00:00:00 GMT"));
}
