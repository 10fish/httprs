use httprs::*;
use hyper::header::HeaderValue;
use regex::Regex;
use std::path::PathBuf;

const TEST_FILE_SIZE: u64 = 2560000;

#[test]
fn local_ips_are_unique_ipv4_addresses() {
    let ips = get_all_local_ips();
    let unique: std::collections::HashSet<_> = ips.iter().collect();
    assert_eq!(unique.len(), ips.len());
    assert!(
        ips.iter()
            .all(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
    );
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
            .replace("{{href}}", link)
            .replace("{{label}}", label)
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

#[test]
fn test_parse_range_values() {
    let expected_ranges = [Segment::Regional(1024, 65535)];
    let actual = Range::from(&HeaderValue::from_static("bytes=1024-65535")).segments;
    assert_eq!(actual, expected_ranges);
}
