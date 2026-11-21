use bytes::Bytes;
use futures_util::stream;
use hyper::header::HeaderValue;
use std::fmt;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, ReadBuf};
use tokio_util::io::StreamReader;

/// HTTP request header `RANGE` value regex. usually it can be one of following forms:
/// ```text
/// Range: <unit>=<range-start>-
/// Range: <unit>=<range-start>-<range-end>
/// Range: <unit>=<range-start>-<range-end>, <range-start>-<range-end>
/// Range: <unit>=<range-start>-<range-end>, <range-start>-<range-end>, <range-start>-<range-end>
/// Range: <unit>=-<suffix-length>
/// ```
pub const HEADER_RANGE_VALUE_REGEX: &str = r"^(bytes)=(.+)$";

/// consists of a range with a start or an end(if not, it means to the start or end of the target file).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Segment {
    RemainingFrom(u64),
    Regional(u64, u64),
    RemainingSize(u64),
}

/// represents the HTTP Request Header value of `header::RANGE`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Range {
    pub unit: String,
    pub segments: Vec<Segment>,
    pub combined: bool,
    pub filesize: Option<u64>,
}

pub(crate) const RANGE_UNIT: &str = "bytes";
const MAX_RANGE_SEGMENTS: usize = 16;

impl Default for Range {
    fn default() -> Self {
        Self::new()
    }
}

impl Range {
    pub fn new() -> Self {
        Self {
            unit: RANGE_UNIT.to_owned(),
            segments: Vec::new(),
            combined: false,
            filesize: None,
        }
    }

    /// Unsupported or invalid fields produce an empty range.
    pub fn from(value: &HeaderValue) -> Self {
        let mut range = Self::new();
        if let Some(segments) = parse_ranges(value) {
            range.segments = segments;
        }
        range
    }

    pub fn adjust(&mut self, filesize: u64) -> &mut Self {
        self.filesize = Some(filesize);
        self
    }

    /// Resolve ranges against the file size and merge adjacent or overlapping segments.
    pub fn combine_segments(&mut self) {
        let Some(filesize) = self.filesize else {
            return;
        };
        self.segments = coalesce(&self.segments, filesize)
            .into_iter()
            .map(|(start, end, _)| Segment::Regional(start, end))
            .collect();
        self.combined = true;
    }
}

/// Resolve, merge, and retain each group's earliest position in the request.
pub(crate) fn coalesce(segments: &[Segment], filesize: u64) -> Vec<(u64, u64, usize)> {
    let Some(last) = filesize.checked_sub(1) else {
        return Vec::new();
    };
    let mut resolved: Vec<_> = segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| {
            let (start, end) = match *segment {
                Segment::RemainingSize(size) if size > 0 => (filesize.saturating_sub(size), last),
                Segment::RemainingFrom(start) if start <= last => (start, last),
                Segment::Regional(start, end) if start <= last && start <= end => {
                    (start, end.min(last))
                }
                _ => return None,
            };
            Some((start, end, index))
        })
        .collect();
    resolved.sort_unstable();

    let mut combined: Vec<(u64, u64, usize)> = Vec::new();
    for (start, end, index) in resolved {
        match combined.last_mut() {
            Some((_, previous_end, previous_index)) if start <= previous_end.saturating_add(1) => {
                *previous_end = (*previous_end).max(end);
                *previous_index = (*previous_index).min(index);
            }
            _ => combined.push((start, end, index)),
        }
    }
    combined
}

pub(crate) fn parse_ranges(value: &HeaderValue) -> Option<Vec<Segment>> {
    let (unit, values) = value.to_str().ok()?.split_once('=')?;
    if !unit.eq_ignore_ascii_case(RANGE_UNIT) {
        return None;
    }

    let mut segments = Vec::new();
    for (index, value) in values.split(',').enumerate() {
        if index >= MAX_RANGE_SEGMENTS {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if value.is_empty() {
            continue;
        }
        let (first, last) = value.split_once('-')?;
        let segment = match (first, last) {
            ("", suffix) => Segment::RemainingSize(decimal(suffix)?),
            (start, "") => Segment::RemainingFrom(decimal(start)?),
            (start, end) => {
                let offset = decimal(start)?;
                let limit = decimal(end)?;
                let start = start.trim_start_matches('0');
                let end = end.trim_start_matches('0');
                if (start.len(), start) > (end.len(), end) {
                    return None;
                }
                Segment::Regional(offset, limit)
            }
        };
        segments.push(segment);
    }
    (!segments.is_empty()).then_some(segments)
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(value.bytes().fold(0u64, |number, digit| {
        number
            .saturating_mul(10)
            .saturating_add(u64::from(digit - b'0'))
    }))
}

/// Asynchronous reader for a multipart/byteranges response.
pub struct MultipartByteRanges {
    reader: Pin<Box<dyn AsyncRead + Send + Sync>>,
}

impl fmt::Debug for MultipartByteRanges {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultipartByteRanges")
            .finish_non_exhaustive()
    }
}

impl MultipartByteRanges {
    pub(crate) fn new(
        file: File,
        content_type: &str,
        ranges: &[(u64, u64)],
        size: u64,
        boundary: &str,
    ) -> Self {
        let mut parts = ranges.iter().enumerate().map(|(index, &(start, end))| {
            let separator = if index == 0 { "" } else { "\r\n" };
            let headers = format!(
                "{separator}--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{size}\r\n\r\n"
            );
            (Bytes::from(headers), start, end - start + 1)
        }).collect::<Vec<_>>();
        parts.push((Bytes::from(format!("\r\n--{boundary}--\r\n")), 0, 0));

        let stream = stream::try_unfold(
            (file, parts.into_iter(), 0u64),
            |(mut file, mut parts, remaining)| async move {
                if remaining > 0 {
                    let mut buffer = vec![0; remaining.min(16 * 1024) as usize];
                    file.read_exact(&mut buffer).await?;
                    let remaining = remaining - buffer.len() as u64;
                    return Ok(Some((Bytes::from(buffer), (file, parts, remaining))));
                }
                let Some((headers, start, length)) = parts.next() else {
                    return Ok::<_, io::Error>(None);
                };
                if length > 0 {
                    file.seek(SeekFrom::Start(start)).await?;
                }
                Ok(Some((headers, (file, parts, length))))
            },
        );
        Self {
            reader: Box::pin(StreamReader::new(stream)),
        }
    }
}

impl AsyncRead for MultipartByteRanges {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reader.as_mut().poll_read(context, buffer)
    }
}

pub(crate) fn multipart_boundary() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("httprs-{:x}-{sequence:x}", now.as_nanos())
}
