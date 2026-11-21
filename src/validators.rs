use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use std::{
    fs::Metadata,
    io::{self, SeekFrom},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

pub(crate) async fn file_tag(
    file: &mut File,
    metadata: &Metadata,
    coding: Option<&str>,
) -> io::Result<HeaderValue> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut remaining = metadata.len();
    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..length]).await?;
        hasher.update(&buffer[..length]);
        remaining -= length as u64;
    }
    let current = file.metadata().await?;
    if current.len() != metadata.len() || current.modified().ok() != metadata.modified().ok() {
        return Err(io::Error::other(
            "file changed while computing its entity tag",
        ));
    }
    file.seek(SeekFrom::Start(0)).await?;

    let hash = hasher.finalize();
    let tag = match coding {
        Some(coding) => format!("W/\"sha256-{hash:x}-{coding}\""),
        None => format!("\"sha256-{hash:x}\""),
    };
    Ok(HeaderValue::from_str(&tag).expect("hash and coding form a valid header"))
}

pub(crate) fn matches(
    headers: &HeaderMap,
    name: HeaderName,
    tag: Option<&HeaderValue>,
    weak: bool,
) -> bool {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return false;
    };
    if first.as_bytes().trim_ascii() == b"*" && values.next().is_none() {
        return true;
    }
    let Some(tag) = tag else { return false };
    std::iter::once(first).chain(values).any(|value| {
        // Commas are allowed inside the opaque, quoted part of an entity tag.
        let mut quoted = false;
        value
            .as_bytes()
            .split(|byte| {
                if *byte == b'"' {
                    quoted = !quoted;
                }
                *byte == b',' && !quoted
            })
            .any(|candidate| {
                let candidate = candidate.trim_ascii();
                let tag = tag.as_bytes();
                if weak {
                    candidate.strip_prefix(b"W/").unwrap_or(candidate)
                        == tag.strip_prefix(b"W/").unwrap_or(tag)
                } else {
                    !tag.starts_with(b"W/") && candidate == tag
                }
            })
    })
}
