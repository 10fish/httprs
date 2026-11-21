use crate::{
    Compression,
    http::{StaticBody, stream_body},
};
use async_compression::tokio::bufread::{GzipEncoder, ZlibEncoder};
use hyper::header::{self, HeaderMap};
use tokio::io::{AsyncRead, BufReader};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Identity,
    Gzip,
    Deflate,
}

impl Encoding {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }

    pub(crate) fn select(
        compression: &Compression,
        headers: &HeaderMap,
        prefer_identity: bool,
    ) -> Option<Self> {
        let configured = match compression {
            Compression::Gzip => Self::Gzip,
            Compression::Deflate => Self::Deflate,
            Compression::Other => unreachable!("compression validated at configuration"),
        };
        let mut configured_quality = None;
        let mut identity_quality = None;
        let mut wildcard_quality = None;
        for value in headers.get_all(header::ACCEPT_ENCODING) {
            let Ok(value) = value.to_str() else { continue };
            for item in value.split(',') {
                let (coding, quality) = item.trim().split_once(';').map_or_else(
                    || (item.trim(), 1000),
                    |(coding, weight)| {
                        (coding.trim_end(), parse_quality(weight.trim()).unwrap_or(0))
                    },
                );
                let target = if coding.eq_ignore_ascii_case(configured.name()) {
                    &mut configured_quality
                } else if coding.eq_ignore_ascii_case("identity") {
                    &mut identity_quality
                } else if coding == "*" {
                    &mut wildcard_quality
                } else {
                    continue;
                };
                *target = Some(target.map_or(quality, |previous: u16| previous.max(quality)));
            }
        }

        let quality = configured_quality.or(wildcard_quality).unwrap_or(0);
        let identity =
            identity_quality.unwrap_or(if wildcard_quality == Some(0) { 0 } else { 1000 });
        if quality > 0
            && (identity == 0 || (!prefer_identity && quality >= identity_quality.unwrap_or(0)))
        {
            Some(configured)
        } else if identity > 0 {
            Some(Self::Identity)
        } else {
            None
        }
    }

    pub(crate) fn encode(self, reader: impl AsyncRead + Send + 'static) -> StaticBody {
        match self {
            Self::Identity => stream_body(reader),
            Self::Gzip => stream_body(GzipEncoder::new(BufReader::new(reader))),
            Self::Deflate => stream_body(ZlibEncoder::new(BufReader::new(reader))),
        }
    }
}

fn parse_quality(weight: &str) -> Option<u16> {
    let (name, value) = weight.split_once('=')?;
    if !name.eq_ignore_ascii_case("q") {
        return None;
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let thousandths = fraction
        .bytes()
        .enumerate()
        .map(|(index, digit)| u16::from(digit - b'0') * [100, 10, 1][index])
        .sum::<u16>();
    match whole {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}
