use std::borrow::Cow;

const HEX: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) fn push_encoded_segment(output: &mut String, segment: &str) {
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
}

pub(crate) fn decode_segment(segment: &str) -> Option<Cow<'_, str>> {
    let Some(first_escape) = segment.find('%') else {
        return Some(Cow::Borrowed(segment));
    };
    let (prefix, escapes) = segment.as_bytes().split_at(first_escape);
    let mut decoded = Vec::with_capacity(segment.len());
    decoded.extend_from_slice(prefix);
    let mut remaining = escapes;

    while let [first, rest @ ..] = remaining {
        // Keep literal plus signs and incomplete or invalid escapes.
        if let [b'%', high, low, tail @ ..] = remaining
            && let (Some(high), Some(low)) = (hex_value(*high), hex_value(*low))
        {
            decoded.push((high << 4) | low);
            remaining = tail;
        } else {
            decoded.push(*first);
            remaining = rest;
        }
    }
    String::from_utf8(decoded).ok().map(Cow::Owned)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_bytes_outside_the_unreserved_set() {
        let mut output = String::from("/files/");
        push_encoded_segment(&mut output, "Az09-._~ +%文件#?");
        assert_eq!(output, "/files/Az09-._~%20%2B%25%E6%96%87%E4%BB%B6%23%3F");
    }

    #[test]
    fn decodes_once_and_preserves_literal_characters() {
        for (encoded, decoded) in [
            ("file+name", "file+name"),
            ("%2b+%20", "++ "),
            ("%2520", "%20"),
            ("%e6%96%87%E4%BB%B6", "文件"),
            ("a%zz%2Gb%4%", "a%zz%2Gb%4%"),
            ("%%41", "%A"),
        ] {
            assert_eq!(
                decode_segment(encoded).as_deref(),
                Some(decoded),
                "{encoded}"
            );
        }
        assert!(decode_segment("%FF").is_none());
    }
}
