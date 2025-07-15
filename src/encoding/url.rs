//! URL encoding/decoding, using [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-2.1) (Percent-encoding).

const SAFE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

/// # Example:
/// ```rust
/// use otp::encoding::url;
///
/// let s = b"hello@example.com";
/// let encoded = url::encode(s);
/// assert_eq!("hello%40example.com", encoded.as_str());
/// ```
pub fn encode(data: &[u8]) -> String {
    data.as_ref()
        .iter()
        .flat_map(|&b| {
            if SAFE_CHARS.contains(&b) {
                vec![b as char].into_iter()
            } else {
                let hex = format!("%{b:02X}");
                hex.chars().collect::<Vec<_>>().into_iter()
            }
        })
        .collect()
}

#[derive(Debug)]
pub enum DecodeUrlError {
    InvalidHex(String),
    UnexpectedEnd,
}

/// Percent-decodes a URL-encoded string.
pub fn decode(data: &str) -> Result<String, DecodeUrlError> {
    let input = data.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        match input[i] {
            b'%' => {
                if i + 2 >= input.len() {
                    return Err(DecodeUrlError::UnexpectedEnd);
                }
                let hex = &input[i + 1..=i + 2];
                let hex_str = std::str::from_utf8(hex).unwrap_or("");
                let byte = u8::from_str_radix(hex_str, 16)
                    .map_err(|_| DecodeUrlError::InvalidHex(hex_str.to_string()))?;
                output.push(byte as char);
                i += 3;
            }
            b => {
                output.push(b as char);
                i += 1;
            }
        }
    }

    Ok(output)
}

impl std::fmt::Display for DecodeUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeUrlError::InvalidHex(s) => write!(f, "invalid hex sequence '%{s}'"),
            DecodeUrlError::UnexpectedEnd => write!(f, "unexpected end of percent-encoding"),
        }
    }
}

impl std::error::Error for DecodeUrlError {}
