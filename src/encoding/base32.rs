//! Base32 encoding/decoding without padding, using [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-6) alphabet.

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// # Example
/// ```rust
/// use otp::encoding::base32;
///
/// let bytes = b"any + old & data";
/// let encoded = base32::encode(bytes);
/// assert_eq!("MFXHSIBLEBXWYZBAEYQGIYLUME", encoded.as_str());
/// ```
pub fn encode(data: &[u8]) -> String {
    let mut encoded = String::with_capacity((data.len() * 8).div_ceil(5));

    let mut buffer = 0_u16;
    let mut bits_left = 0;

    for &byte in data {
        buffer <<= 8;
        buffer |= byte as u16;
        bits_left += 8;

        while bits_left >= 5 {
            let index = (buffer >> (bits_left - 5)) & 0x1F;
            encoded.push(BASE32_ALPHABET[index as usize] as char);
            bits_left -= 5;
        }
    }

    if bits_left > 0 {
        let index = (buffer << (5 - bits_left)) & 0x1F;
        encoded.push(BASE32_ALPHABET[index as usize] as char);
    }

    encoded
}

/// # Example:
/// ```rust
/// use otp::encoding::base32;
///
/// let hello_world = "JBSWY3DPFQQHO33SNRSCC";
/// let decoded = base32::decode(hello_world).expect("Decoding failed");
/// assert_eq!(b"Hello, world!", decoded.as_slice());
/// assert_eq!(hello_world, base32::encode(b"Hello, world!"));
///
/// let hello_world_with_pad = "JBSWY3DPFQQHO33SNRSCC===";
/// let result_invalid_err = base32::decode(hello_world_with_pad);
/// assert!(matches!(result_invalid_err, Err(base32::DecodeBase32Error::InvalidChar(_))));
/// ```
pub fn decode(data: &str) -> Result<Vec<u8>, DecodeBase32Error> {
    let mut output = Vec::with_capacity((data.len() * 5) / 8);

    let mut buffer = 0_u32;
    let mut bits_left = 0;

    for b in data.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return Err(DecodeBase32Error::InvalidChar(b as char)),
        } as u32;

        buffer = (buffer << 5) | val;
        bits_left += 5;

        if bits_left >= 8 {
            output.push((buffer >> (bits_left - 8)) as u8);
            bits_left -= 8;
        }
    }

    Ok(output)
}

#[derive(Debug, Clone)]
pub enum DecodeBase32Error {
    InvalidChar(char),
}

impl std::fmt::Display for DecodeBase32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeBase32Error::InvalidChar(c) => write!(f, "invalid base32 character: '{c}'"),
        }
    }
}

impl std::error::Error for DecodeBase32Error {}
