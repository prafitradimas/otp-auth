//! Base16 encoding/decoding, using [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-8) alphabet.

/// # Example:
/// ```rust
/// use otp::encoding::hex;
///
/// let bytes: [u8; 4] = [9, 10, 11, 12];
/// let encoded = hex::encode(&bytes);
/// assert_eq!("090a0b0c", encoded.as_str());
/// ```
pub fn encode(data: &[u8]) -> String {
    data.iter()
        .map(|&b| unsafe {
            let i = 2 * b as usize;
            HEX_BYTES.get_unchecked(i..i + 2)
        })
        .collect()
}

/// # Example:
/// ```rust
/// use otp::encoding::hex;
///
/// let input = "090A0B0C";
/// let decoded = hex::decode(input).expect("Decoding failed");
/// assert_eq!([9, 10, 11, 12], decoded.as_slice());
///
/// let input_odd_err = "090A0B0CZ";
/// let result_odd_err = hex::decode(input_odd_err);
/// assert!(matches!(result_odd_err, Err(hex::DecodeHexError::InvalidLength)));
///
/// let input_parse_int_err = "090A0B0CZZ";
/// let result_parse_int_err = hex::decode(input_parse_int_err);
/// assert!(matches!(result_parse_int_err, Err(hex::DecodeHexError::ParseInt(_))));
/// ```
pub fn decode(data: &str) -> Result<Vec<u8>, DecodeHexError> {
    if data.len() & 1 != 0 {
        Err(DecodeHexError::InvalidLength)
    } else {
        (0..data.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&data[i..i + 2], 16).map_err(DecodeHexError::ParseInt))
            .collect()
    }
}

#[derive(Debug)]
pub enum DecodeHexError {
    InvalidLength,
    ParseInt(std::num::ParseIntError),
}

impl std::error::Error for DecodeHexError {}

impl std::fmt::Display for DecodeHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeHexError::ParseInt(e) => e.fmt(f),
            DecodeHexError::InvalidLength => "input has an odd number of bytes".fmt(f),
        }
    }
}

const HEX_BYTES: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                         404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
                         606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                         808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                         a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                         c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                         e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
