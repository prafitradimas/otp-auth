//! Cryptographic hash algorithm implementations for HMAC-based OTPs.
//!
//! This module provides support for SHA-1, SHA-256, and SHA-512 algorithms,
//! as defined in [RFC 4226] (HOTP) and [RFC 6238] (TOTP).
//!
//! It exposes a common [`Algorithm`] enum used for abstracting over the different hash functions,
//! with convenience methods for computing hashes in both raw bytes and hexadecimal formats.
//!
//! # Examples
//! ```rust
//! use otp::Algorithm;
//!
//! let data = b"The quick brown fox jumps over the lazy dog";
//! let alg = Algorithm::SHA256;
//!
//! let hex_hash = alg.hash_hex(data);
//! println!("SHA-256: {}", hex_hash);
//!
//! let raw_hash = alg.hash_bytes(data);
//! assert_eq!(raw_hash.len(), 32); // 256-bit output
//! ```
//!
//! [RFC 4226]: https://datatracker.ietf.org/doc/html/rfc4226
//! [RFC 6238]: https://datatracker.ietf.org/doc/html/rfc6238

mod sha1;
mod sha256;
mod sha512;

pub use self::sha1::sha1;
pub use self::sha256::sha256;
pub use self::sha512::sha512;

/// Enumeration of supported cryptographic hash algorithms for use with HMAC.
///
/// This enum allows users to choose between SHA-1, SHA-256, and SHA-512
/// as required by OTP generation specifications.
///
/// The default value is `SHA1`, which is the original algorithm used in HOTP.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Algorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl Algorithm {
    /// Hashes binary input data using the selected algorithm, returning the result as a hex string.
    ///
    /// # Arguments
    /// * `data` - The input string to hash
    ///
    /// # Returns
    /// A hexadecimal representation of the hash output.
    ///
    /// # Example
    /// ```rust
    /// use otp::Algorithm;
    ///
    /// let sha1_hash = Algorithm::SHA1.hash_hex(b"");
    /// assert_eq!(sha1_hash.len(), 40); // 160-bit = 20 bytes = 40 hex chars
    ///
    /// let sha256_hash = Algorithm::SHA256.hash_hex(b"");
    /// assert_eq!(sha256_hash.len(), 64); // 256-bit = 32 bytes = 64 hex chars
    ///
    /// let sha512_hash = Algorithm::SHA512.hash_hex(b"");
    /// assert_eq!(sha512_hash.len(), 128); // 512-bit = 64 bytes = 128 hex chars
    /// ```
    pub fn hash_hex(&self, data: &[u8]) -> String {
        match self {
            Algorithm::SHA1 => crate::encoding::hex::encode(&self::sha1(data)),
            Algorithm::SHA256 => crate::encoding::hex::encode(&self::sha256(data)),
            Algorithm::SHA512 => crate::encoding::hex::encode(&self::sha512(data)),
        }
    }

    /// Hashes binary input data using the selected algorithm, returning raw bytes.
    ///
    /// # Arguments
    /// * `data` - A byte slice of input data to hash
    ///
    /// # Returns
    /// A `Vec<u8>` containing the hash output.
    ///
    /// # Example
    /// ```rust
    /// use otp::Algorithm;
    ///
    /// let sha1_hash = Algorithm::SHA1.hash_bytes(b"");
    /// assert_eq!(sha1_hash.len(), 20); // 160-bit = 20 bytes
    ///
    /// let sha256_hash = Algorithm::SHA256.hash_bytes(b"");
    /// assert_eq!(sha256_hash.len(), 32); // 256-bit = 32 bytes
    ///
    /// let sha512_hash = Algorithm::SHA512.hash_bytes(b"");
    /// assert_eq!(sha512_hash.len(), 64); // 512-bit = 64 bytes
    /// ```
    pub fn hash_bytes(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::SHA1 => self::sha1(data).to_vec(),
            Algorithm::SHA256 => self::sha256(data).to_vec(),
            Algorithm::SHA512 => self::sha512(data).to_vec(),
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::SHA1 => f.write_str("SHA1"),
            Algorithm::SHA256 => f.write_str("SHA256"),
            Algorithm::SHA512 => f.write_str("SHA512"),
        }
    }
}
