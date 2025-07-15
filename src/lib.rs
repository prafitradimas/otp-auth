//! # `otp` — Rust Implementation of HMAC and Time based one-time passwords.
//!
//! This crate provides a fully self-contained implementation of the [HOTP (HMAC-based One-Time Password)](https://datatracker.ietf.org/doc/html/rfc4226)
//! and [TOTP (Time-based One-Time Password)](https://datatracker.ietf.org/doc/html/rfc6238).
//!
//! ## Features
//! - **HOTP**: Counter-based one-time password generator and validator.
//! - **TOTP**: Time-based one-time password generator and validator.
//! - **URI generation**: Generate otpauth-compatible URIs for use with QR code generation (e.g., Google Authenticator).
//!
//! ## Example (TOTP)
//!
//! ```rust
//! use otp::{Totp, Algorithm, Secret};
//!
//! let totp = Totp::new(
//!     Algorithm::SHA1,
//!     "example.com".into(),
//!     "user@example.com".into(),
//!     6,
//!     30,
//!     Secret::from_bytes(b"my-secret"),
//! );
//!
//! let timestamp = std::time::SystemTime::now()
//!                     .duration_since(std::time::UNIX_EPOCH)
//!                     .expect("Clock may have gone backwards")
//!                     .as_secs();
//! let otp = totp.generate_at(timestamp);
//!
//! assert!(totp.verify(otp, timestamp, 1));
//!
//! println!("{}", totp.to_uri());
//! // "otpauth://totp/example.com%3Auser%40example.com?secret=NV4S243FMNZGK5A&issuer=example.com&algorithm=SHA1&digits=6&period=30"

//!
//! ```
//!
//! ## References
//! - [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) — HMAC: Keyed-Hashing for Message Authentication
//! - [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) — HOTP: An HMAC-Based One-Time Password Algorithm
//! - [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP: Time-Based One-Time Password Algorithm
//! - [RFC 3174](https://datatracker.ietf.org/doc/html/rfc3174/) — US Secure Hash Algorithm 1 (SHA1)
//! - [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) — US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
//! - [RFC 2202](https://datatracker.ietf.org/doc/html/rfc2202) — Test Cases for HMAC-MD5 and HMAC-SHA-1
//! - [RFC 4231](https://datatracker.ietf.org/doc/html/rfc4231) — Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
//! - [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) — The Base16, Base32, and Base64 Data Encodings
//! - [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) — Uniform Resource Identifier (URI): Generic Syntax
//! - [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) — for QR-compatible URIs

pub mod encoding;

mod alg;
mod hmac;
mod hotp;
mod secret;
mod totp;

pub use self::alg::Algorithm;
pub use self::hmac::hmac;
pub use self::hotp::Hotp;
pub use self::secret::Secret;
pub use self::totp::Totp;
