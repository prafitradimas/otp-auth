# otp-auth

A Rust implementation of [HOTP](https://datatracker.ietf.org/doc/html/rfc4226) and [TOTP](https://datatracker.ietf.org/doc/html/rfc6238) based one-time passwords.  

---

## Features

- HOTP (HMAC-based OTP)
- TOTP (Time-based OTP)
- SHA-1, SHA-256, SHA-512 algorithms
- URI generation (compatible with Google Authenticator)

---

## Examples

```rust
use otp::{Totp, Algorithm, Secret};

let totp = Totp::new(
    Algorithm::SHA1,
    "example.com".into(),
    "user@example.com".into(),
    6,
    30,
    Secret::from_bytes(b"my-secret"),
);

let timestamp = 1_720_000_000; // example UNIX timestamp
let otp = totp.generate_at(timestamp);

assert!(totp.verify(otp, timestamp, 1));
```

## References

- [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) — HMAC: Keyed-Hashing for Message Authentication
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) — HOTP: An HMAC-Based One-Time Password Algorithm
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP: Time-Based One-Time Password Algorithm
- [RFC 3174](https://datatracker.ietf.org/doc/html/rfc3174/) — US Secure Hash Algorithm 1 (SHA1)
- [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) — US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
- [RFC 2202](https://datatracker.ietf.org/doc/html/rfc2202) — Test Cases for HMAC-MD5 and HMAC-SHA-1
- [RFC 4231](https://datatracker.ietf.org/doc/html/rfc4231) — Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
- [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) — The Base16, Base32, and Base64 Data Encodings
- [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) — Uniform Resource Identifier (URI): Generic Syntax
- [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) — for QR-compatible URIs

## LICENSE

This work is released under the MIT license. A copy of the license is provided in the [LICENSE](./LICENSE) file.
