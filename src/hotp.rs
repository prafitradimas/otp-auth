use crate::{Algorithm, Secret, encoding, hmac};

pub struct Hotp {
    alg: Algorithm,
    issuer: String,
    label: String,
    digits: u8,
    counter: u64,
    secret: Secret,
}

impl Default for Hotp {
    fn default() -> Self {
        Self {
            alg: Algorithm::default(),
            issuer: String::new(),
            label: String::new(),
            digits: 6,
            counter: 0,
            secret: Default::default(),
        }
    }
}

impl Hotp {
    /// Creates a new [`Hotp`] instance with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `alg` - The hashing algorithm to use (e.g., [`Algorithm::SHA1`], [`Algorithm::SHA256`], or [`Algorithm::SHA512`]).
    /// * `issuer` - The name of the service or provider (e.g., `"GitHub"` or `"example.com"`).
    /// * `label` - An identifier for the user account (e.g., `"alice@example.com"`).
    /// * `digits` - Number of digits in the generated OTP (typically 6 or 8).
    /// * `counter` - Initial counter value for HOTP generation.
    /// * `secret` - The shared secret key used to generate the HMAC.
    ///
    /// # Returns
    ///
    /// Returns a new instance of [`Hotp`] configured with the provided parameters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use otp::{Hotp, Algorithm, Secret};
    ///
    /// let hotp = Hotp::new(
    ///     Algorithm::SHA1,
    ///     "example".into(),
    ///     "alice@example.com".into(),
    ///     6,
    ///     0,
    ///     Secret::from_bytes(b"supersecret"),
    /// );
    /// ```
    pub fn new(
        alg: Algorithm,
        issuer: String,
        label: String,
        digits: u8,
        counter: u64,
        secret: Secret,
    ) -> Self {
        Self {
            alg,
            issuer,
            label,
            digits,
            counter,
            secret,
        }
    }

    /// Generates the next OTP value and increments the internal counter.
    ///
    /// This method uses the current counter value, produces a new HOTP code,
    /// then advances the internal counter by one.
    ///
    /// Internally uses `generate_at` and follows the [HOTP Algorithm]
    /// specified in [RFC 4226].
    ///
    /// # Returns
    /// A numeric HOTP code as a `u32`.
    ///
    /// # Example
    /// ```rust
    /// let mut hotp = otp::Hotp::default();
    /// let otp = hotp.generate();
    /// println!("OTP: {}", otp);
    /// ```
    ///
    /// [HOTP Algorithm]: <https://datatracker.ietf.org/doc/html/rfc4226>
    /// [RFC 4226]: <https://datatracker.ietf.org/doc/html/rfc4226#section-5.3>
    pub fn generate(&mut self) -> u32 {
        let otp = self.generate_at(self.counter);
        self.counter += 1;
        otp
    }

    /// Generates an OTP value at a specific counter value, without modifying internal state.
    ///
    /// This method is useful for verifying or regenerating a known HOTP value at a given counter.
    ///
    /// It uses HMAC with the configured algorithm (SHA-1, SHA-256, etc.), then applies dynamic
    /// truncation as described in [RFC 4226].
    ///
    /// # Arguments
    /// * `counter` - The counter value at which to generate the OTP
    ///
    /// # Returns
    /// A numeric OTP code as a `u32`.
    ///
    /// # Example
    /// ```rust
    /// let hotp = otp::Hotp::default();
    /// let otp = hotp.generate_at(1234);
    /// ```
    ///
    /// # References
    /// - [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226#section-5.3)
    pub fn generate_at(&self, counter: u64) -> u32 {
        let message = counter.to_be_bytes();

        let hmac_result = hmac(self.alg, self.secret.as_bytes(), &message);

        let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;

        let code = ((u32::from(hmac_result[offset]) & 0x7f) << 24)
            | (u32::from(hmac_result[offset + 1]) << 16)
            | (u32::from(hmac_result[offset + 2]) << 8)
            | u32::from(hmac_result[offset + 3]);

        code % 10_u32.pow(self.digits as u32)
    }

    /// Verifies a provided OTP code against a given counter value, allowing for a window of flexibility.
    ///
    /// This method compares the given `otp` with the expected values generated
    /// at `counter - window` to `counter + window`. This accounts for clock drift
    /// or synchronization delays.
    ///
    /// # Arguments
    /// * `otp`     - The OTP code to verify
    /// * `counter` - The current known counter (typically stored server-side)
    /// * `window`  - How many counter steps before and after to check
    ///
    /// # Returns
    /// `true` if a match is found within the window range, `false` otherwise.
    ///
    /// # Example
    /// ```rust
    /// let hotp = otp::Hotp::default();
    /// let otp = hotp.generate_at(5);
    /// assert!(hotp.verify(otp, 5, 1)); // exact match
    /// assert!(hotp.verify(otp, 6, 1)); // match in past window
    /// assert!(!hotp.verify(otp, 10, 2)); // out of range
    /// ```
    ///
    /// # References
    /// - [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226#section-5.4)
    pub fn verify(&self, otp: u32, counter: u64, window: u64) -> bool {
        if self.generate_at(counter) == otp {
            return true;
        }

        for i in 1..=window {
            if counter >= i && self.generate_at(counter - i) == otp {
                return true;
            }
            if self.generate_at(counter + i) == otp {
                return true;
            }
        }

        false
    }

    /// Generates a Key URI string in the format compatible with Google Authenticator and other TOTP/HOTP apps.
    ///
    /// This URI can be encoded as a QR code and scanned by authenticator apps (e.g., Google Authenticator, Authy)
    /// to configure the OTP settings automatically.
    ///
    /// The URI format follows the [Key URI Format] specification:
    ///
    /// ```text
    /// otpauth://TYPE/LABEL?PARAMETERS
    /// ```
    ///
    /// For example, a TOTP URI might look like:
    ///
    /// ```text
    /// otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30
    /// ```
    ///
    /// # Format Details
    /// - `TYPE`: Either `totp` or `hotp`
    /// - `LABEL`: Usually `issuer:account`, URL-encoded
    /// - `secret`: Base32-encoded secret key
    /// - `issuer`: The provider or service name (optional, but recommended)
    /// - `algorithm`: Hash function used (e.g., SHA1, SHA256, SHA512)
    /// - `digits`: Number of digits in the OTP (typically 6 or 8)
    /// - `period` (TOTP only): Time step in seconds (e.g., 30)
    /// - `counter` (HOTP only): Current counter value
    ///
    /// # Returns
    /// A `String` containing the `otpauth://` URI.
    ///
    /// # Example
    /// ```rust
    /// use otp::{Totp, Algorithm, Secret};
    ///
    /// let totp = Totp::new(
    ///     Algorithm::SHA256,
    ///     "Example".into(),
    ///     "alice@example.com".into(),
    ///     6,
    ///     30,
    ///     Secret::from_bytes(b"supersecretkey")
    /// );
    ///
    /// let uri = totp.to_uri();
    /// assert!(uri.starts_with("otpauth://totp/"));
    /// ```
    ///
    /// [Key URI Format]: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    pub fn to_uri(&self) -> String {
        let secret = self.secret.into_base32();
        let label = if self.issuer().is_empty() {
            encoding::url::encode(self.label().as_bytes())
        } else {
            encoding::url::encode(format!("{}:{}", &self.issuer(), &self.label()).as_bytes())
        };
        let issuer = if !self.issuer().is_empty() {
            format!(
                "&issuer={}",
                encoding::url::encode(self.issuer().as_bytes())
            )
        } else {
            String::new()
        };
        let digits = self.digits;
        let counter = self.counter;
        let alg = self.alg.to_string();

        format!(
            "otpauth://hotp/{label}?secret={secret}{issuer}&algorithm={alg}&digits={digits}&counter={counter}"
        )
    }

    #[inline]
    pub fn alg(&self) -> Algorithm {
        self.alg
    }

    #[inline]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[inline]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[inline]
    pub fn digits(&self) -> u8 {
        self.digits
    }

    #[inline]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    #[inline]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Parses a HOTP configuration from a URI string in the [Key URI Format].
    ///
    /// This function supports URIs of the form:
    /// `otpauth://hotp/{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&counter={counter}`
    ///
    /// # Arguments
    ///
    /// * `uri` - A string slice containing the HOTP URI.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Hotp)` if the URI is valid and can be parsed. Otherwise returns `Err(Error)`
    /// indicating the reason for failure.
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    ///
    /// - URI does not start with the `otpauth://hotp/` scheme.
    /// - Missing or empty label in the URI.
    /// - Missing or invalid query parameters (e.g., `secret`, `counter`).
    /// - Unsupported or invalid algorithm name.
    /// - Base32 decoding of the secret fails.
    /// - Convert string errors (e.g., `counter`, `digits`).
    /// - Invalid percent-encoding in the label or issuer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use otp::Hotp;
    ///
    /// let uri = "otpauth://hotp/example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=example&algorithm=SHA1&digits=6&counter=1";
    /// let hotp = Hotp::from_uri(uri).unwrap();
    /// assert_eq!(hotp.issuer(), "example");
    /// assert_eq!(hotp.label(), "alice@example.com");
    /// ```
    ///
    /// [Key URI Format]: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    pub fn from_uri(uri: &str) -> Result<Self, ParseUriError> {
        let rest = uri
            .strip_prefix("otpauth://hotp/")
            .ok_or(ParseUriError::InvalidPrefix)?;

        let (label_encoded, queries) = rest.split_once('?').ok_or(ParseUriError::InvalidFormat)?;
        if label_encoded.is_empty() {
            return Err(ParseUriError::InvalidLabel);
        }

        let label_decoded =
            encoding::url::decode(label_encoded).map_err(|_| ParseUriError::InvalidLabel)?;

        let (issuer_from_label, label) =
            if let Some((issuer, label)) = label_decoded.split_once(':') {
                (Some(issuer), label.to_string())
            } else {
                (None, label_decoded)
            };

        let params: std::collections::HashMap<&str, &str> = queries
            .split('&')
            .map(|param| match param.split_once('=') {
                Some((key, val)) => (key, val),
                None => (param, ""),
            })
            .collect();

        let digits = params.get("digits").map_or(Ok(6), |val| {
            val.parse::<u8>().map_err(|_| ParseUriError::InvalidDigits)
        })?;

        let counter = params
            .get("counter")
            .ok_or(ParseUriError::MissingCounter)
            .and_then(|val| {
                val.parse::<u64>()
                    .map_err(|_| ParseUriError::InvalidCounter)
            })?;

        let secret = params
            .get("secret")
            .ok_or(ParseUriError::MissingSecret)
            .and_then(|raw_secret| {
                Secret::from_base32(raw_secret).map_err(|_| ParseUriError::InvalidSecret)
            })?;

        let issuer_from_param = params
            .get("issuer")
            .map(|iss| encoding::url::decode(iss).map_err(|_| ParseUriError::InvalidIssuer))
            .transpose()?;

        let issuer = match (issuer_from_label, issuer_from_param) {
            (None, None) => Ok(String::new()),
            (None, Some(from_param)) => Ok(from_param),
            (Some(from_label), None) => Ok(from_label.to_string()),
            (Some(from_label), Some(from_param)) => {
                if from_label != from_param {
                    Err(ParseUriError::IssuerMismatch)
                } else {
                    Ok(from_param)
                }
            }
        }?;

        let alg = params
            .get("algorithm")
            .map(|alg| {
                let alg = alg.to_uppercase();
                match alg.as_str() {
                    "SHA1" => Ok(Algorithm::SHA1),
                    "SHA256" => Ok(Algorithm::SHA256),
                    "SHA512" => Ok(Algorithm::SHA512),
                    _ => Err(ParseUriError::InvalidAlgorithm),
                }
            })
            .transpose()?;

        Ok(Self::new(
            alg.unwrap_or(Algorithm::SHA1),
            issuer,
            label,
            digits,
            counter,
            secret,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseUriError {
    InvalidPrefix,
    InvalidFormat,
    InvalidLabel,
    InvalidIssuer,
    InvalidDigits,
    InvalidCounter,
    InvalidSecret,
    InvalidAlgorithm,
    IssuerMismatch,
    MissingSecret,
    MissingCounter,
}

impl std::fmt::Display for ParseUriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseUriError::InvalidPrefix => {
                        f.write_str("URI must start with 'otpauth://hotp/'. Missing or incorrect prefix.")
                    }
            ParseUriError::InvalidFormat => {
                        f.write_str("URI has an incorrect general format. Ensure it follows 'otpauth://type/label?parameters'.")
                    }
            ParseUriError::InvalidLabel => {
                        f.write_str("The label (account name) in the URI is invalid or missing. Ensure it's properly encoded.")
                    }
            ParseUriError::InvalidIssuer => {
                        f.write_str("The 'issuer' parameter is invalid or missing a value. Ensure it's present and correctly encoded.")
                    }
            ParseUriError::InvalidDigits => {
                        f.write_str("The 'digits' parameter is invalid. It must be a positive integer, typically 6 or 8.")
                    }
            ParseUriError::InvalidSecret => {
                        f.write_str("The 'secret' parameter is invalid or not properly base32 encoded.")
                    }
            ParseUriError::InvalidAlgorithm => {
                        f.write_str("The 'algorithm' parameter is invalid. Expected 'SHA1', 'SHA256', or 'SHA512'.")
                    }
            ParseUriError::IssuerMismatch => {
                        f.write_str("The issuer specified in the label does not match the 'issuer' parameter.")
                    }
            ParseUriError::MissingSecret => {
                        f.write_str("The 'secret' parameter is required but missing from the URI.")
                    }
            ParseUriError::InvalidCounter => {
                        f.write_str("The 'counter' parameter is invalid. It must be a positive integer.")
            },
            ParseUriError::MissingCounter => {
                        f.write_str("The 'counter' parameter is required but missing from the URI.")
            },
        }
    }
}

impl std::error::Error for ParseUriError {}

#[cfg(test)]
impl Eq for Hotp {}

#[cfg(test)]
impl PartialEq for Hotp {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg
            && self.issuer == other.issuer
            && self.label == other.label
            && self.digits == other.digits
            && self.secret == other.secret
    }
}

#[cfg(test)]
impl std::fmt::Debug for Hotp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hotp")
            .field("alg", &self.alg.to_string())
            .field("issuer", &self.issuer)
            .field("label", &self.label)
            .field("digits", &self.digits)
            .field("counter", &self.counter)
            .field("secret", &self.secret)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_uri() {
        let alg = Algorithm::SHA512;
        let issuer = String::from("example");
        let label = String::from("alice@example.com");
        let digits = 6;
        let counter = 0;
        let secret = Secret::from_bytes(b"The quick brown fox jumps over the lazy dog");

        let hotp = Hotp::new(alg, issuer, label, digits, counter, secret);
        let hotp_uri = hotp.to_uri();

        let hotp_from_uri = Hotp::from_uri(&hotp_uri).expect("parse error");

        assert_eq!(hotp_uri, hotp_from_uri.to_uri(), "should have same uri");
        assert_eq!(hotp, hotp_from_uri, "should be equal");
    }

    #[test]
    fn test_from_uri_with_invalid_prefix() {
        let uri =
            "otpauth://totp/issuer:alice@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1024";
        let result = Hotp::from_uri(uri);
        assert!(
            matches!(result, Err(ParseUriError::InvalidPrefix)),
            "should be invalid prefix"
        );
    }

    #[test]
    fn test_from_uri_with_missing_counter() {
        let uri =
            "otpauth://hotp/issuer:alice@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1024";
        let result = Hotp::from_uri(uri);
        assert!(
            matches!(result, Err(ParseUriError::MissingCounter)),
            "should be missing counter"
        );
    }

    #[test]
    fn test_from_uri_with_missing_secret() {
        let uri = "otpauth://hotp/issuer:alice@example.com?algorithm=SHA1024&counter=69420";
        let result = Hotp::from_uri(uri);
        assert!(
            matches!(result, Err(ParseUriError::MissingSecret)),
            "should be missing secret"
        );
    }

    #[test]
    fn test_from_uri_with_invalid_algorithm() {
        let uri = "otpauth://hotp/issuer:alice@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1024&counter=69";
        let result = Hotp::from_uri(uri);
        assert!(
            matches!(result, Err(ParseUriError::InvalidAlgorithm)),
            "should be invalid algorithm"
        );
    }

    #[test]
    fn test_from_uri_with_invalid_uri_encoding() {
        let uri = "otpauth://hotp/issuer%ZZ:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        let result = Hotp::from_uri(uri);
        assert!(
            matches!(result, Err(ParseUriError::InvalidLabel)),
            "should be invalid label"
        );
    }

    #[test]
    fn test_from_uri_with_issuer_mismatch() {
        let uri = "otpauth://hotp/javascript:alice@example.com?secret=JBSWY3DPEHPK3PXP&counter=69&issuer=rust";
        let result = Hotp::from_uri(uri);
        assert!(matches!(result, Err(ParseUriError::IssuerMismatch)));
    }

    #[test]
    fn test_from_uri_with_invalid_format() {
        let uri = "otpauth://hotp/javascript:alice@example.com&secret=JBSWY3DPEHPK3PXP&counter=69&issuer=rust";
        let result = Hotp::from_uri(uri);
        assert!(matches!(result, Err(ParseUriError::InvalidFormat)));
    }
}
