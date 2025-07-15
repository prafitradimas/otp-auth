use crate::alg::Algorithm;

const HMAC_INNER_PAD: u8 = 0x36;
const HMAC_OUTER_PAD: u8 = 0x5c;

/// Computes the HMAC (Hash-based Message Authentication Code) for a given key and message
/// using the specified hashing algorithm.
///
/// HMAC is a cryptographic mechanism defined in [RFC 2104] and commonly used in authentication
/// and data integrity protocols such as HOTP and TOTP.
///
/// Internally, it computes:
///
/// ```text
/// HMAC(key, message) = H((key ⊕ opad) || H((key ⊕ ipad) || message))
/// ```
///
/// Where:
/// - `H` is the selected hashing function (e.g. SHA1, SHA256, SHA512)
/// - `ipad` is the inner padding (0x36 repeated to block size)
/// - `opad` is the outer padding (0x5c repeated to block size)
///
/// # Parameters
///
/// - `alg`: The hashing algorithm to use (e.g. `Algorithm::SHA1`, `SHA256`, `SHA512`)
/// - `key`: The secret key used for HMAC computation (will be hashed if longer than block size)
/// - `message`: The message to authenticate
///
/// # Returns
///
/// A `Vec<u8>` containing the raw HMAC digest.
///
/// # Example
///
/// ```rust
/// use otp::{hmac, Algorithm};
///
/// let key = b"secret key";
/// let message = b"The quick brown fox";
///
/// let mac = hmac(Algorithm::SHA256, key, message);
/// assert_eq!(mac.len(), 32); // SHA256 produces 32-byte output
/// ```
///
/// [RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104
pub fn hmac(alg: Algorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    let block_size = match alg {
        Algorithm::SHA1 | Algorithm::SHA256 => 64,
        Algorithm::SHA512 => 128,
    };

    let mut key_block = vec![0_u8; block_size];

    if key.len() > block_size {
        let hashed = alg.hash_bytes(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_key_pad = vec![0_u8; block_size];
    let mut outer_key_pad = vec![0_u8; block_size];

    for i in 0..block_size {
        inner_key_pad[i] = key_block[i] ^ HMAC_INNER_PAD;
        outer_key_pad[i] = key_block[i] ^ HMAC_OUTER_PAD;
    }

    let mut inner = Vec::with_capacity(block_size + message.len());
    inner.extend_from_slice(&inner_key_pad);
    inner.extend_from_slice(message);
    let inner_hash = alg.hash_bytes(&inner);

    let mut outer = Vec::with_capacity(block_size + inner_hash.len());
    outer.extend_from_slice(&outer_key_pad);
    outer.extend_from_slice(&inner_hash);

    alg.hash_bytes(&outer)
}

/// # Sources:
/// All the test case is found here: https://datatracker.ietf.org/doc/html/rfc2202#section-3
#[cfg(test)]
mod hmac_sha1_tests {
    use super::*;
    use crate::encoding::hex::encode;

    #[test]
    fn test_case_1() {
        let key: Vec<u8> = (0..20).map(|_| 0x0b_u8).collect();
        let message = b"Hi There";

        let hash_bytes = hmac(Algorithm::SHA1, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "b617318655057264e28bc0b6fb378c8ef146be00";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_2() {
        let key: &[u8] = b"Jefe";
        let message = b"what do ya want for nothing?";

        let hash_bytes = hmac(Algorithm::SHA1, key, message);

        let actual = encode(&hash_bytes);
        let expect = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_3() {
        let key: Vec<u8> = (0..20).map(|_| 0xaa_u8).collect();
        let message: Vec<u8> = (0..50).map(|_| 0xdd_u8).collect();

        let hash_bytes = hmac(Algorithm::SHA1, &key, &message);

        let actual = encode(&hash_bytes);
        let expect = "125d7342b9ac11cd91a39af48aa17b4f63f175d3";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_4() {
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        let message: Vec<u8> = (0..50).map(|_| 0xcd_u8).collect();

        let hash_bytes = hmac(Algorithm::SHA1, &key, &message);

        let actual = encode(&hash_bytes);
        let expect = "4c9007f4026250c6bc8414f9bf50c86c2d7235da";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_5() {
        let key: Vec<u8> = (0..20).map(|_| 0x0c_u8).collect();
        let message = b"Test With Truncation";

        let hash_bytes = hmac(Algorithm::SHA1, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_6() {
        let key: Vec<u8> = (0..80).map(|_| 0xaa_u8).collect();
        let message = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let hash_bytes = hmac(Algorithm::SHA1, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "aa4ae5e15272d00e95705637ce8a3b55ed402112";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_7() {
        let key: Vec<u8> = (0..80).map(|_| 0xaa_u8).collect();
        let message = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

        let hash_bytes = hmac(Algorithm::SHA1, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91";

        assert_eq!(expect, actual);
    }
}

/// # Sources:
/// All the test case is found here: https://datatracker.ietf.org/doc/html/rfc4231#section-4
#[cfg(test)]
mod hmac_sha256_tests {
    use super::*;
    use crate::encoding::hex::encode;

    #[test]
    fn test_case_1() {
        let key: Vec<u8> = (0..20).map(|_| 0x0b_u8).collect();
        let message = b"Hi There";

        let hash_bytes = hmac(Algorithm::SHA256, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_2() {
        let key: &[u8] = b"Jefe";
        let message = b"what do ya want for nothing?";

        let hash_bytes = hmac(Algorithm::SHA256, key, message);

        let actual = encode(&hash_bytes);
        let expect = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_3() {
        let key: Vec<u8> = (0..20).map(|_| 0xaa_u8).collect();
        let message: Vec<u8> = (0..50).map(|_| 0xdd_u8).collect();

        let hash_bytes = hmac(Algorithm::SHA256, &key, &message);

        let actual = encode(&hash_bytes);
        let expect = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_4() {
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        let message: Vec<u8> = (0..50).map(|_| 0xcd_u8).collect();

        let hash_bytes = hmac(Algorithm::SHA256, &key, &message);

        let actual = encode(&hash_bytes);
        let expect = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_5() {
        let key: Vec<u8> = (0..20).map(|_| 0x0c_u8).collect();
        let message = b"Test With Truncation";

        let hash_bytes = hmac(Algorithm::SHA256, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "a3b6167473100ee06e0c796c2955552b";
        let (truncated, _) = actual.split_at(expect.len());

        assert_eq!(expect, truncated);
    }

    #[test]
    fn test_case_6() {
        let key: Vec<u8> = (0..131).map(|_| 0xaa_u8).collect();

        let message = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let hash_bytes = hmac(Algorithm::SHA256, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_7() {
        let key: Vec<u8> = (0..131).map(|_| 0xaa_u8).collect();

        let message = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let hash_bytes = hmac(Algorithm::SHA256, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

        assert_eq!(expect, actual);
    }
}

/// # Sources:
/// All the test case is found here: https://datatracker.ietf.org/doc/html/rfc4231#section-4
#[cfg(test)]
mod hmac_sha512_tests {
    use super::*;
    use crate::encoding::hex::encode;

    #[test]
    fn test_case_1() {
        let key: Vec<u8> = (0..20).map(|_| 0x0b_u8).collect();
        let message = b"Hi There";

        let hash_bytes = hmac(Algorithm::SHA512, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_2() {
        let key: &[u8] = b"Jefe";
        let message = b"what do ya want for nothing?";

        let hash_bytes = hmac(Algorithm::SHA512, key, message);

        let actual = encode(&hash_bytes);
        let expect = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_3() {
        let key: Vec<u8> = (0..20).map(|_| 0xaa_u8).collect();
        let message: Vec<u8> = (0..50).map(|_| 0xdd_u8).collect();

        let hash_bytes = hmac(Algorithm::SHA512, &key, &message);

        let actual = encode(&hash_bytes);
        let expect = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_4() {
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        let message: Vec<u8> = (0..50).map(|_| 0xcd_u8).collect();

        let hash_bytes = hmac(Algorithm::SHA512, &key, &message);

        let actual = encode(&hash_bytes);
        let expect = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_5() {
        let key: Vec<u8> = (0..20).map(|_| 0x0c_u8).collect();
        let message = b"Test With Truncation";

        let hash_bytes = hmac(Algorithm::SHA512, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "415fad6271580a531d4179bc891d87a6";

        let (truncated, _) = actual.split_at(expect.len());
        assert_eq!(expect, truncated);
    }

    #[test]
    fn test_case_6() {
        let key: Vec<u8> = (0..131).map(|_| 0xaa_u8).collect();

        let message = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let hash_bytes = hmac(Algorithm::SHA512, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598";

        assert_eq!(expect, actual);
    }

    #[test]
    fn test_case_7() {
        let key: Vec<u8> = (0..131).map(|_| 0xaa_u8).collect();

        let message = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let hash_bytes = hmac(Algorithm::SHA512, &key, message);

        let actual = encode(&hash_bytes);
        let expect = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58";

        assert_eq!(expect, actual);
    }
}
