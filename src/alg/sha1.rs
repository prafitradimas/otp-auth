//! # Source: <https://datatracker.ietf.org/doc/html/rfc3174/>

/// # Example:
/// ```rust
/// use otp::Algorithm;
///
/// let alg = Algorithm::SHA1;
/// let hash = alg.hash_hex(b"The quick brown fox jumps over the lazy dog");
/// assert_eq!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", &hash);
/// ```
pub fn sha1(input: &[u8]) -> [u8; 20] {
    // SHA-1 constants
    let mut state: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    const BLOCK_SIZE: usize = 64;
    const PREP_ROUNDS: usize = 16;
    const EXTENSION_ROUNDS: usize = 80;
    const COMPRESSION_ROUNDS: usize = 80;

    let bit_len = (input.len() as u64) * 8;
    let mut padded = input.to_vec();

    // mark of the end of the original message.
    padded.push(0x80);

    // pad with zeroes until the length mod 64 is = 56.
    padded.resize(((padded.len() + BLOCK_SIZE) & !63_usize) - 8, 0x00);

    // reserves the last 8 bytes for the bit-length field.
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // process 512-bit blocks
    for chunk in padded.chunks(BLOCK_SIZE) {
        let mut words = [0_u32; COMPRESSION_ROUNDS];

        // w[0..16]: schedule preparation
        for i in 0..PREP_ROUNDS {
            words[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        // w[16..80]: schedule extension
        for i in PREP_ROUNDS..EXTENSION_ROUNDS {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = state;

        #[allow(clippy::needless_range_loop)]
        for i in 0..COMPRESSION_ROUNDS {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5A827999),
                20..40 => (b ^ c ^ d, 0x6ED9EBA1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(words[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // next state
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0_u8; 20];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }

    digest
}
