//! # Sources: <https://datatracker.ietf.org/doc/html/rfc6234>

#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// # Example:
/// ```rust
/// use otp::Algorithm;
///
/// let alg = Algorithm::SHA256;
///
/// let empty_hash = alg.hash_hex(b"");
/// assert_eq!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &empty_hash);
///
/// let hash = alg.hash_hex(b"The quick brown fox jumps over the lazy dog");
/// assert_eq!("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", &hash);
/// ```
pub fn sha256(input: &[u8]) -> [u8; 32] {
    #[rustfmt::skip]
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const BLOCK_SIZE: usize = 64;
    const PREP_ROUNDS: usize = 16;
    const EXTENSION_ROUNDS: usize = 64;
    const COMPRESSION_ROUNDS: usize = 64;

    let bit_len = (input.len() as u64) * 8;

    let mut padded = input.to_vec();

    // mark of the end of the original message.
    padded.push(0x80);

    // pad with zeroes until the length mod 64 is = 56.
    padded.resize(((padded.len() + BLOCK_SIZE) & !63_usize) - 8, 0x00);

    // reserves the last 8 bytes for the bit-length field.
    padded.extend_from_slice(&bit_len.to_be_bytes());

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

        // w[16..64]: schedule extension
        for i in PREP_ROUNDS..EXTENSION_ROUNDS {
            #[rustfmt::skip]
            let s0 = words[i - 15].rotate_right(7) ^ words[i - 15].rotate_right(18) ^ (words[i - 15] >> 3);

            #[rustfmt::skip]
            let s1 = words[i - 2].rotate_right(17) ^ words[i - 2].rotate_right(19) ^ (words[i - 2] >> 10);

            words[i] = words[i - 16]
                .wrapping_add(s0)
                .wrapping_add(words[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;

        for i in 0..COMPRESSION_ROUNDS {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(words[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0_u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }

    digest
}
