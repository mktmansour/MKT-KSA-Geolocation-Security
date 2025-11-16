/*!
Pure Rust SHA-512/SHA-384 implementation with no external dependencies.
Intended for security-sensitive use where third-party crates are undesired.
The implementation follows FIPS 180-4.
*/

#[inline(always)]
fn rotr(x: u64, n: u64) -> u64 {
    (x >> n) | (x << (64 - n))
}

#[inline(always)]
fn big_sigma0(x: u64) -> u64 {
    rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

#[inline(always)]
fn big_sigma1(x: u64) -> u64 {
    rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

#[inline(always)]
fn small_sigma0(x: u64) -> u64 {
    rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

#[inline(always)]
fn small_sigma1(x: u64) -> u64 {
    rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H0_512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const H0_384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

fn pad_message(input: &[u8]) -> Vec<u8> {
    let bit_len = (input.len() as u128) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 128) != 112 {
        msg.push(0x00);
    }
    // Append 128-bit length (big-endian)
    let high = (bit_len >> 64) as u64;
    let low = (bit_len & 0xffff_ffff_ffff_ffff) as u64;
    for &v in &[high, low] {
        msg.extend_from_slice(&v.to_be_bytes());
    }
    msg
}

fn compress(block: &[u8], state: &mut [u64; 8]) {
    debug_assert_eq!(block.len(), 128);
    let mut w = [0u64; 80];
    for (i, chunk) in block.chunks_exact(8).take(16).enumerate() {
        w[i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    for t in 16..80 {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

    for t in 0..80 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
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

fn sha512_impl(input: &[u8], h0: [u64; 8]) -> [u8; 64] {
    let msg = pad_message(input);
    let mut state = h0;
    for block in msg.chunks_exact(128) {
        compress(block, &mut state);
    }
    let mut out = [0u8; 64];
    for (i, v) in state.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn sha512(input: &[u8]) -> [u8; 64] {
    sha512_impl(input, H0_512)
}

pub fn sha512_hex(input: &[u8]) -> String {
    to_hex(&sha512(input))
}

pub fn sha384(input: &[u8]) -> [u8; 64] {
    // Compute with SHA-384 IVs; caller may truncate to 48 bytes.
    sha512_impl(input, H0_384)
}

pub fn sha384_trunc48(input: &[u8]) -> [u8; 48] {
    let full = sha384(input);
    let mut out = [0u8; 48];
    out.copy_from_slice(&full[..48]);
    out
}

#[inline]
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
