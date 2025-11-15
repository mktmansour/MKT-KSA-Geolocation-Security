use mkt_ksa_geo_sec::core::digest::StdHasherDigest;
use mkt_ksa_geo_sec::security::inspection::{inspect_and_fingerprint, Limits};

#[test]
fn fuzz_like_inspection_random_bytes() {
    // pseudo-fuzz: iterate seeds & sizes without external deps
    for seed in [1u64, 0xABCDEF0123456789, 7777, 999_999] {
        for &len in &[0usize, 1, 2, 7, 31, 127, 255, 1024] {
            let body = gen(seed, len);
            let mut d = StdHasherDigest::default();
            let res = inspect_and_fingerprint(&mut d, Limits::default(), b"H:1\r\n\r\n", &body);
            // Should always produce a fingerprint, ok may be false if pattern hits
            assert!(!res.fingerprint_hex.is_empty());
        }
    }
}

fn gen(mut x: u64, len: usize) -> Vec<u8> {
    x |= 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xFF) as u8);
    }
    out
}
