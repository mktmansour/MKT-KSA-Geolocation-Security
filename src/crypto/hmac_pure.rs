/*!
Pure Rust HMAC over SHA-512/SHA-384 with no external dependencies.
*/

use super::sha512_pure::{sha384_trunc48, sha512};

#[inline]
fn xor_bytes(buf: &mut [u8], val: u8) {
    for b in buf.iter_mut() {
        *b ^= val;
    }
}

fn normalize_key(mut key: Vec<u8>, block_size: usize) -> Vec<u8> {
    if key.len() > block_size {
        let h = sha512(&key);
        key.clear();
        key.extend_from_slice(&h);
    }
    if key.len() < block_size {
        key.resize(block_size, 0);
    }
    key
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const B: usize = 128; // SHA-512 block size
    let k = normalize_key(key.to_vec(), B);
    let mut kipad = k.clone();
    let mut kopad = k;
    xor_bytes(&mut kipad, 0x36);
    xor_bytes(&mut kopad, 0x5c);
    // inner = SHA512(kipad || data)
    let mut inner: Vec<u8> = Vec::with_capacity(kipad.len() + data.len());
    inner.extend_from_slice(&kipad);
    inner.extend_from_slice(data);
    let inner_hash = sha512(&inner);
    // outer = SHA512(kopad || inner_hash)
    let mut outer: Vec<u8> = Vec::with_capacity(kopad.len() + inner_hash.len());
    outer.extend_from_slice(&kopad);
    outer.extend_from_slice(&inner_hash);
    sha512(&outer)
}

pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    const B: usize = 128; // SHA-512 family
    let k = normalize_key(key.to_vec(), B);
    let mut kipad = k.clone();
    let mut kopad = k;
    xor_bytes(&mut kipad, 0x36);
    xor_bytes(&mut kopad, 0x5c);
    let mut inner: Vec<u8> = Vec::with_capacity(kipad.len() + data.len());
    inner.extend_from_slice(&kipad);
    inner.extend_from_slice(data);
    let inner_hash = sha384_trunc48(&inner); // 48 bytes
    let mut outer: Vec<u8> = Vec::with_capacity(kopad.len() + inner_hash.len());
    outer.extend_from_slice(&kopad);
    outer.extend_from_slice(&inner_hash);
    sha384_trunc48(&outer)
}

#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}


