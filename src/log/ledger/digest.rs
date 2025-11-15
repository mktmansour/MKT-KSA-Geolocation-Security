pub trait Digest {
    fn hash_bytes(&mut self, bytes: &[u8]);
    fn finalize_hex(self) -> String;
}

#[cfg(feature = "ledger_blake3")]
pub mod blake3_impl {
    use super::Digest;
    pub struct Blake3Digest(blake3::Hasher);
    impl Default for Blake3Digest { fn default() -> Self { Self(blake3::Hasher::new()) } }
    impl Digest for Blake3Digest {
        fn hash_bytes(&mut self, bytes: &[u8]) { self.0.update(bytes); }
        fn finalize_hex(self) -> String { self.0.finalize().to_hex().to_string() }
    }
}


