/*! Arabic: سياسات تشفير تكيفية (Zero‑deps): السماح بالخوارزميات، الأطوال، الدوران
English: Adaptive crypto policies (zero‑deps): algorithm allowlists, sizes, rotation */

#[derive(Debug, Clone)]
pub struct CryptoPolicy {
    pub require_fips: bool,
    pub min_key_bits: u16,
    pub rotate_after_ms: u64,
    pub allow_xchacha20_poly1305: bool,
    pub allow_aes256_gcm: bool,
    pub allow_ed25519: bool,
    pub allow_ecdsa_p256: bool,
    pub require_aad: bool,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            require_fips: false,
            min_key_bits: 256,
            rotate_after_ms: 86_400_000,
            allow_xchacha20_poly1305: true,
            allow_aes256_gcm: true,
            allow_ed25519: true,
            allow_ecdsa_p256: true,
            require_aad: true,
        }
    }
}
