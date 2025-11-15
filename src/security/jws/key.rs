use crate::security::secret::SecureBytes;
use ed25519_dalek::VerifyingKey;

/// Arabic: زوج مفاتيح Ed25519 مع kid وإدارة آمنة للمفتاح الخاص
/// English: Ed25519 keypair with kid and safe private key handling
#[derive(Debug, Clone)]
pub struct Ed25519Keypair {
    pub kid: String,
    secret: [u8; 32],
    pubkey: VerifyingKey,
}

impl Ed25519Keypair {
    pub fn from_secure_bytes(
        kid: impl Into<String>,
        sk: &SecureBytes,
    ) -> Result<Self, &'static str> {
        let bytes = sk.expose();
        if bytes.len() != 32 {
            return Err("ed25519 secret must be 32 bytes");
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(bytes);
        let signing = ed25519_dalek::SigningKey::from_bytes(&s);
        let pubkey = signing.verifying_key();
        Ok(Self {
            kid: kid.into(),
            secret: s,
            pubkey,
        })
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.pubkey
    }
}
