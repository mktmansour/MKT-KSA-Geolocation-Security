/******************************************************************************************
    Arabic: واجهات صفر تبعية للتشفير الذكي (AEAD/Signer/RNG/KDF/KEM/KeyStore)
    English: Zero‑deps crypto traits (AEAD/Signer/RNG/KDF/KEM/KeyStore)
******************************************************************************************/

use crate::security::secret::SecureBytes;

#[derive(Debug)]
pub enum CryptoStrictError {
    NotAvailable,
    InvalidParameter,
}

pub trait CryptoRngProvider {
    fn random(&self, len: usize) -> Result<Vec<u8>, CryptoStrictError>;
}

pub trait AeadCipher {
    fn encrypt(
        &self,
        key: &SecureBytes,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoStrictError>;
    fn decrypt(
        &self,
        key: &SecureBytes,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoStrictError>;
}

pub trait Signer {
    fn sign(&self, sk: &SecureBytes, msg: &[u8]) -> Result<Vec<u8>, CryptoStrictError>;
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoStrictError>;
}

pub trait Kdf {
    fn derive(
        &self,
        ikm: &SecureBytes,
        salt: &[u8],
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, CryptoStrictError>;
}

pub trait Kem {
    fn encap(&self, peer_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoStrictError>; // (ct, ss)
    fn decap(&self, sk: &SecureBytes, ct: &[u8]) -> Result<Vec<u8>, CryptoStrictError>; // ss
}

#[derive(Clone, Debug)]
pub struct KeyId(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Disabled,
    Revoked,
}

#[derive(Clone, Debug)]
pub struct KeyMeta {
    pub key_id: KeyId,
    pub version: u32,
    pub created_ms: u64,
    pub device_fingerprint_hash: Option<String>,
    pub status: KeyStatus,
}

pub trait KeyStore {
    fn put(&mut self, meta: KeyMeta, key: SecureBytes) -> Result<(), CryptoStrictError>;
    fn get(&self, key_id: &KeyId) -> Result<(KeyMeta, SecureBytes), CryptoStrictError>;
    fn rotate(
        &mut self,
        key_id: &KeyId,
        new_key: SecureBytes,
        new_version: u32,
        created_ms: u64,
    ) -> Result<(), CryptoStrictError>;
    fn set_status(&mut self, key_id: &KeyId, status: KeyStatus) -> Result<(), CryptoStrictError>;
}
