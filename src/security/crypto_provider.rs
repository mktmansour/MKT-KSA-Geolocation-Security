/******************************************************************************************
        📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: crypto_provider.rs
    المسار: src/security/crypto_provider.rs

    وظيفة الملف:
    تعريف واجهة موحّدة (Trait) لمزوّد التشفير والتوقيع والعشوائية مع تنفيذ افتراضي
    صفر تبعيات (NoCrypto) يعيد أخطاء واضحة بدل منح أمان زائف. الهدف هو تمكين "نواة
    صفر تبعية" عبر حقن مزوّدات حقيقية خلف ميزات اختيارية دون كسر المنطق.

    File Name: crypto_provider.rs
    Path:     src/security/crypto_provider.rs

    File Role:
    Defines a unified trait for crypto/signing/randomness with a zero‑dependency default
    implementation (NoCrypto) that returns explicit errors rather than weak security.
    This enables a "zero‑dependency core" by injecting real providers behind features.
******************************************************************************************/

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::security::secret::SecureBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    NotAvailable,
    InvalidKey,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CryptoError::NotAvailable => "operation not available in zero-deps mode",
            CryptoError::InvalidKey => "invalid key or parameter",
        };
        write!(f, "{}", msg)
    }
}
impl Error for CryptoError {}

/// Arabic: واجهة موحّدة لمزوّد التشفير/التوقيع/العشوائية.
/// English: Unified interface for crypto/signing/randomness provider.
pub trait CryptoProvider {
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>, CryptoError>;

    fn hmac_sign_sha512(&self, key: &SecureBytes, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn hmac_verify_sha512(
        &self,
        key: &SecureBytes,
        data: &[u8],
        mac: &[u8],
    ) -> Result<bool, CryptoError>;

    fn encrypt_aes_gcm(
        &self,
        key: &SecureBytes,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn decrypt_aes_gcm(
        &self,
        key: &SecureBytes,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn sign_eddsa(&self, _sk: &SecureBytes, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotAvailable)
    }
    fn verify_eddsa(&self, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<bool, CryptoError> {
        Err(CryptoError::NotAvailable)
    }
}

/// Arabic: تنفيذ افتراضي صفر تبعيات يعيد أخطاء واضحة.
/// English: Default zero‑dependency implementation returning explicit errors.
#[derive(Default, Debug, Clone, Copy)]
pub struct NoCrypto;

impl CryptoProvider for NoCrypto {
    fn random_bytes(&self, _len: usize) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotAvailable)
    }

    fn hmac_sign_sha512(&self, _key: &SecureBytes, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotAvailable)
    }

    fn hmac_verify_sha512(
        &self,
        _key: &SecureBytes,
        _data: &[u8],
        _mac: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::NotAvailable)
    }

    fn encrypt_aes_gcm(
        &self,
        _key: &SecureBytes,
        _nonce: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotAvailable)
    }

    fn decrypt_aes_gcm(
        &self,
        _key: &SecureBytes,
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotAvailable)
    }
}
