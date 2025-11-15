/*! Arabic: مخزن مفاتيح في الذاكرة مع ربط اختياري ببصمة الجهاز
English: In-memory keystore with optional device-binding */

use super::traits::{CryptoStrictError, KeyId, KeyMeta, KeyStatus, KeyStore};
use crate::security::secret::SecureBytes;
use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct InMemoryKeyStore {
    entries: HashMap<String, (KeyMeta, SecureBytes)>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl KeyStore for InMemoryKeyStore {
    fn put(&mut self, meta: KeyMeta, key: SecureBytes) -> Result<(), CryptoStrictError> {
        // Arabic: إذا كان المفتاح مرتبطًا ببصمة جهاز، خزّن المعرّف داخل الميتاداتا
        // English: If device-bound, the device fingerprint hash is already carried in meta
        self.entries.insert(meta.key_id.0.clone(), (meta, key));
        Ok(())
    }

    fn get(&self, key_id: &KeyId) -> Result<(KeyMeta, SecureBytes), CryptoStrictError> {
        self.entries
            .get(&key_id.0)
            .cloned()
            .ok_or(CryptoStrictError::NotAvailable)
    }

    fn rotate(
        &mut self,
        key_id: &KeyId,
        new_key: SecureBytes,
        new_version: u32,
        created_ms: u64,
    ) -> Result<(), CryptoStrictError> {
        let (mut meta, _) = self
            .entries
            .get(&key_id.0)
            .cloned()
            .ok_or(CryptoStrictError::NotAvailable)?;
        meta.version = new_version;
        meta.created_ms = created_ms;
        self.entries.insert(key_id.0.clone(), (meta, new_key));
        Ok(())
    }
    fn set_status(&mut self, key_id: &KeyId, status: KeyStatus) -> Result<(), CryptoStrictError> {
        let (mut meta, key) = self
            .entries
            .get(&key_id.0)
            .cloned()
            .ok_or(CryptoStrictError::NotAvailable)?;
        meta.status = status;
        self.entries.insert(key_id.0.clone(), (meta, key));
        Ok(())
    }
}

// Arabic: مساعد لإنشاء KeyMeta مرتبط ببصمة جهاز
// English: Helper to build device-bound KeyMeta
pub fn make_device_bound_meta(
    key_id: String,
    version: u32,
    created_ms: u64,
    device_fingerprint_hash: String,
) -> KeyMeta {
    KeyMeta {
        key_id: KeyId(key_id),
        version,
        created_ms,
        device_fingerprint_hash: Some(device_fingerprint_hash),
        status: KeyStatus::Active,
    }
}
