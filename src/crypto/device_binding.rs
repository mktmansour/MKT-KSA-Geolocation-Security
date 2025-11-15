/*! Arabic: أدوات ربط المفاتيح ببصمة الجهاز (Zero‑deps)
English: Device-bound key helpers (zero‑deps) */

use crate::crypto::keystore::InMemoryKeyStore;
use crate::security::crypto_smart::traits::KeyStore;
use crate::security::crypto_smart::traits::{KeyId, KeyMeta, KeyStatus};

pub fn is_key_allowed_on_device(meta: &KeyMeta, current_device_fp_hash: &str) -> bool {
    match &meta.device_fingerprint_hash {
        Some(bound) => bound == current_device_fp_hash,
        None => false,
    }
}

pub fn enforce_device_binding(
    store: &InMemoryKeyStore,
    key_id: &KeyId,
    current_device_fp_hash: &str,
) -> bool {
    if let Ok((meta, _)) = store.get(key_id) {
        if meta.status != KeyStatus::Active {
            return false;
        }
        return is_key_allowed_on_device(&meta, current_device_fp_hash);
    }
    false
}
