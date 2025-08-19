/******************************************************************************************
*  📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
*  ملف: src/security/signing.rs
*
*  الهدف: دوال توقيع/تحقق عالية الأمان بدون OpenSSL، باستخدام RustCrypto (hmac + sha2)
*  وإدارة مفاتيح آمنة عبر secrecy::SecretVec.
*
*  Purpose: High-security signing/verification without OpenSSL using RustCrypto (hmac + sha2)
*  and secure key handling via secrecy::SecretVec.
******************************************************************************************/

use crate::security::secret::SecureBytes;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Sha384, Sha512};

/// أخطاء التوقيع الموحدة
/// Unified signing errors
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid key for HMAC")]
    InvalidKey,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

type HmacSha512 = Hmac<Sha512>;
type HmacSha384 = Hmac<Sha384>;

/// يوقّع مصفوفة بايت باستخدام HMAC-SHA512
/// Signs a byte slice using HMAC-SHA512
///
/// # Errors
/// يرجع خطأ إذا فشل إنشاء HMAC (مفتاح غير صالح).
/// Returns error if HMAC cannot be constructed (invalid key).
pub fn sign_hmac_sha512(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> {
    let mut mac = HmacSha512::new_from_slice(key.expose()).map_err(|_| SigningError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// يتحقق من صحة HMAC-SHA512
/// Verifies HMAC-SHA512
#[must_use]
pub fn verify_hmac_sha512(data: &[u8], signature: &[u8], key: &SecureBytes) -> bool {
    let Ok(mut mac) = HmacSha512::new_from_slice(key.expose()) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(signature).is_ok()
}

/// يوقّع مصفوفة بايت باستخدام HMAC-SHA384 (لاستخدامات معينة)
/// Signs a byte slice using HMAC-SHA384 (for specific modules)
///
/// # Errors
pub fn sign_hmac_sha384(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> {
    let mut mac = HmacSha384::new_from_slice(key.expose()).map_err(|_| SigningError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// يتحقق من صحة HMAC-SHA384
/// Verifies HMAC-SHA384
#[must_use]
pub fn verify_hmac_sha384(data: &[u8], signature: &[u8], key: &SecureBytes) -> bool {
    let Ok(mut mac) = HmacSha384::new_from_slice(key.expose()) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(signature).is_ok()
}

/// يوقّع بنية قابلة للتسلسل باستثناء حقل معيّن (مثلاً signature)
/// Signs a serializable struct while excluding a specific field (e.g., signature)
///
/// # Errors
/// - Serialization: عند فشل التسلسل إلى JSON.
pub fn sign_struct_excluding_field<T: Serialize>(
    value: &T,
    exclude_field: &str,
    key: &SecureBytes,
) -> Result<Vec<u8>, SigningError> {
    // تسلسل إلى JSON ثم إزالة الحقل عبر serde_json::Value
    let json =
        serde_json::to_value(value).map_err(|e| SigningError::Serialization(e.to_string()))?;
    let json = match json {
        serde_json::Value::Object(mut map) => {
            map.remove(exclude_field);
            serde_json::Value::Object(map)
        }
        other => other,
    };
    let data = serde_json::to_vec(&json).map_err(|e| SigningError::Serialization(e.to_string()))?;
    sign_hmac_sha512(&data, key)
}

/// يتحقق من بنية قابلة للتسلسل باستثناء حقل معيّن
/// Verifies a serializable struct while excluding a specific field
#[must_use]
pub fn verify_struct_excluding_field<T: Serialize>(
    value: &T,
    exclude_field: &str,
    signature: &[u8],
    key: &SecureBytes,
) -> bool {
    let Ok(mut json) = serde_json::to_value(value) else {
        return false;
    };
    if let serde_json::Value::Object(ref mut map) = json {
        map.remove(exclude_field);
    }
    let Ok(data) = serde_json::to_vec(&json) else {
        return false;
    };
    verify_hmac_sha512(&data, signature, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha512_roundtrip() {
        let key = SecureBytes::new(vec![1u8; 64]);
        let data = b"hello";
        let sig = sign_hmac_sha512(data, &key).unwrap();
        assert!(verify_hmac_sha512(data, &sig, &key));
    }

    #[test]
    fn struct_sign_verify_excluding_signature() {
        #[derive(serde::Serialize)]
        struct Sample {
            a: u32,
            b: String,
            signature: Option<String>,
        }
        let key = SecureBytes::new(vec![42u8; 32]);
        let s = Sample {
            a: 7,
            b: "x".to_string(),
            signature: None,
        };
        let sig = sign_struct_excluding_field(&s, "signature", &key).unwrap();
        assert!(verify_struct_excluding_field(&s, "signature", &sig, &key));
    }
}
