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
#[cfg(feature = "sign_hmac")]
use hmac::{Hmac, Mac};
#[cfg(feature = "serde")]
use serde::Serialize;
#[cfg(feature = "sign_hmac")]
use sha2::{Sha384, Sha512};

/// أخطاء التوقيع الموحدة
/// Unified signing errors
#[derive(Debug)]
pub enum SigningError {
    /// invalid key for HMAC
    InvalidKey,
    /// serialization failed: message
    Serialization(String),
    /// feature disabled
    FeatureDisabled,
}

#[cfg(feature = "sign_hmac")]
type HmacSha512 = Hmac<Sha512>;
#[cfg(feature = "sign_hmac")]
type HmacSha384 = Hmac<Sha384>;

/// يوقّع مصفوفة بايت باستخدام HMAC-SHA512
/// Signs a byte slice using HMAC-SHA512
#[cfg(feature = "sign_hmac")]
pub fn sign_hmac_sha512(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> {
    let mut mac = HmacSha512::new_from_slice(key.expose()).map_err(|_| SigningError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// نسخة بديلة عندما تكون الميزة معطلة
#[cfg(not(feature = "sign_hmac"))]
pub fn sign_hmac_sha512(_data: &[u8], _key: &SecureBytes) -> Result<Vec<u8>, SigningError> {
    Err(SigningError::FeatureDisabled)
}

/// يتحقق من صحة HMAC-SHA512
/// Verifies HMAC-SHA512
#[must_use]
#[cfg(feature = "sign_hmac")]
pub fn verify_hmac_sha512(data: &[u8], signature: &[u8], key: &SecureBytes) -> bool {
    let Ok(mut mac) = HmacSha512::new_from_slice(key.expose()) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(signature).is_ok()
}

#[must_use]
#[cfg(not(feature = "sign_hmac"))]
pub fn verify_hmac_sha512(_data: &[u8], _signature: &[u8], _key: &SecureBytes) -> bool {
    false
}

/// يوقّع مصفوفة بايت باستخدام HMAC-SHA384 (لاستخدامات معينة)
/// Signs a byte slice using HMAC-SHA384 (for specific modules)
#[cfg(feature = "sign_hmac")]
pub fn sign_hmac_sha384(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> {
    let mut mac = HmacSha384::new_from_slice(key.expose()).map_err(|_| SigningError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(not(feature = "sign_hmac"))]
pub fn sign_hmac_sha384(_data: &[u8], _key: &SecureBytes) -> Result<Vec<u8>, SigningError> {
    Err(SigningError::FeatureDisabled)
}

/// يتحقق من صحة HMAC-SHA384
/// Verifies HMAC-SHA384
#[must_use]
#[cfg(feature = "sign_hmac")]
pub fn verify_hmac_sha384(data: &[u8], signature: &[u8], key: &SecureBytes) -> bool {
    let Ok(mut mac) = HmacSha384::new_from_slice(key.expose()) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(signature).is_ok()
}

#[must_use]
#[cfg(not(feature = "sign_hmac"))]
pub fn verify_hmac_sha384(_data: &[u8], _signature: &[u8], _key: &SecureBytes) -> bool {
    false
}

/// يوقّع بنية قابلة للتسلسل باستثناء حقل معيّن (مثلاً signature)
/// Signs a serializable struct while excluding a specific field (e.g., signature)
#[cfg(all(feature = "serde", feature = "sign_hmac"))]
pub fn sign_struct_excluding_field<T: Serialize>(
    value: &T,
    exclude_field: &str,
    key: &SecureBytes,
) -> Result<Vec<u8>, SigningError> {
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

#[cfg(any(not(feature = "serde"), not(feature = "sign_hmac")))]
pub fn sign_struct_excluding_field<T>(
    _value: &T,
    _exclude_field: &str,
    _key: &SecureBytes,
) -> Result<Vec<u8>, SigningError> {
    Err(SigningError::FeatureDisabled)
}

/// يتحقق من بنية قابلة للتسلسل باستثناء حقل معيّن
/// Verifies a serializable struct while excluding a specific field
#[cfg(all(feature = "serde", feature = "sign_hmac"))]
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

#[cfg(any(not(feature = "serde"), not(feature = "sign_hmac")))]
#[must_use]
pub fn verify_struct_excluding_field<T>(
    _value: &T,
    _exclude_field: &str,
    _signature: &[u8],
    _key: &SecureBytes,
) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "sign_hmac"))]
    #[test]
    fn hmac_sha512_disabled_by_default() {
        let key = SecureBytes::new(vec![1u8; 64]);
        let data = b"hello";
        let _ = (key, data);
        // Default build is zero-deps; feature is disabled so function returns FeatureDisabled
        let err = sign_hmac_sha512(data, &SecureBytes::new(vec![0; 32])).err();
        assert!(matches!(err, Some(SigningError::FeatureDisabled)));
    }
}
