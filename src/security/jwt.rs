/******************************************************************************************
        📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    File Name: jwt.rs
    Path:      src/security/jwt.rs

    File Role:
    هذا الملف هو "إدارة الجوازات" الرقمية للمشروع.
    مسؤول عن إصدار والتحقق من "جوازات السفر" (JSON Web Tokens - JWTs)
    التي تثبت هوية المستخدم وتصاريحه. تم تصميمه ليكون محصنًا ضد
    الثغرات الأمنية الشائعة مثل تسريب المفاتيح، هجمات إعادة التشغيل،
    وتضمين معلومات حساسة في التوكن.

    --------------------------------------------------------------

    File Name: jwt.rs
    Path:      src/security/jwt.rs

    File Role:
    This file is the project's digital "Passport Control".
    It is responsible for issuing and verifying "passports" (JSON Web Tokens - JWTs)
    that prove a user's identity and permissions. It is designed to be hardened
    against common security vulnerabilities like secret key leakage, replay attacks,
    and embedding sensitive information in the token.
******************************************************************************************/

use crate::security::secret::SecureString;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

/// Arabic: تعريف الأخطاء المخصصة لوحدة JWT.
/// English: Defines custom errors for the JWT module.
#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT Error: {0}")]
    TokenError(String),
    #[error("Invalid token claims: {0}")]
    InvalidClaims(String),
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Arabic: "المطالبات" (Claims) التي يتم تضمينها في حمولة التوكن.
///
/// تم تطويرها لتشمل الأدوار، المصدر، والجمهور لزيادة الأمان.
/// English: The "claims" included in the token's payload.
///
/// Enhanced to include roles, issuer, and audience for increased security.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Arabic: معرف المستخدم (Subject).
    /// English: User ID (Subject).
    pub sub: Uuid,
    /// Arabic: الأدوار والصلاحيات الممنوحة للمستخدم.
    /// English: The roles and permissions granted to the user.
    pub roles: Vec<String>,
    /// Arabic: وقت انتهاء صلاحية التوكن (Unix timestamp).
    /// English: Token expiration time (Unix timestamp).
    pub exp: i64,
    /// Arabic: وقت إصدار التوكن (Unix timestamp).
    /// English: Token issuance time (Unix timestamp).
    pub iat: i64,
    /// Arabic: الجهة التي أصدرت التوكن (Issuer).
    /// English: The entity that issued the token (Issuer).
    pub iss: String,
    /// Arabic: الجمهور المستهدف للتوكن (Audience).
    /// English: The intended audience for the token (Audience).
    pub aud: String,
}

/// Arabic: مدير JWT. يغلف منطق التشفير والتوقيع.
/// English: The JWT manager. Encapsulates encoding and signing logic.
#[derive(Clone)]
pub struct JwtManager {
    secret: Vec<u8>,
    token_duration_sec: i64,
    issuer: String,
    audience: String,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

fn b64url_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

fn b64url_decode(input: &str) -> Result<Vec<u8>, JwtError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| JwtError::TokenError(format!("base64 decode failed: {e}")))
}

fn sign_hs512(secret: &[u8], signing_input: &str) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha512::new_from_slice(secret)
        .map_err(|e| JwtError::TokenError(format!("hmac init failed: {e}")))?;
    mac.update(signing_input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

impl JwtManager {
    /// Arabic: إنشاء مدير JWT جديد مع مفتاح سري وبيانات تعريفية.
    /// English: Creates a new JWT manager with a secret key and identity metadata.
    #[must_use]
    pub fn new(
        secret: &SecureString,
        token_duration_sec: i64,
        issuer: String,
        audience: String,
    ) -> Self {
        let secret_bytes = secret.expose().as_bytes().to_vec();
        Self {
            secret: secret_bytes,
            token_duration_sec,
            issuer,
            audience,
        }
    }

    fn encode_claims(&self, claims: &Claims) -> Result<String, JwtError> {
        let header = serde_json::json!({
            "alg": "HS512",
            "typ": "JWT"
        });
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| JwtError::TokenError(format!("header serialization failed: {e}")))?;
        let payload_json = serde_json::to_vec(claims)
            .map_err(|e| JwtError::TokenError(format!("claims serialization failed: {e}")))?;

        let encoded_header = b64url_encode(&header_json);
        let encoded_payload = b64url_encode(&payload_json);
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature = sign_hs512(&self.secret, &signing_input)?;
        let encoded_signature = b64url_encode(&signature);
        Ok(format!("{signing_input}.{encoded_signature}"))
    }

    /// Arabic: إنشاء توكن جديد لمستخدم معين مع أدواره.
    /// English: Creates a new token for a specific user with their roles.
    ///
    /// # Errors
    /// يعيد `JwtError` في حال فشل التشفير/التوقيع.
    pub fn generate_token(&self, user_id: Uuid, roles: Vec<String>) -> Result<String, JwtError> {
        let now = Utc::now();
        let expiration = now + Duration::seconds(self.token_duration_sec);

        let claims = Claims {
            sub: user_id,
            roles,
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
        };
        self.encode_claims(&claims)
    }

    /// Arabic: فك تشفير والتحقق من صحة التوكن بشكل كامل.
    /// يتحقق من التوقيع، تاريخ الانتهاء، الخوارزمية، المصدر، والجمهور.
    /// English: Decodes and fully validates a token.
    /// Verifies signature, expiration, algorithm, issuer, and audience.
    ///
    /// # Errors
    /// يعيد `JwtError` عند فشل التحقق أو عدم صحة المطالبات.
    pub fn decode_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(JwtError::InvalidTokenFormat)?;
        let payload_b64 = parts.next().ok_or(JwtError::InvalidTokenFormat)?;
        let signature_b64 = parts.next().ok_or(JwtError::InvalidTokenFormat)?;
        if parts.next().is_some() {
            return Err(JwtError::InvalidTokenFormat);
        }

        let header_raw = b64url_decode(header_b64)?;
        let header: JwtHeader = serde_json::from_slice(&header_raw)
            .map_err(|e| JwtError::TokenError(format!("header parse failed: {e}")))?;

        if header.alg != "HS512" {
            return Err(JwtError::TokenError("unsupported algorithm".to_string()));
        }
        if let Some(typ) = header.typ {
            if typ != "JWT" {
                return Err(JwtError::TokenError("invalid token type".to_string()));
            }
        }

        let signing_input = format!("{header_b64}.{payload_b64}");
        let expected_sig = sign_hs512(&self.secret, &signing_input)?;
        let provided_sig = b64url_decode(signature_b64)?;
        if expected_sig.as_slice().ct_eq(provided_sig.as_slice()).unwrap_u8() != 1 {
            return Err(JwtError::InvalidSignature);
        }

        let payload_raw = b64url_decode(payload_b64)?;
        let claims: Claims = serde_json::from_slice(&payload_raw)
            .map_err(|e| JwtError::TokenError(format!("claims parse failed: {e}")))?;

        let now = Utc::now().timestamp();
        if claims.exp <= now {
            return Err(JwtError::TokenError("token expired".to_string()));
        }
        if claims.iss != self.issuer {
            return Err(JwtError::InvalidClaims("issuer mismatch".to_string()));
        }
        if claims.aud != self.audience {
            return Err(JwtError::InvalidClaims("audience mismatch".to_string()));
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_manager() -> JwtManager {
        let secret = crate::security::secret::SecureString::new(
            "a_very_secure_and_long_secret_key_that_is_at_least_32_bytes_long".to_string(),
        );
        JwtManager::new(
            &secret,
            60,
            "my_app".to_string(),
            "user_service".to_string(),
        )
    }

    #[test]
    fn test_generate_and_decode_token_successfully() {
        let manager = create_manager();
        let user_id = Uuid::new_v4();
        let roles = vec!["user".to_string(), "reader".to_string()];

        let token = manager.generate_token(user_id, roles.clone()).unwrap();
        assert!(!token.is_empty());

        let claims = manager.decode_token(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.roles, roles);
        assert_eq!(claims.iss, "my_app");
        assert_eq!(claims.aud, "user_service");
    }

    #[test]
    fn test_decode_expired_token_fails() {
        let manager = create_manager();
        let user_id = Uuid::new_v4();
        // Create a token that is already expired
        let now = Utc::now();
        let expired_claims = Claims {
            sub: user_id,
            roles: vec![],
            exp: (now - Duration::seconds(10)).timestamp(), // 10 seconds in the past
            iat: (now - Duration::seconds(70)).timestamp(),
            iss: manager.issuer.clone(),
            aud: manager.audience.clone(),
        };
        let token = manager.encode_claims(&expired_claims).unwrap();
        let result = manager.decode_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_token_with_wrong_secret_fails() {
        let manager1 = create_manager();
        let user_id = Uuid::new_v4();
        let token = manager1.generate_token(user_id, vec![]).unwrap();

        // Create another manager with a different secret
        let wrong_secret = crate::security::secret::SecureString::new(
            "this_is_the_wrong_secret_key_and_should_fail".to_string(),
        );
        let manager2 = JwtManager::new(
            &wrong_secret,
            60,
            "my_app".to_string(),
            "user_service".to_string(),
        );

        let result = manager2.decode_token(&token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidSignature));
    }

    #[test]
    fn test_decode_with_wrong_issuer_fails() {
        let manager = create_manager();
        let user_id = Uuid::new_v4();
        let token = manager.generate_token(user_id, vec![]).unwrap();

        let wrong_issuer_manager = JwtManager::new(
            &crate::security::secret::SecureString::new(
                "a_very_secure_and_long_secret_key_that_is_at_least_32_bytes_long".to_string(),
            ),
            60,
            "wrong_issuer".to_string(),
            "user_service".to_string(),
        );

        let result = wrong_issuer_manager.decode_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_rejects_non_hs512_algorithm() {
        let manager = create_manager();
        let claims = Claims {
            sub: Uuid::new_v4(),
            roles: vec!["user".to_string()],
            exp: (Utc::now() + Duration::seconds(60)).timestamp(),
            iat: Utc::now().timestamp(),
            iss: manager.issuer.clone(),
            aud: manager.audience.clone(),
        };

        // Token header is intentionally marked as HS256 and must be rejected.
        let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
        let encoded_header = b64url_encode(&serde_json::to_vec(&header).unwrap());
        let encoded_payload = b64url_encode(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature = sign_hs512(&manager.secret, &signing_input).unwrap();
        let token = format!("{signing_input}.{}", b64url_encode(&signature));

        let result = manager.decode_token(&token);
        assert!(result.is_err());
    }
}
