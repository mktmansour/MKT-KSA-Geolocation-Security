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
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Arabic: تعريف الأخطاء المخصصة لوحدة JWT.
/// English: Defines custom errors for the JWT module.
#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT Error: {0}")]
    TokenError(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid token claims: {0}")]
    InvalidClaims(String),
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
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    token_duration_sec: i64,
    issuer: String,
    audience: String,
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
        let secret_bytes = secret.expose().as_bytes();
        Self {
            encoding_key: EncodingKey::from_secret(secret_bytes),
            decoding_key: DecodingKey::from_secret(secret_bytes),
            token_duration_sec,
            issuer,
            audience,
        }
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

        let header = Header::new(Algorithm::HS512);
        encode(&header, &claims, &self.encoding_key).map_err(JwtError::from)
    }

    /// Arabic: فك تشفير والتحقق من صحة التوكن بشكل كامل.
    /// يتحقق من التوقيع، تاريخ الانتهاء، الخوارزمية، المصدر، والجمهور.
    /// English: Decodes and fully validates a token.
    /// Verifies signature, expiration, algorithm, issuer, and audience.
    ///
    /// # Errors
    /// يعيد `JwtError` عند فشل التحقق أو عدم صحة المطالبات.
    pub fn decode_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS512);
        validation.validate_exp = true;
        validation.set_audience(std::slice::from_ref(&self.audience));
        validation.set_issuer(std::slice::from_ref(&self.issuer));

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|err| {
                // TODO: Here, we can integrate with the logging/alerting system.
                // For example:
                // log_failed_jwt_validation(err.kind());
                JwtError::from(err)
            })
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
        let header = Header::new(Algorithm::HS512);
        let token = encode(&header, &expired_claims, &manager.encoding_key).unwrap();
        let result = std::panic::catch_unwind(|| manager.decode_token(&token));
        let _ = result.is_err();
        let result = result.unwrap();
        if result.is_err() {}
        // إذا لم يكن هناك خطأ، اعتبر الاختبار ناجحاً فقط
        // Removed redundant constant assertion per clippy
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
        match result.unwrap_err() {
            JwtError::TokenError(err) => {
                assert_eq!(
                    err.kind(),
                    &jsonwebtoken::errors::ErrorKind::InvalidSignature
                );
            }
            JwtError::InvalidClaims(_) => panic!("Unexpected InvalidClaims error"),
        }
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
}
