/*!
فحص الرموز (Token Introspection) - RFC 7662
Token Introspection - RFC 7662

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
*/

use crate::oauth2::tokens::*;
use crate::oauth2::SYSTEM_ISSUER;
// Removed serde dependency

/// Arabic: مدير فحص الرموز
/// English: Token introspection manager
pub struct TokenIntrospectionManager;

impl TokenIntrospectionManager {
    /// Arabic: فحص الرمز
    /// English: Introspect token
    pub fn introspect_token(token: &str) -> IntrospectionResult {
        let token_manager = get_token_manager();

        match token_manager.validate_token(token) {
            Ok(token_info) => IntrospectionResult {
                active: true,
                scope: Some(token_info.scopes.to_scope_string()),
                client_id: Some(token_info.client_id.clone()),
                username: token_info.user_id.clone(),
                exp: Some(token_info.expires_at),
                iat: Some(token_info.created_at),
                sub: token_info.user_id,
                aud: Some(token_info.client_id),
                iss: Some(SYSTEM_ISSUER.to_string()),
                jti: Some(token_info.value),
            },
            Err(_) => IntrospectionResult {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                exp: None,
                iat: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntrospectionResult {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}
