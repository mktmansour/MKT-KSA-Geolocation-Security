/*!
دمج OAuth2 مع نظام الحراس الحالي
OAuth2 Integration with Current Guards System

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
*/

use crate::oauth2::clients::*;
use crate::oauth2::tokens::*;
use crate::webhook::guards::GuardConfig;

/// Arabic: إنشاء حراس OAuth2 للمسارات المختلفة
/// English: Create OAuth2 guards for different paths
pub fn create_oauth2_guards() -> Vec<GuardConfig> {
    vec![
        // OAuth2 Authorization Endpoint
        GuardConfig {
            path: "/oauth/authorize".to_string(),
            alg: "oauth2".to_string(),
            key_id: "oauth2_auth".to_string(),
            required: true,
            ts_window_ms: 300_000, // 5 minutes
            anti_replay_on: true,
        },
        // OAuth2 Token Endpoint
        GuardConfig {
            path: "/oauth/token".to_string(),
            alg: "oauth2".to_string(),
            key_id: "oauth2_token".to_string(),
            required: true,
            ts_window_ms: 600_000, // 10 minutes
            anti_replay_on: true,
        },
        // OAuth2 Introspection Endpoint
        GuardConfig {
            path: "/oauth/introspect".to_string(),
            alg: "oauth2".to_string(),
            key_id: "oauth2_introspect".to_string(),
            required: true,
            ts_window_ms: 300_000, // 5 minutes
            anti_replay_on: true,
        },
        // OAuth2 UserInfo Endpoint
        GuardConfig {
            path: "/oauth/userinfo".to_string(),
            alg: "oauth2".to_string(),
            key_id: "oauth2_userinfo".to_string(),
            required: true,
            ts_window_ms: 300_000, // 5 minutes
            anti_replay_on: true,
        },
        // OAuth2 Revocation Endpoint
        GuardConfig {
            path: "/oauth/revoke".to_string(),
            alg: "oauth2".to_string(),
            key_id: "oauth2_revoke".to_string(),
            required: true,
            ts_window_ms: 300_000, // 5 minutes
            anti_replay_on: true,
        },
        // OAuth2 JWK Set Endpoint
        GuardConfig {
            path: "/oauth/keys".to_string(),
            alg: "none".to_string(),
            key_id: "oauth2_keys".to_string(),
            required: false,
            ts_window_ms: 600_000, // 10 minutes
            anti_replay_on: false,
        },
        // OpenID Connect Discovery
        GuardConfig {
            path: "/oauth/.well-known/openid_configuration".to_string(),
            alg: "none".to_string(),
            key_id: "oauth2_discovery".to_string(),
            required: false,
            ts_window_ms: 3_600_000, // 1 hour
            anti_replay_on: false,
        },
    ]
}

/// Arabic: التحقق من صحة رمز OAuth2
/// English: Validate OAuth2 token
pub fn validate_oauth2_token(token: &str) -> Result<TokenInfo, TokenValidationError> {
    let token_manager = get_token_manager();
    token_manager.validate_token(token)
}

/// Arabic: التحقق من صحة العميل OAuth2
/// English: Validate OAuth2 client
pub fn validate_oauth2_client(
    client_id: &str,
    secret: Option<&str>,
) -> Result<Client, ClientValidationError> {
    let client_manager = get_client_manager();
    client_manager.validate_client(client_id, secret)
}
