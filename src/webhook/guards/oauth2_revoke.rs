/*!
حراس OAuth2 Revocation Endpoint
OAuth2 Revocation Endpoint Guards
*/

use crate::webhook::guards::GuardConfig;

/// Arabic: حارس endpoint إلغاء الرموز OAuth2
/// English: OAuth2 Revocation endpoint guard
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/oauth/revoke".to_string(),
        alg: "oauth2".to_string(),
        key_id: "oauth2_revoke".to_string(),
        required: true,
        ts_window_ms: 300_000, // 5 minutes
        anti_replay_on: true,
    }
}
