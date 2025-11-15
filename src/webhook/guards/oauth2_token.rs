/*!
حراس OAuth2 Token Endpoint
OAuth2 Token Endpoint Guards
*/

use crate::webhook::guards::GuardConfig;

/// Arabic: حارس endpoint الرموز OAuth2
/// English: OAuth2 Token endpoint guard
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/oauth/token".to_string(),
        alg: "oauth2".to_string(),
        key_id: "oauth2_token".to_string(),
        required: true,
        ts_window_ms: 300_000, // 5 minutes
        anti_replay_on: true,
    }
}
