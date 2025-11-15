/*!
حراس OAuth2 Authorization Endpoint
OAuth2 Authorization Endpoint Guards
*/

use crate::webhook::guards::GuardConfig;

/// Arabic: حارس endpoint المصادقة OAuth2
/// English: OAuth2 Authorization endpoint guard
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/oauth/authorize".to_string(),
        alg: "oauth2".to_string(),
        key_id: "oauth2_authorize".to_string(),
        required: true,
        ts_window_ms: 300_000, // 5 minutes
        anti_replay_on: true,
    }
}
