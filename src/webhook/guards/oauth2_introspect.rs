/*!
حراس OAuth2 Introspection Endpoint
OAuth2 Introspection Endpoint Guards
*/

use crate::webhook::guards::GuardConfig;

/// Arabic: حارس endpoint فحص الرموز OAuth2
/// English: OAuth2 Introspection endpoint guard
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/oauth/introspect".to_string(),
        alg: "oauth2".to_string(),
        key_id: "oauth2_introspect".to_string(),
        required: true,
        ts_window_ms: 300_000, // 5 minutes
        anti_replay_on: true,
    }
}
