/*!
حراس OAuth2 UserInfo Endpoint
OAuth2 UserInfo Endpoint Guards
*/

use crate::webhook::guards::GuardConfig;

/// Arabic: حارس endpoint معلومات المستخدم OAuth2
/// English: OAuth2 UserInfo endpoint guard
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/oauth/userinfo".to_string(),
        alg: "oauth2".to_string(),
        key_id: "oauth2_userinfo".to_string(),
        required: true,
        ts_window_ms: 300_000, // 5 minutes
        anti_replay_on: true,
    }
}
