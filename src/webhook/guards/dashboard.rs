use crate::webhook::guards::GuardConfig;
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/dashboard".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "dashboard".to_string(),
        required: false,
        ts_window_ms: 300_000,
        anti_replay_on: true,
    }
}
