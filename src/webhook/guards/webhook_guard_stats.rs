use crate::webhook::guards::GuardConfig;

pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/webhook/guard/stats".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "auth_hmac".to_string(),
        required: true,
        ts_window_ms: 180_000,
        anti_replay_on: true,
    }
}
