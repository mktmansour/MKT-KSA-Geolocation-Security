use crate::webhook::guards::GuardConfig;
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/webhook/guard/list".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "webhook_guard_list".to_string(),
        required: true,
        ts_window_ms: 300_000,
        anti_replay_on: true,
    }
}
