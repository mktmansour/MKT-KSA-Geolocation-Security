use crate::webhook::guards::GuardConfig;
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/backup/send".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "backup_send".to_string(),
        required: true,
        ts_window_ms: 300_000,
        anti_replay_on: true,
    }
}
