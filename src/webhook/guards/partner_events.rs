use crate::webhook::guards::GuardConfig;

pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/partner/events".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "partner_hmac".to_string(),
        required: true,
        ts_window_ms: 300_000,
        anti_replay_on: true,
    }
}
