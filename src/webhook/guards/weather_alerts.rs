use crate::webhook::guards::GuardConfig;

pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/weather/alerts".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "weather_hmac".to_string(),
        required: true,
        ts_window_ms: 180_000,
        anti_replay_on: true,
    }
}
