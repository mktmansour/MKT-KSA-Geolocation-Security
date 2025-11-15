use crate::webhook::guards::GuardConfig;

pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/geo/maplayer".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "geo_layer_hmac".to_string(),
        required: true,
        ts_window_ms: 300_000,
        anti_replay_on: true,
    }
}
