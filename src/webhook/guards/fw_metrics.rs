/*!
حراس Firewall Metrics
Firewall Metrics Guards
*/

use crate::webhook::guards::GuardConfig;

/// Arabic: حارس metrics الجدار الناري
/// English: Firewall metrics guard
pub fn register() -> GuardConfig {
    GuardConfig {
        path: "/fw/metrics".to_string(),
        alg: "hmac-sha512".to_string(),
        key_id: "fw_metrics".to_string(),
        required: false,
        ts_window_ms: 300_000,
        anti_replay_on: true,
    }
}
