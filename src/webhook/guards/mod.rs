/*!
Arabic: حُرّاس ويب‑هوك لكل مسار (Registry) — صفري التبعيات.
English: Per‑path webhook guards (Registry) — zero‑dependency.
*/

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub mod ai_feedback;
pub mod ai_ingest;
pub mod ai_model_update;
pub mod alerts_disable;
pub mod alerts_in;
pub mod alerts_set;
pub mod anti_replay_purge_config;
pub mod anti_replay_purge_disable;
pub mod anti_replay_purge_run;
pub mod anti_replay_purge_status;
pub mod backup_consent;
pub mod backup_download;
pub mod backup_email;
pub mod backup_schedule;
pub mod backup_schedule_disable;
pub mod backup_send;
pub mod cloud_push;
pub mod dashboard;
pub mod events_ndjson;
pub mod export_csv;
pub mod fw_close;
pub mod fw_metrics;
pub mod fw_open;
pub mod geo_maplayer;
pub mod geo_satellite;
pub mod keys_auto_config;
pub mod keys_auto_disable;
pub mod keys_create;
pub mod keys_export_hex;
pub mod keys_meta;
pub mod keys_rotate;
pub mod memory_config;
pub mod memory_purge;
pub mod memory_status;
pub mod metrics;
pub mod oauth2_authorize;
pub mod oauth2_introspect;
pub mod oauth2_revoke;
pub mod oauth2_token;
pub mod oauth2_userinfo;
pub mod partner_events;
pub mod partner_telemetry;
pub mod policy_get;
pub mod policy_set;
pub mod policy_set_dsl;
pub mod templates_default;
pub mod templates_set;
pub mod toggle;
pub mod weather_alerts;
pub mod weather_hook;
pub mod webhook_guard_disable;
pub mod webhook_guard_list;
pub mod webhook_guard_set;
pub mod webhook_guard_stats;
pub mod webhook_in;

#[derive(Clone, Debug)]
pub struct GuardConfig {
    pub path: String,
    pub alg: String,          // "hmac-sha512" | "none"
    pub key_id: String,       // key identifier in key store
    pub required: bool,       // require signature or allow unsigned
    pub ts_window_ms: u64,    // timestamp validity window
    pub anti_replay_on: bool, // enable nonce tracking
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            path: "/webhook/in".to_string(),
            alg: "hmac-sha512".to_string(),
            key_id: "auth_hmac".to_string(),
            required: true,
            ts_window_ms: 5 * 60 * 1000,
            anti_replay_on: true,
        }
    }
}

static REG: OnceLock<Mutex<HashMap<String, GuardConfig>>> = OnceLock::new();
static BASE: OnceLock<Mutex<HashMap<String, GuardConfig>>> = OnceLock::new();

fn map_mut() -> std::sync::MutexGuard<'static, HashMap<String, GuardConfig>> {
    REG.get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn base_mut() -> std::sync::MutexGuard<'static, HashMap<String, GuardConfig>> {
    BASE.get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub fn set_guard(cfg: GuardConfig) {
    let mut m = map_mut();
    let mut b = base_mut();
    b.entry(cfg.path.clone()).or_insert_with(|| cfg.clone());
    m.insert(cfg.path.clone(), cfg);
}

pub fn disable_guard(path: &str) {
    let mut m = map_mut();
    m.remove(path);
}

pub fn get_guard_for(path: &str) -> Option<GuardConfig> {
    let m = REG
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    m.get(path).cloned()
}

pub fn list_guards() -> Vec<GuardConfig> {
    let m = REG
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut v: Vec<GuardConfig> = m.values().cloned().collect();
    v.sort_by(|a, b| a.path.cmp(&b.path));
    v
}

// Arabic: تسجيل حراس افتراضيين لمسارات معروفة — يُستدعى مرة واحدة عند الإقلاع
// English: Register built‑in guards for known paths — call once at boot
pub fn register_builtins() {
    let mut m = map_mut();
    if !m.contains_key("/ai/ingest") {
        m.insert("/ai/ingest".into(), ai_ingest::register());
    }
    if !m.contains_key("/weather/hook") {
        m.insert("/weather/hook".into(), weather_hook::register());
    }
    if !m.contains_key("/alerts/in") {
        m.insert("/alerts/in".into(), alerts_in::register());
    }
    if !m.contains_key("/geo/satellite") {
        m.insert("/geo/satellite".into(), geo_satellite::register());
    }
    if !m.contains_key("/geo/maplayer") {
        m.insert("/geo/maplayer".into(), geo_maplayer::register());
    }
    if !m.contains_key("/webhook/in") {
        m.insert("/webhook/in".into(), webhook_in::register());
    }
    if !m.contains_key("/metrics") {
        m.insert("/metrics".into(), metrics::register());
    }
    if !m.contains_key("/events.ndjson") {
        m.insert("/events.ndjson".into(), events_ndjson::register());
    }
    if !m.contains_key("/fw/metrics") {
        m.insert("/fw/metrics".into(), fw_metrics::register());
    }
    if !m.contains_key("/fw/open") {
        m.insert("/fw/open".into(), fw_open::register());
    }
    if !m.contains_key("/fw/close") {
        m.insert("/fw/close".into(), fw_close::register());
    }
    if !m.contains_key("/backup/download") {
        m.insert("/backup/download".into(), backup_download::register());
    }
    if !m.contains_key("/backup/send") {
        m.insert("/backup/send".into(), backup_send::register());
    }
    if !m.contains_key("/backup/consent") {
        m.insert("/backup/consent".into(), backup_consent::register());
    }
    if !m.contains_key("/backup/schedule") {
        m.insert("/backup/schedule".into(), backup_schedule::register());
    }
    if !m.contains_key("/backup/schedule/disable") {
        m.insert(
            "/backup/schedule/disable".into(),
            backup_schedule_disable::register(),
        );
    }
    if !m.contains_key("/backup/email") {
        m.insert("/backup/email".into(), backup_email::register());
    }
    if !m.contains_key("/templates/set") {
        m.insert("/templates/set".into(), templates_set::register());
    }
    if !m.contains_key("/templates/default") {
        m.insert("/templates/default".into(), templates_default::register());
    }
    if !m.contains_key("/toggle") {
        m.insert("/toggle".into(), toggle::register());
    }
    if !m.contains_key("/dashboard") {
        m.insert("/dashboard".into(), dashboard::register());
    }
    if !m.contains_key("/keys/auto/config") {
        m.insert("/keys/auto/config".into(), keys_auto_config::register());
    }
    if !m.contains_key("/keys/auto/disable") {
        m.insert("/keys/auto/disable".into(), keys_auto_disable::register());
    }
    if !m.contains_key("/keys/create") {
        m.insert("/keys/create".into(), keys_create::register());
    }
    if !m.contains_key("/keys/rotate") {
        m.insert("/keys/rotate".into(), keys_rotate::register());
    }
    if !m.contains_key("/keys/meta") {
        m.insert("/keys/meta".into(), keys_meta::register());
    }
    if !m.contains_key("/keys/export_hex") {
        m.insert("/keys/export_hex".into(), keys_export_hex::register());
    }
    if !m.contains_key("/policy/get") {
        m.insert("/policy/get".into(), policy_get::register());
    }
    if !m.contains_key("/policy/set") {
        m.insert("/policy/set".into(), policy_set::register());
    }
    if !m.contains_key("/policy/set_dsl") {
        m.insert("/policy/set_dsl".into(), policy_set_dsl::register());
    }
    if !m.contains_key("/alerts/set") {
        m.insert("/alerts/set".into(), alerts_set::register());
    }
    if !m.contains_key("/alerts/disable") {
        m.insert("/alerts/disable".into(), alerts_disable::register());
    }
    if !m.contains_key("/webhook/guard/list") {
        m.insert("/webhook/guard/list".into(), webhook_guard_list::register());
    }
    if !m.contains_key("/webhook/guard/set") {
        m.insert("/webhook/guard/set".into(), webhook_guard_set::register());
    }
    if !m.contains_key("/webhook/guard/disable") {
        m.insert(
            "/webhook/guard/disable".into(),
            webhook_guard_disable::register(),
        );
    }
    if !m.contains_key("/webhook/guard/stats") {
        m.insert(
            "/webhook/guard/stats".into(),
            webhook_guard_stats::register(),
        );
    }
    if !m.contains_key("/export/csv") {
        m.insert("/export/csv".into(), export_csv::register());
    }
    if !m.contains_key("/cloud/push") {
        m.insert("/cloud/push".into(), cloud_push::register());
    }
    if !m.contains_key("/anti_replay/purge/config") {
        m.insert(
            "/anti_replay/purge/config".into(),
            anti_replay_purge_config::register(),
        );
    }
    if !m.contains_key("/anti_replay/purge/disable") {
        m.insert(
            "/anti_replay/purge/disable".into(),
            anti_replay_purge_disable::register(),
        );
    }
    if !m.contains_key("/anti_replay/purge/run") {
        m.insert(
            "/anti_replay/purge/run".into(),
            anti_replay_purge_run::register(),
        );
    }
    if !m.contains_key("/anti_replay/purge/status") {
        m.insert(
            "/anti_replay/purge/status".into(),
            anti_replay_purge_status::register(),
        );
    }
    if !m.contains_key("/memory/config") {
        m.insert("/memory/config".into(), memory_config::register());
    }
    if !m.contains_key("/memory/purge") {
        m.insert("/memory/purge".into(), memory_purge::register());
    }
    if !m.contains_key("/memory/status") {
        m.insert("/memory/status".into(), memory_status::register());
    }
    if !m.contains_key("/ai/model/update") {
        m.insert("/ai/model/update".into(), ai_model_update::register());
    }
    if !m.contains_key("/ai/feedback") {
        m.insert("/ai/feedback".into(), ai_feedback::register());
    }
    if !m.contains_key("/partner/events") {
        m.insert("/partner/events".into(), partner_events::register());
    }
    if !m.contains_key("/partner/telemetry") {
        m.insert("/partner/telemetry".into(), partner_telemetry::register());
    }
    if !m.contains_key("/weather/alerts") {
        m.insert("/weather/alerts".into(), weather_alerts::register());
    }
    if !m.contains_key("/oauth/authorize") {
        m.insert("/oauth/authorize".into(), oauth2_authorize::register());
    }
    if !m.contains_key("/oauth/token") {
        m.insert("/oauth/token".into(), oauth2_token::register());
    }
    if !m.contains_key("/oauth/introspect") {
        m.insert("/oauth/introspect".into(), oauth2_introspect::register());
    }
    if !m.contains_key("/oauth/userinfo") {
        m.insert("/oauth/userinfo".into(), oauth2_userinfo::register());
    }
    if !m.contains_key("/oauth/revoke") {
        m.insert("/oauth/revoke".into(), oauth2_revoke::register());
    }
    drop(m);
    enforce_tiers();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builtins_register_metrics_and_events_with_strict_config() {
        // Register once
        register_builtins();
        // Metrics
        let m = get_guard_for("/metrics").expect("metrics guard");
        assert!(m.required, "metrics must require signature");
        assert_eq!(m.key_id, "auth_hmac");
        assert_eq!(m.alg, "hmac-sha512");
        assert_eq!(m.ts_window_ms, 60_000);
        assert!(m.anti_replay_on);
        // Events
        let e = get_guard_for("/events.ndjson").expect("events guard");
        assert!(e.required);
        assert_eq!(e.ts_window_ms, 60_000);
    }
}

fn enforce_tiers() {
    let mut m = map_mut();
    let mut b = base_mut();
    for (_p, g) in m.iter_mut() {
        let path = g.path.as_str();
        b.entry(path.to_string()).or_insert_with(|| g.clone());
        // Always enforce anti-replay
        g.anti_replay_on = true;
        // Keys & policy & memory & anti_replay are highly sensitive
        if path.starts_with("/keys/")
            || path.starts_with("/policy/")
            || path.starts_with("/anti_replay/")
            || path.starts_with("/memory/")
        {
            g.required = true;
            if g.ts_window_ms > 120_000 {
                g.ts_window_ms = 120_000;
            }
        }
        if path.starts_with("/backup/") || path.starts_with("/alerts/") {
            g.required = true;
            if g.ts_window_ms > 180_000 {
                g.ts_window_ms = 180_000;
            }
        }
        if path.starts_with("/ai/") {
            if g.key_id.is_empty() {
                g.key_id = "auth_hmac".to_string();
            }
            if g.ts_window_ms > 180_000 {
                g.ts_window_ms = 180_000;
            }
        }
        if path.starts_with("/partner/") {
            if g.key_id.is_empty() {
                g.key_id = "partner_hmac".to_string();
            }
            if g.ts_window_ms > 300_000 {
                g.ts_window_ms = 300_000;
            }
        }
        if path.starts_with("/weather/") {
            if g.key_id.is_empty() {
                g.key_id = "weather_hmac".to_string();
            }
            if g.ts_window_ms > 180_000 {
                g.ts_window_ms = 180_000;
            }
        }
        // telemetry/export/cloud
        if path.starts_with("/cloud/") || path.starts_with("/export/") {
            g.required = true;
            if g.ts_window_ms > 300_000 {
                g.ts_window_ms = 300_000;
            }
        }
    }
}

pub fn relax_guard_if_safe(path: &str) {
    // Restore towards baseline when global risk low and errors rare
    let risk = crate::telemetry::current_risk();
    if risk > 30 {
        return;
    }
    let base = {
        let b = BASE
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        b.get(path).cloned()
    };
    if let Some(base_cfg) = base {
        if let Some(mut cur) = get_guard_for(path) {
            let mut changed = false;
            if cur.ts_window_ms < base_cfg.ts_window_ms {
                cur.ts_window_ms = base_cfg.ts_window_ms;
                changed = true;
            }
            if base_cfg.required && !cur.required {
                cur.required = true; // never relax below required baseline
            }
            if changed {
                set_guard(cur);
                crate::telemetry::record_event("guard_relax", &format!("path={}", path));
            }
        }
    }
}
