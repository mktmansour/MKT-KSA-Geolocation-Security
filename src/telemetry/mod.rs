/*!
Arabic: وحدة قياس وتتبع صفر تبعية: عدادات، أحداث، ومفاتيح تفعيل/تعطيل.
English: Zero‑deps telemetry: counters, events, and feature toggles.
*/

use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex, OnceLock,
};

#[derive(Debug)]
pub struct Counters {
    pub inspected: AtomicU64,
    pub blocked: AtomicU64,
    pub fingerprinted_in: AtomicU64,
    pub fingerprinted_out: AtomicU64,
    pub compressed_in: AtomicU64,
    pub compressed_out: AtomicU64,
    pub webhook_in_ok: AtomicU64,
    pub webhook_in_err: AtomicU64,
    pub webhook_out_ok: AtomicU64,
    pub webhook_out_err: AtomicU64,
    pub fw_allowed: AtomicU64,
    pub fw_blocked: AtomicU64,
    pub sig_ok: AtomicU64,
    pub sig_err: AtomicU64,
    pub oauth2_auth_requests: AtomicU64,
    pub oauth2_auth_success: AtomicU64,
    pub oauth2_auth_failed: AtomicU64,
    pub oauth2_token_requests: AtomicU64,
    pub oauth2_token_success: AtomicU64,
    pub oauth2_token_failed: AtomicU64,
    pub oauth2_introspect_requests: AtomicU64,
    pub oauth2_introspect_success: AtomicU64,
    pub oauth2_introspect_failed: AtomicU64,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            inspected: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            fingerprinted_in: AtomicU64::new(0),
            fingerprinted_out: AtomicU64::new(0),
            compressed_in: AtomicU64::new(0),
            compressed_out: AtomicU64::new(0),
            webhook_in_ok: AtomicU64::new(0),
            webhook_in_err: AtomicU64::new(0),
            webhook_out_ok: AtomicU64::new(0),
            webhook_out_err: AtomicU64::new(0),
            fw_allowed: AtomicU64::new(0),
            fw_blocked: AtomicU64::new(0),
            sig_ok: AtomicU64::new(0),
            sig_err: AtomicU64::new(0),
            oauth2_auth_requests: AtomicU64::new(0),
            oauth2_auth_success: AtomicU64::new(0),
            oauth2_auth_failed: AtomicU64::new(0),
            oauth2_token_requests: AtomicU64::new(0),
            oauth2_token_success: AtomicU64::new(0),
            oauth2_token_failed: AtomicU64::new(0),
            oauth2_introspect_requests: AtomicU64::new(0),
            oauth2_introspect_success: AtomicU64::new(0),
            oauth2_introspect_failed: AtomicU64::new(0),
        }
    }
}

#[derive(Debug)]
pub struct Toggles {
    pub compression_enabled: AtomicBool,
    pub ai_insights_enabled: AtomicBool,
    pub cloud_enabled: AtomicBool,
    pub csv_export_enabled: AtomicBool,
}

impl Default for Toggles {
    fn default() -> Self {
        Self {
            compression_enabled: AtomicBool::new(true),
            ai_insights_enabled: AtomicBool::new(false),
            cloud_enabled: AtomicBool::new(false),
            csv_export_enabled: AtomicBool::new(true),
        }
    }
}

#[derive(Debug)]
pub struct Telemetry {
    pub counters: Counters,
    pub toggles: Toggles,
    pub events: Mutex<VecDeque<String>>,       // ndjson lines
    pub risk_score: AtomicU64,                 // 0..100 scaled as u64
    pub backup: Mutex<Option<BackupSchedule>>, // schedule state
    pub consent_token: Mutex<Option<String>>,  // required for backup
    pub templates: Mutex<Templates>,
    pub default_lang_ar: AtomicBool,
    pub alerts: Mutex<Option<AlertConfig>>,
    pub behavior: Mutex<BehaviorStats>, // adaptive stats (zero-deps)
    pub circuit_open: AtomicBool,
    pub circuit_open_ms: AtomicU64,
    pub mem_limit_bytes: AtomicU64,
    pub mem_auto_purge: AtomicBool,
    pub sig_paths: Mutex<HashMap<String, SigPathStats>>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            counters: Counters::default(),
            toggles: Toggles::default(),
            events: Mutex::new(VecDeque::with_capacity(1024)),
            risk_score: AtomicU64::new(0),
            backup: Mutex::new(None),
            consent_token: Mutex::new(None),
            templates: Mutex::new(Templates::default()),
            default_lang_ar: AtomicBool::new(detect_default_lang_ar()),
            alerts: Mutex::new(None),
            behavior: Mutex::new(BehaviorStats::default()),
            circuit_open: AtomicBool::new(false),
            circuit_open_ms: AtomicU64::new(0),
            mem_limit_bytes: AtomicU64::new(0),
            mem_auto_purge: AtomicBool::new(false),
            sig_paths: Mutex::new(HashMap::new()),
        }
    }
}

static TELEMETRY: OnceLock<Telemetry> = OnceLock::new();

pub fn init() {
    let _ = TELEMETRY.set(Telemetry::default());
}

fn t() -> &'static Telemetry {
    TELEMETRY.get_or_init(|| Telemetry {
        risk_score: AtomicU64::new(0),
        ..Telemetry::default()
    })
}

pub fn set_compression_enabled(enabled: bool) {
    t().toggles
        .compression_enabled
        .store(enabled, Ordering::Relaxed);
}
pub fn compression_enabled() -> bool {
    t().toggles.compression_enabled.load(Ordering::Relaxed)
}

pub fn set_ai_insights_enabled(enabled: bool) {
    t().toggles
        .ai_insights_enabled
        .store(enabled, Ordering::Relaxed);
}
pub fn ai_insights_enabled() -> bool {
    t().toggles.ai_insights_enabled.load(Ordering::Relaxed)
}
pub fn set_cloud_enabled(enabled: bool) {
    t().toggles.cloud_enabled.store(enabled, Ordering::Relaxed);
}
pub fn cloud_enabled() -> bool {
    t().toggles.cloud_enabled.load(Ordering::Relaxed)
}
pub fn set_csv_export_enabled(enabled: bool) {
    t().toggles
        .csv_export_enabled
        .store(enabled, Ordering::Relaxed);
}
pub fn csv_export_enabled() -> bool {
    t().toggles.csv_export_enabled.load(Ordering::Relaxed)
}

pub fn inc_inspected() {
    t().counters.inspected.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_blocked() {
    t().counters.blocked.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_fp_in() {
    t().counters
        .fingerprinted_in
        .fetch_add(1, Ordering::Relaxed);
}
pub fn inc_fp_out() {
    t().counters
        .fingerprinted_out
        .fetch_add(1, Ordering::Relaxed);
}
pub fn inc_comp_in() {
    t().counters.compressed_in.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_comp_out() {
    t().counters.compressed_out.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_webhook_in_ok() {
    t().counters.webhook_in_ok.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_webhook_in_err() {
    t().counters.webhook_in_err.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_webhook_out_ok() {
    t().counters.webhook_out_ok.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_webhook_out_err() {
    t().counters.webhook_out_err.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_sig_ok() {
    t().counters.sig_ok.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_sig_err() {
    t().counters.sig_err.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SigPathStats {
    pub ok: u64,
    pub err: u64,
    pub last_ms: u128,
}

pub fn record_sig_ok_path(path: &str) {
    let mut m = t().sig_paths.lock().unwrap_or_else(|e| e.into_inner());
    let e = m.entry(path.to_string()).or_default();
    e.ok = e.ok.saturating_add(1);
    e.last_ms = now_unix_ms();
}
pub fn record_sig_err_path(path: &str) {
    let mut m = t().sig_paths.lock().unwrap_or_else(|e| e.into_inner());
    let e = m.entry(path.to_string()).or_default();
    e.err = e.err.saturating_add(1);
    e.last_ms = now_unix_ms();
}

pub fn adaptive_guard_tighten_for(path: &str) {
    // Decision inputs
    let risk = current_risk();
    let (ok, err) = {
        let m = t().sig_paths.lock().unwrap_or_else(|e| e.into_inner());
        match m.get(path) {
            Some(s) => (s.ok, s.err),
            None => (0, 0),
        }
    };
    let total = ok.saturating_add(err);
    if total == 0 {
        return;
    }
    let err_ratio = (err as f64) / (total as f64);
    // Tighten if high global risk or significant per-path error ratio
    let should_tighten = risk >= 70 || err_ratio >= 0.2;
    if !should_tighten {
        return;
    }
    if let Some(mut cfg) = crate::webhook::guards::get_guard_for(path) {
        let old = cfg.ts_window_ms;
        // shrink window by 50%, clamp to [60_000 .. old]
        let half = old / 2;
        let new_win = core::cmp::max(60_000, core::cmp::min(old, half.max(60_000)));
        let mut changed = false;
        if new_win < old {
            cfg.ts_window_ms = new_win;
            changed = true;
        }
        if !cfg.required {
            cfg.required = true;
            changed = true;
        }
        if !cfg.anti_replay_on {
            cfg.anti_replay_on = true;
            changed = true;
        }
        if changed {
            crate::webhook::guards::set_guard(cfg.clone());
            record_event(
                "guard_tighten",
                &format!("path={} ts_window_ms={}", path, cfg.ts_window_ms),
            );
        }
    }
}

pub fn record_event(kind: &str, detail: &str) {
    let ts = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis(),
        Err(_) => 0,
    };
    let line = format!(
        "{{\"ts\":{},\"kind\":\"{}\",\"detail\":\"{}\"}}",
        ts,
        sanitize(kind),
        sanitize(detail)
    );
    let tel = t();
    let mut ev = tel.events.lock().unwrap_or_else(|e| e.into_inner());
    if ev.len() >= 1024 {
        ev.pop_front();
    }
    ev.push_back(line);
}

fn sanitize(s: &str) -> String {
    s.replace('"', "'").replace('\n', " ")
}

pub fn metrics_json() -> String {
    let c = &t().counters;
    format!(
        "{{\"inspected\":{},\"blocked\":{},\"fp_in\":{},\"fp_out\":{},\"comp_in\":{},\"comp_out\":{},\"wh_in_ok\":{},\"wh_in_err\":{},\"wh_out_ok\":{},\"wh_out_err\":{},\"fw_allowed\":{},\"fw_blocked\":{},\"sig_ok\":{},\"sig_err\":{},\"oauth2_auth_req\":{},\"oauth2_auth_ok\":{},\"oauth2_auth_err\":{},\"oauth2_token_req\":{},\"oauth2_token_ok\":{},\"oauth2_token_err\":{},\"oauth2_intro_req\":{},\"oauth2_intro_ok\":{},\"oauth2_intro_err\":{},\"risk\":{},\"circuit_open\":{},\"compression_enabled\":{},\"mem_limit\":{},\"mem_auto\":{}}}",
        c.inspected.load(Ordering::Relaxed),
        c.blocked.load(Ordering::Relaxed),
        c.fingerprinted_in.load(Ordering::Relaxed),
        c.fingerprinted_out.load(Ordering::Relaxed),
        c.compressed_in.load(Ordering::Relaxed),
        c.compressed_out.load(Ordering::Relaxed),
        c.webhook_in_ok.load(Ordering::Relaxed),
        c.webhook_in_err.load(Ordering::Relaxed),
        c.webhook_out_ok.load(Ordering::Relaxed),
        c.webhook_out_err.load(Ordering::Relaxed),
        c.fw_allowed.load(Ordering::Relaxed),
        c.fw_blocked.load(Ordering::Relaxed),
        c.sig_ok.load(Ordering::Relaxed),
        c.sig_err.load(Ordering::Relaxed),
        c.oauth2_auth_requests.load(Ordering::Relaxed),
        c.oauth2_auth_success.load(Ordering::Relaxed),
        c.oauth2_auth_failed.load(Ordering::Relaxed),
        c.oauth2_token_requests.load(Ordering::Relaxed),
        c.oauth2_token_success.load(Ordering::Relaxed),
        c.oauth2_token_failed.load(Ordering::Relaxed),
        c.oauth2_introspect_requests.load(Ordering::Relaxed),
        c.oauth2_introspect_success.load(Ordering::Relaxed),
        c.oauth2_introspect_failed.load(Ordering::Relaxed),
        t().risk_score.load(Ordering::Relaxed),
        if t().circuit_open.load(Ordering::Relaxed) { 1 } else { 0 },
        if compression_enabled() { "true" } else { "false" },
        t().mem_limit_bytes.load(Ordering::Relaxed),
        if t().mem_auto_purge.load(Ordering::Relaxed) { "true" } else { "false" }
    )
}

pub fn events_ndjson() -> String {
    t().events
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------- Memory guard (zero-deps) ----------
pub fn set_memory_limit(bytes: u64, auto: bool) {
    t().mem_limit_bytes.store(bytes, Ordering::Relaxed);
    t().mem_auto_purge.store(auto, Ordering::Relaxed);
}

pub fn memory_status() -> (u64, bool, usize) {
    let limit = t().mem_limit_bytes.load(Ordering::Relaxed);
    let auto = t().mem_auto_purge.load(Ordering::Relaxed);
    let used = t().events.lock().unwrap_or_else(|e| e.into_inner()).len();
    (limit, auto, used)
}

pub fn try_memory_purge(force: bool) -> bool {
    let limit = t().mem_limit_bytes.load(Ordering::Relaxed);
    if limit == 0 && !force {
        return false;
    }
    // crude estimate: ~256 bytes per event line average; adjust when needed
    let approx_used = t()
        .events
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len()
        .saturating_mul(256) as u64;
    let over = approx_used > limit && limit > 0;
    if force || over {
        let mut ev = t().events.lock().unwrap_or_else(|e| e.into_inner());
        // purge oldest 50% to keep recency and reduce churn
        let drop_n = ev.len() / 2;
        for _ in 0..drop_n {
            ev.pop_front();
        }
        record_event(
            "mem_purge",
            &format!(
                "force={} dropped={} approx_before={} limit={}",
                force, drop_n, approx_used, limit
            ),
        );
        return true;
    }
    false
}

pub fn sig_paths_json() -> String {
    let m = t().sig_paths.lock().unwrap_or_else(|e| e.into_inner());
    let mut entries: Vec<(String, SigPathStats)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
    // sort descending by err
    entries.sort_by(|a, b| b.1.err.cmp(&a.1.err));
    let body = entries
        .into_iter()
        .map(|(k, s)| {
            format!(
                "{{\"path\":\"{}\",\"ok\":{},\"err\":{},\"last_ms\":{}}}",
                k, s.ok, s.err, s.last_ms
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{}]", body)
}

pub fn set_risk(score_0_to_100: u8) {
    t().risk_score
        .store(score_0_to_100 as u64, Ordering::Relaxed);
}
pub fn current_risk() -> u8 {
    t().risk_score.load(Ordering::Relaxed) as u8
}

pub fn export_events_ndjson() -> Vec<u8> {
    events_ndjson().into_bytes()
}

// ---------- Adaptive telemetry (zero-deps) ----------
#[derive(Debug)]
pub struct BehaviorStats {
    pub ewma_rps: f64,
    pub last_obs_ms: u128,
    pub uniques: VecDeque<u64>, // rolling hash of (ip|path)
}

impl Default for BehaviorStats {
    fn default() -> Self {
        Self {
            ewma_rps: 0.0,
            last_obs_ms: 0,
            uniques: VecDeque::with_capacity(256),
        }
    }
}

fn checksum64(s: &str) -> u64 {
    let mut acc: u64 = 1469598103934665603; // FNV offset basis constant-like (no deps)
    for b in s.as_bytes() {
        acc ^= *b as u64;
        acc = acc.wrapping_mul(1099511628211);
    }
    acc
}

/// Arabic: ملاحظة طلب HTTP وتعديل مستوى الخطر بثقل إحصائي بسيط
/// English: Observe HTTP request and adjust risk via simple EWMA/spike/uniques
pub fn observe_http(
    _method: &str,
    path: &str,
    status: u16,
    bytes_in: usize,
    bytes_out: usize,
    peer_ip: Option<&str>,
) {
    // compute instantaneous rate from time delta
    let now = now_unix_ms();
    let tel = t();
    let mut b = tel.behavior.lock().unwrap_or_else(|e| e.into_inner());
    let inst = if b.last_obs_ms == 0 {
        0.0
    } else {
        let dt_ms = (now.saturating_sub(b.last_obs_ms)) as f64;
        if dt_ms <= 0.0 {
            0.0
        } else {
            1000.0 / dt_ms
        }
    };
    let alpha = 0.2;
    b.ewma_rps = alpha * inst + (1.0 - alpha) * b.ewma_rps;
    b.last_obs_ms = now;

    // track uniques of (ip|path) with rolling window
    let key = match peer_ip {
        Some(ip) => format!("{}|{}", ip, path),
        None => format!("-|{}", path),
    };
    let h = checksum64(&key);
    b.uniques.push_back(h);
    if b.uniques.len() > 256 {
        b.uniques.pop_front();
    }

    drop(b); // release lock before adjusting risk

    // derive delta risk
    let mut delta_i = 0i32;
    if inst > 0.0 {
        let ew = t()
            .behavior
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ewma_rps;
        if inst > (ew * 3.0 + 5.0) {
            delta_i += 10;
        }
    }
    if status >= 500 {
        delta_i += 5;
    }
    if bytes_in > 1_000_000 || bytes_out > 1_000_000 {
        delta_i += 3;
    }

    // slight decay when calm
    if delta_i == 0 {
        let ew = t()
            .behavior
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ewma_rps;
        if ew < 0.5 {
            delta_i -= 1;
        }
    }

    if delta_i != 0 {
        let cur = tel.risk_score.load(Ordering::Relaxed) as i32;
        let new = (cur + delta_i).clamp(0, 100);
        tel.risk_score.store(new as u64, Ordering::Relaxed);
        // trigger auto key rotation policy (if configured)
        crate::crypto::key_rotation::auto_check(new as u8);
        // circuit breaker policy
        if new >= 90 {
            if !tel.circuit_open.swap(true, Ordering::Relaxed) {
                tel.circuit_open_ms
                    .store(now_unix_ms() as u64, Ordering::Relaxed);
                record_event("circuit_open", &format!("risk={}", new));
            }
        } else if new <= 40 && tel.circuit_open.swap(false, Ordering::Relaxed) {
            record_event("circuit_close", &format!("risk={}", new));
        }
    }
}

pub fn circuit_is_open() -> bool {
    t().circuit_open.load(Ordering::Relaxed)
}
pub fn fw_allow() {
    t().counters.fw_allowed.fetch_add(1, Ordering::Relaxed);
}
pub fn fw_block() {
    t().counters.fw_blocked.fetch_add(1, Ordering::Relaxed);
}

// ---------- Backup scheduling (zero-deps) ----------
#[derive(Debug, Clone)]
pub struct BackupSchedule {
    pub interval_secs: u64,
    pub next_unix_ms: u128,
    pub dest_url: Option<String>,
    pub dest_email: Option<String>,
    pub risk_threshold: u8, // only run if risk <= threshold
}

pub fn set_backup_consent(token: String) {
    *t().consent_token.lock().unwrap_or_else(|e| e.into_inner()) = Some(token);
}
pub fn clear_backup_consent() {
    *t().consent_token.lock().unwrap_or_else(|e| e.into_inner()) = None;
}
pub fn has_consent(token: &str) -> bool {
    t().consent_token
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_deref()
        == Some(token)
}

pub fn configure_backup(
    interval_secs: u64,
    dest_url: Option<String>,
    dest_email: Option<String>,
    risk_threshold: u8,
) {
    let now_ms = now_unix_ms();
    *t().backup.lock().unwrap_or_else(|e| e.into_inner()) = Some(BackupSchedule {
        interval_secs,
        next_unix_ms: now_ms + (interval_secs as u128) * 1000,
        dest_url,
        dest_email,
        risk_threshold,
    });
    spawn_scheduler_once();
}

pub fn disable_backup() {
    *t().backup.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

static SCHED_STARTED: OnceLock<()> = OnceLock::new();
fn spawn_scheduler_once() {
    if SCHED_STARTED.set(()).is_ok() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let mut run = None;
            {
                let tel = t();
                if let Some(cfg) = tel.backup.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                    let now = now_unix_ms();
                    if now >= cfg.next_unix_ms {
                        run = Some(cfg);
                    }
                }
            }
            if let Some(mut cfg) = run {
                // security checks
                let risk = t().risk_score.load(Ordering::Relaxed) as u8;
                if risk <= cfg.risk_threshold {
                    // perform send
                    if let Err(e) = perform_backup_send(&cfg) {
                        record_event("backup_error", &e);
                    } else {
                        record_event("backup_ok", "scheduled send completed");
                    }
                } else {
                    record_event("backup_skip", "risk too high");
                }
                // schedule next
                cfg.next_unix_ms = now_unix_ms() + (cfg.interval_secs as u128) * 1000;
                *t().backup.lock().unwrap_or_else(|e| e.into_inner()) = Some(cfg);
            }
        });
    }
}

fn now_unix_ms() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis(),
        Err(_) => 0,
    }
}

fn backup_fingerprint(data: &[u8]) -> String {
    use crate::core::digest::CoreDigest;
    let mut d = crate::core::digest::StdHasherDigest::default();
    d.hash_bytes(data);
    d.finalize_hex()
}

fn perform_backup_send(cfg: &BackupSchedule) -> Result<(), String> {
    let data = export_events_ndjson();
    let _fp = backup_fingerprint(&data);
    if let Some(_url) = &cfg.dest_url {
        // HTTP POST via std (if enabled)
        #[cfg(all(feature = "egress", feature = "egress_http_std"))]
        {
            use std::io::Write;
            use std::net::TcpStream;
            if let Ok((host, port, path)) = crate::webhook::parse_http_url(_url) {
                let mut s = TcpStream::connect((host.as_str(), port)).map_err(|e| e.to_string())?;
                let header = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, host, data.len());
                s.write_all(header.as_bytes()).map_err(|e| e.to_string())?;
                s.write_all(&data).map_err(|e| e.to_string())?;
                return Ok(());
            }
            return Err("invalid url".into());
        }
        #[cfg(not(all(feature = "egress", feature = "egress_http_std")))]
        {
            return Err("egress disabled".into());
        }
    }
    if let Some(_email) = &cfg.dest_email {
        #[cfg(feature = "smtp_std")]
        {
            let body = String::from_utf8_lossy(&data).to_string();
            super_email_send(_email, "MKT Backup", &body)?;
            return Ok(());
        }
        #[cfg(not(feature = "smtp_std"))]
        {
            return Err("smtp disabled".into());
        }
    }
    Err("no destination configured".into())
}

#[cfg(feature = "smtp_std")]
fn super_email_send(to: &str, subject: &str, body: &str) -> Result<(), String> {
    // delegate to std_http smtp sender (kept here for decoupling in future)
    crate::api::std_http::smtp_send_simple(to, subject, body).map_err(|e| e.to_string())
}

// ---------- Templates (AR/EN) ----------
#[derive(Debug, Clone, Default)]
pub struct Templates {
    pub subject_ar: Option<String>,
    pub body_ar: Option<String>,
    pub subject_en: Option<String>,
    pub body_en: Option<String>,
}

pub fn set_template(lang: &str, subject: String, body: String) {
    let mut tpls = t().templates.lock().unwrap_or_else(|e| e.into_inner());
    match lang {
        "ar" => {
            tpls.subject_ar = Some(subject);
            tpls.body_ar = Some(body);
        }
        _ => {
            tpls.subject_en = Some(subject);
            tpls.body_en = Some(body);
        }
    }
}
pub fn set_default_lang(lang: &str) {
    t().default_lang_ar
        .store(matches!(lang, "ar" | "AR"), Ordering::Relaxed);
}

pub fn compose_backup_email(lang: Option<&str>, data_ndjson: &str) -> (String, String) {
    let tpls = t()
        .templates
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let use_ar = lang
        .map(|s| s.eq_ignore_ascii_case("ar"))
        .unwrap_or_else(|| t().default_lang_ar.load(Ordering::Relaxed));
    if use_ar {
        let subj = tpls
            .subject_ar
            .clone()
            .unwrap_or_else(|| "نسخة احتياطية للنظام".to_string());
        let body = format!(
            "{}\n\n{}",
            tpls.body_ar
                .clone()
                .unwrap_or_else(|| "مرفق سجل الأحداث بنسق NDJSON".to_string()),
            data_ndjson
        );
        (subj, body)
    } else {
        let subj = tpls
            .subject_en
            .clone()
            .unwrap_or_else(|| "System Backup".to_string());
        let body = format!(
            "{}\n\n{}",
            tpls.body_en
                .clone()
                .unwrap_or_else(|| "Attached NDJSON event log".to_string()),
            data_ndjson
        );
        (subj, body)
    }
}

fn detect_default_lang_ar() -> bool {
    let mut val = std::env::var("APP_LANG")
        .ok()
        .or_else(|| std::env::var("LANG").ok())
        .or_else(|| std::env::var("LC_ALL").ok())
        .unwrap_or_default();
    val.make_ascii_lowercase();
    val.contains("ar")
}

// ---------- OAuth2 Telemetry Functions ----------

/// Arabic: زيادة عداد طلبات المصادقة OAuth2
/// English: Increment OAuth2 authorization requests counter
pub fn inc_oauth2_auth_requests() {
    t().counters
        .oauth2_auth_requests
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد نجاح المصادقة OAuth2
/// English: Increment OAuth2 authorization success counter
pub fn inc_oauth2_auth_success() {
    t().counters
        .oauth2_auth_success
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد فشل المصادقة OAuth2
/// English: Increment OAuth2 authorization failed counter
pub fn inc_oauth2_auth_failed() {
    t().counters
        .oauth2_auth_failed
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد طلبات الرموز OAuth2
/// English: Increment OAuth2 token requests counter
pub fn inc_oauth2_token_requests() {
    t().counters
        .oauth2_token_requests
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد نجاح الرموز OAuth2
/// English: Increment OAuth2 token success counter
pub fn inc_oauth2_token_success() {
    t().counters
        .oauth2_token_success
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد فشل الرموز OAuth2
/// English: Increment OAuth2 token failed counter
pub fn inc_oauth2_token_failed() {
    t().counters
        .oauth2_token_failed
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد طلبات فحص الرموز OAuth2
/// English: Increment OAuth2 introspection requests counter
pub fn inc_oauth2_introspect_requests() {
    t().counters
        .oauth2_introspect_requests
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد نجاح فحص الرموز OAuth2
/// English: Increment OAuth2 introspection success counter
pub fn inc_oauth2_introspect_success() {
    t().counters
        .oauth2_introspect_success
        .fetch_add(1, Ordering::Relaxed);
}

/// Arabic: زيادة عداد فشل فحص الرموز OAuth2
/// English: Increment OAuth2 introspection failed counter
pub fn inc_oauth2_introspect_failed() {
    t().counters
        .oauth2_introspect_failed
        .fetch_add(1, Ordering::Relaxed);
}

// ---------- Risk Alerts (zero-deps) ----------
#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub risk_high_threshold: u8,
    pub dest_email: Option<String>,
    pub dest_url: Option<String>,
    pub cooldown_secs: u64,
    pub last_alert_unix_ms: u128,
}

pub fn set_alert_config(risk: u8, email: Option<String>, url: Option<String>, cooldown_secs: u64) {
    *t().alerts.lock().unwrap_or_else(|e| e.into_inner()) = Some(AlertConfig {
        risk_high_threshold: risk,
        dest_email: email,
        dest_url: url,
        cooldown_secs,
        last_alert_unix_ms: 0,
    });
    spawn_alert_monitor_once();
}

pub fn disable_alerts() {
    *t().alerts.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

static ALERT_STARTED: OnceLock<()> = OnceLock::new();
fn spawn_alert_monitor_once() {
    if ALERT_STARTED.set(()).is_ok() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let cfg_opt = t().alerts.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(mut cfg) = cfg_opt {
                let risk = t().risk_score.load(Ordering::Relaxed) as u8;
                let now = now_unix_ms();
                if risk >= cfg.risk_high_threshold
                    && now.saturating_sub(cfg.last_alert_unix_ms)
                        >= (cfg.cooldown_secs as u128) * 1000
                {
                    // record event
                    record_event(
                        "risk_alert",
                        &format!("risk={} threshold={}", risk, cfg.risk_high_threshold),
                    );
                    // try send
                    let payload = format!(
                        "{{\"alert\":\"risk_high\",\"risk\":{},\"threshold\":{}}}",
                        risk, cfg.risk_high_threshold
                    );
                    let _ = send_alert(&cfg, &payload);
                    cfg.last_alert_unix_ms = now;
                    *t().alerts.lock().unwrap_or_else(|e| e.into_inner()) = Some(cfg);
                }
            }
        });
    }
}

fn send_alert(cfg: &AlertConfig, _payload: &str) -> Result<(), String> {
    if let Some(_url) = &cfg.dest_url {
        #[cfg(all(feature = "egress", feature = "egress_http_std"))]
        {
            use std::io::Write;
            use std::net::TcpStream;
            if let Ok((host, port, path)) = crate::webhook::parse_http_url(_url) {
                let mut s = TcpStream::connect((host.as_str(), port)).map_err(|e| e.to_string())?;
                let header = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, host, _payload.len());
                s.write_all(header.as_bytes()).map_err(|e| e.to_string())?;
                s.write_all(_payload.as_bytes())
                    .map_err(|e| e.to_string())?;
                return Ok(());
            }
        }
    }
    if let Some(_email) = &cfg.dest_email {
        #[cfg(feature = "smtp_std")]
        {
            let (subj, body) = compose_backup_email(None, _payload);
            super_email_send(_email, &subj, &body)?;
            return Ok(());
        }
    }
    Ok(())
}
