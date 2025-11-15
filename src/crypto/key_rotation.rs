/*!
Arabic: تدوير مفاتيح في الذاكرة مع حارس مضاد للإعادة (Anti‑Replay) – صفري التبعيات.
English: In‑memory key rotation with an Anti‑Replay guard – zero‑dependency.

الغرض | Purpose:
- إدارة دورة حياة المفاتيح (إنشاء، تدوير، تعطيل/إلغاء) داخل الذاكرة دون تبعيات خارجية.
- منع إعادة الاستخدام للـ nonce/التذكرة ضمن نافذة زمنية قصيرة.
- توفير API بسيط يمكن وصله مع `crypto_smart::keystore::InMemoryKeyStore`.

ملاحظات أمنية | Security Notes:
- في نمط صفري التبعيات لا يتوفر RNG حقيقي؛ نستخدم توليدًا حتميًا بسيطًا (timestamp+counter+checksum) لأغراض الاختبار/التكامل الداخلي. عند الحاجة للإنتاج، اربط مزوّد RNG حقيقي عبر Trait خارجي.
- المسح الآمن للذاكرة يتم أفضل‑جهد عبر إسقاط القيم؛ عند تفعيل ميزة `secure_secrecy`، تتوافر ضمانات أقوى.
*/

use crate::security::crypto_smart::keystore::{make_device_bound_meta, InMemoryKeyStore};
use crate::security::crypto_smart::traits::{
    CryptoStrictError, KeyId, KeyMeta, KeyStatus, KeyStore,
};
use crate::security::secret::SecureBytes;
use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct RotatingKeyManager {
    store: Mutex<InMemoryKeyStore>,
    anti_replay: Mutex<AntiReplay>,
    counter: AtomicU64,
    rng: Mutex<
        Option<Arc<dyn crate::security::crypto_smart::traits::CryptoRngProvider + Send + Sync>>,
    >,
}

#[derive(Debug)]
struct AntiReplay {
    // Arabic: لكل مفتاح نخزن نافذة من بصمات nonces مع طوابع زمنية
    // English: For each key, keep a window of nonce hashes with timestamps
    per_key: HashMap<String, VecDeque<(u64, u64)>>, // (nonce_hash, ts_ms)
    max_entries_per_key: usize,
    window_ms: u64,
}

impl Default for AntiReplay {
    fn default() -> Self {
        Self {
            per_key: HashMap::new(),
            max_entries_per_key: 1024,
            window_ms: 5 * 60 * 1000,
        }
    }
}

impl RotatingKeyManager {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(InMemoryKeyStore::new()),
            anti_replay: Mutex::new(AntiReplay::default()),
            counter: AtomicU64::new(1),
            rng: Mutex::new(None),
        }
    }

    pub fn with_params(max_entries_per_key: usize, window_ms: u64) -> Self {
        let ar = AntiReplay {
            per_key: HashMap::new(),
            max_entries_per_key: max_entries_per_key.max(16),
            window_ms: window_ms.max(1000),
        };
        Self {
            store: Mutex::new(InMemoryKeyStore::new()),
            anti_replay: Mutex::new(ar),
            counter: AtomicU64::new(1),
            rng: Mutex::new(None),
        }
    }

    /// Arabic: إنشاء مفتاح جديد وكتابته بالمخزن
    /// English: Create a new key and store it
    pub fn create_key(
        &self,
        key_id: &str,
        version: u32,
        key_len: usize,
        device_fp_hash: Option<String>,
        created_ms: u64,
    ) -> Result<KeyMeta, CryptoStrictError> {
        let key = self.generate_bytes(key_len);
        let meta = match device_fp_hash {
            Some(h) => make_device_bound_meta(key_id.to_string(), version, created_ms, h),
            None => KeyMeta {
                key_id: KeyId(key_id.to_string()),
                version,
                created_ms,
                device_fingerprint_hash: None,
                status: KeyStatus::Active,
            },
        };
        self.store
            .lock()
            .map_err(|_| CryptoStrictError::NotAvailable)?
            .put(meta.clone(), SecureBytes::new(key))?;
        Ok(meta)
    }

    /// Arabic: تدوير مفتاح موجود إلى نسخة جديدة مع زيادة رقم الإصدار
    /// English: Rotate an existing key to a new version
    pub fn rotate_key(
        &self,
        key_id: &str,
        new_version: u32,
        key_len: usize,
        created_ms: u64,
    ) -> Result<(), CryptoStrictError> {
        let new_key = SecureBytes::new(self.generate_bytes(key_len));
        let kid = KeyId(key_id.to_string());
        self.store
            .lock()
            .map_err(|_| CryptoStrictError::NotAvailable)?
            .rotate(&kid, new_key, new_version, created_ms)
    }

    /// Arabic: تغيير حالة المفتاح (تعطيل/إلغاء)
    /// English: Set key status (disable/revoke)
    pub fn set_status(&self, key_id: &str, status: KeyStatus) -> Result<(), CryptoStrictError> {
        let kid = KeyId(key_id.to_string());
        self.store
            .lock()
            .map_err(|_| CryptoStrictError::NotAvailable)?
            .set_status(&kid, status)
    }

    /// Arabic: جلب مفتاح مع بياناته
    /// English: Fetch key with metadata
    pub fn get(&self, key_id: &str) -> Result<(KeyMeta, SecureBytes), CryptoStrictError> {
        self.store
            .lock()
            .map_err(|_| CryptoStrictError::NotAvailable)?
            .get(&KeyId(key_id.to_string()))
    }

    /// Arabic: جلب ميتاداتا مفتاح فقط
    /// English: Fetch metadata only
    pub fn get_meta(&self, key_id: &str) -> Option<KeyMeta> {
        self.get(key_id).ok().map(|(m, _)| m)
    }

    /// Arabic: تصدير ميتاداتا المفاتيح المعروفة (من دون المواد السرية)
    /// English: Export metadata for known keys (without secret material)
    pub fn export_metadata_for(&self, ids: &[String]) -> Vec<KeyMeta> {
        let mut metas: Vec<KeyMeta> = Vec::new();
        for id in ids {
            if let Some(m) = self.get_meta(id) {
                metas.push(m);
            }
        }
        metas.sort_by(|a, b| a.key_id.0.cmp(&b.key_id.0));
        metas
    }

    /// Arabic: تصدير المواد السرية بصيغة hex (للاختبار وبإدراك المخاطر)
    /// English: Export key materials as hex (testing only; risk-aware)
    pub fn export_material_hex_for(&self, ids: &[String]) -> Vec<(KeyMeta, String)> {
        let mut out: Vec<(KeyMeta, String)> = Vec::new();
        for id in ids {
            if let Ok((m, k)) = self.get(id) {
                out.push((m, to_hex(k.expose())));
            }
        }
        out.sort_by(|a, b| a.0.key_id.0.cmp(&b.0.key_id.0));
        out
    }

    /// Arabic: التحقق من nonce وإضافته لمنع الإعادة ضمن النافذة الزمنية
    /// English: Check and mark a nonce to prevent replay within the window
    pub fn check_and_mark_nonce(
        &self,
        key_id: &str,
        nonce: &[u8],
        ts_ms: u64,
    ) -> Result<(), CryptoStrictError> {
        let mut ar = self
            .anti_replay
            .lock()
            .map_err(|_| CryptoStrictError::NotAvailable)?;
        let max_cap = ar.max_entries_per_key;
        let window = ar.window_ms;
        let list = ar
            .per_key
            .entry(key_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(max_cap));
        let h = checksum64_bytes(nonce);
        // prune
        while let Some(&(_, old_ts)) = list.front() {
            if ts_ms.saturating_sub(old_ts) > window || list.len() > max_cap {
                list.pop_front();
            } else {
                break;
            }
        }
        // check
        if list.iter().any(|(x, _)| *x == h) {
            return Err(CryptoStrictError::InvalidParameter);
        }
        list.push_back((h, ts_ms));
        Ok(())
    }

    pub fn set_rng_provider(
        &self,
        provider: Arc<dyn crate::security::crypto_smart::traits::CryptoRngProvider + Send + Sync>,
    ) {
        *self.rng.lock().unwrap_or_else(|e| e.into_inner()) = Some(provider);
    }

    fn generate_bytes(&self, len: usize) -> Vec<u8> {
        // Arabic: توليد بسيط لأغراض الاختبار (timestamp + counter + FNV‑like checksum)
        // English: Simple generator for testing (timestamp + counter + FNV‑like checksum)
        if let Some(r) = self.rng.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            if let Ok(v) = r.random(len) {
                return v;
            }
        }
        let mut out = vec![0u8; len.max(16)];
        let now = now_unix_ms();
        let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
        let seed = mix64(now ^ ctr);
        for (i, b) in out.iter_mut().enumerate() {
            *b = mix8(seed, i as u64);
        }
        out
    }
}

// Arabic: مُدير مفاتيح عالمي للاستخدام من طبقات الـ API
// English: Global key manager singleton for API layers
static KEY_MGR: OnceLock<RotatingKeyManager> = OnceLock::new();

pub fn key_manager() -> &'static RotatingKeyManager {
    KEY_MGR.get_or_init(RotatingKeyManager::new)
}

// Additional utilities for Anti-Replay lifecycle control
impl RotatingKeyManager {
    /// Purge Anti-Replay entries for all keys according to current window and capacity
    pub fn purge_anti_replay_now(&self, now_ms: u64) {
        if let Ok(mut ar) = self.anti_replay.lock() {
            let max_cap = ar.max_entries_per_key;
            let window = ar.window_ms;
            for (_kid, list) in ar.per_key.iter_mut() {
                while let Some(&(_, old_ts)) = list.front() {
                    if now_ms.saturating_sub(old_ts) > window || list.len() > max_cap {
                        list.pop_front();
                    } else {
                        break;
                    }
                }
                while list.len() > max_cap {
                    list.pop_front();
                }
            }
        }
    }

    /// Safely adjust Anti-Replay parameters
    pub fn set_anti_replay_params(&self, max_entries_per_key: usize, window_ms: u64) {
        if let Ok(mut ar) = self.anti_replay.lock() {
            ar.max_entries_per_key = max_entries_per_key.max(16);
            ar.window_ms = window_ms.max(1000);
        }
    }

    /// Arabic: إحصاءات سريعة عن Anti-Replay (عدد المفاتيح وعدد الإدخالات)
    /// English: Quick Anti-Replay stats (keys count, entries count)
    pub fn anti_replay_counts(&self) -> (usize, usize) {
        if let Ok(ar) = self.anti_replay.lock() {
            let keys = ar.per_key.len();
            let entries: usize = ar.per_key.values().map(|v| v.len()).sum();
            (keys, entries)
        } else {
            (0, 0)
        }
    }
}

// ---------- Auto-rotation policy (zero-deps) ----------
#[derive(Default, Clone)]
struct AutoPolicy {
    enabled: bool,
    threshold: u8,
    min_interval_ms: u64,
    last_rot_ms: u64,
    keys: Vec<String>,
    key_len: usize,
}

static AUTO: OnceLock<Mutex<AutoPolicy>> = OnceLock::new();

pub fn configure_auto_rotation(
    threshold: u8,
    min_interval_secs: u64,
    keys: Vec<String>,
    key_len: usize,
) {
    let p = AutoPolicy {
        enabled: true,
        threshold,
        min_interval_ms: min_interval_secs.saturating_mul(1000),
        last_rot_ms: 0,
        keys,
        key_len,
    };
    *AUTO
        .get_or_init(|| Mutex::new(AutoPolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = p;
}

pub fn disable_auto_rotation() {
    AUTO.get_or_init(|| Mutex::new(AutoPolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .enabled = false;
}

pub fn auto_check(current_risk: u8) {
    let mut p = AUTO
        .get_or_init(|| Mutex::new(AutoPolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !p.enabled || current_risk < p.threshold {
        return;
    }
    let now = now_unix_ms();
    if now.saturating_sub(p.last_rot_ms) < p.min_interval_ms {
        return;
    }
    let mgr = key_manager();
    for id in p.keys.iter() {
        if let Ok((meta, _)) = mgr.get(id) {
            let _ = mgr.rotate_key(id, meta.version.saturating_add(1), p.key_len, now);
        }
    }
    p.last_rot_ms = now;
}

/// Arabic: لقطة حالة للتدوير التلقائي لعرضها في لوحة المعلومات
/// English: Snapshot of auto-rotation status for the dashboard
pub fn auto_status() -> (bool, u8, u64, u64, usize, usize) {
    let p = AUTO
        .get_or_init(|| Mutex::new(AutoPolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    (
        p.enabled,
        p.threshold,
        p.min_interval_ms,
        p.last_rot_ms,
        p.keys.len(),
        p.key_len,
    )
}

// ---------- Anti-Replay Purge Scheduling (zero-deps) ----------
#[derive(Clone, Copy, Debug)]
enum PurgeCadence {
    Daily,
    Weekly,
    Monthly,
}

impl PurgeCadence {
    fn to_ms(self) -> u64 {
        match self {
            PurgeCadence::Daily => 24 * 60 * 60 * 1000,
            PurgeCadence::Weekly => 7 * 24 * 60 * 60 * 1000,
            PurgeCadence::Monthly => 30 * 24 * 60 * 60 * 1000,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            PurgeCadence::Daily => "daily",
            PurgeCadence::Weekly => "weekly",
            PurgeCadence::Monthly => "monthly",
        }
    }
}

#[derive(Clone, Debug)]
struct ArPurgePolicy {
    enabled: bool,
    cadence: PurgeCadence,
    next_unix_ms: u64,
    sensitivity: u8,     // 0..100: higher -> retain more under high risk
    base_window_ms: u64, // baseline window
    base_capacity: usize,
}

impl Default for ArPurgePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            cadence: PurgeCadence::Weekly,
            next_unix_ms: 0,
            sensitivity: 50,
            base_window_ms: 5 * 60 * 1000,
            base_capacity: 1024,
        }
    }
}

static AR_PURGE: OnceLock<Mutex<ArPurgePolicy>> = OnceLock::new();
static AR_PURGE_STARTED: OnceLock<()> = OnceLock::new();

fn ar_spawn_scheduler_once() {
    if AR_PURGE_STARTED.set(()).is_ok() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(15));
            let (enabled, due, cadence_ms, sensitivity, base_w, base_c) = {
                let p = AR_PURGE
                    .get_or_init(|| Mutex::new(ArPurgePolicy::default()))
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                (
                    p.enabled,
                    p.next_unix_ms,
                    p.cadence.to_ms(),
                    p.sensitivity,
                    p.base_window_ms,
                    p.base_capacity,
                )
            };
            if !enabled {
                continue;
            }
            let now = now_unix_ms();
            if now < due {
                continue;
            }

            // Adaptive params: retain more under high risk, trim when risk is low
            let risk = crate::telemetry::current_risk();
            let mgr = key_manager();
            let (window_ms, capacity) = if risk >= sensitivity {
                (
                    base_w.saturating_mul(3).min(60 * 60 * 1000),
                    base_c.saturating_mul(2).min(8192),
                )
            } else {
                (base_w, base_c)
            };
            mgr.set_anti_replay_params(capacity, window_ms);
            mgr.purge_anti_replay_now(now);

            // schedule next
            let mut p = AR_PURGE
                .get_or_init(|| Mutex::new(ArPurgePolicy::default()))
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            p.next_unix_ms = now.saturating_add(cadence_ms);
        });
    }
}

/// Configure Anti-Replay purge with cadence and risk sensitivity
pub fn configure_anti_replay_purge(
    mode: &str,
    sensitivity: u8,
    base_window_ms: u64,
    base_capacity: usize,
) {
    let cadence = match mode {
        "daily" => PurgeCadence::Daily,
        "weekly" => PurgeCadence::Weekly,
        _ => PurgeCadence::Monthly,
    };
    let now = now_unix_ms();
    let mut p = AR_PURGE
        .get_or_init(|| Mutex::new(ArPurgePolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    p.enabled = true;
    p.cadence = cadence;
    p.next_unix_ms = now.saturating_add(cadence.to_ms());
    p.sensitivity = sensitivity;
    p.base_window_ms = base_window_ms.max(1000);
    p.base_capacity = base_capacity.max(16);
    drop(p);
    ar_spawn_scheduler_once();
}

/// Disable Anti-Replay purge scheduling
pub fn disable_anti_replay_purge() {
    AR_PURGE
        .get_or_init(|| Mutex::new(ArPurgePolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .enabled = false;
}

/// Run purge immediately with auto-adaptation to current risk
pub fn run_anti_replay_purge_now() {
    let mgr = key_manager();
    let risk = crate::telemetry::current_risk();
    let (base_w, base_c, sensitivity) = {
        let p = AR_PURGE
            .get_or_init(|| Mutex::new(ArPurgePolicy::default()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        (p.base_window_ms, p.base_capacity, p.sensitivity)
    };
    let (window_ms, capacity) = if risk >= sensitivity {
        (
            base_w.saturating_mul(3).min(60 * 60 * 1000),
            base_c.saturating_mul(2).min(8192),
        )
    } else {
        (base_w, base_c)
    };
    mgr.set_anti_replay_params(capacity, window_ms);
    mgr.purge_anti_replay_now(now_unix_ms());
}

/// Snapshot Anti-Replay purge status for dashboard
pub fn anti_replay_purge_status() -> (bool, &'static str, u64, u64, u8, u64, usize) {
    let p = AR_PURGE
        .get_or_init(|| Mutex::new(ArPurgePolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    (
        p.enabled,
        p.cadence.as_str(),
        p.cadence.to_ms(),
        p.next_unix_ms,
        p.sensitivity,
        p.base_window_ms,
        p.base_capacity,
    )
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn mix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58476D1CE4E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn mix8(seed: u64, idx: u64) -> u8 {
    checksum64(&(seed ^ (idx.wrapping_mul(0x9E37)))).to_le_bytes()[0]
}

fn checksum64(s: &u64) -> u64 {
    let mut acc: u64 = 1469598103934665603; // FNV offset basis like
    let bytes = s.to_le_bytes();
    for b in bytes.iter() {
        acc ^= *b as u64;
        acc = acc.wrapping_mul(1099511628211);
    }
    acc
}

fn checksum64_bytes(nonce: &[u8]) -> u64 {
    let mut acc: u64 = 1469598103934665603;
    for b in nonce {
        acc ^= *b as u64;
        acc = acc.wrapping_mul(1099511628211);
    }
    acc
}

fn to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------- Tests (zero‑deps) ----------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_and_fetch() {
        let mgr = RotatingKeyManager::new();
        let meta = mgr
            .create_key("auth_hmac", 1, 32, None, now_unix_ms())
            .unwrap();
        assert_eq!(meta.version, 1);
        mgr.rotate_key("auth_hmac", 2, 32, now_unix_ms()).unwrap();
        let (m2, k2) = mgr.get("auth_hmac").unwrap();
        assert_eq!(m2.version, 2);
        assert_eq!(k2.expose().len(), 32);
    }

    #[test]
    fn anti_replay_works() {
        let mgr = RotatingKeyManager::with_params(16, 5000);
        let nonce = b"unique-nonce-123";
        let now = now_unix_ms();
        mgr.check_and_mark_nonce("auth_hmac", nonce, now).unwrap();
        let dup = mgr.check_and_mark_nonce("auth_hmac", nonce, now + 100);
        assert!(dup.is_err());
    }
}
