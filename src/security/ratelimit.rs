/******************************************************************************************
    📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: ratelimit.rs
    المسار:    src/security/ratelimit.rs

    دور الملف:
    وحدة تحديد معدل الطلبات (Rate Limiting) لحماية الأنظمة من هجمات DoS/Brute-force/Abuse.
    توفر منطقًا مرنًا وقابلًا للتخصيص لتحديد المعدل لكل IP أو مستخدم أو نقطة نهاية، مع دعم القوائم البيضاء والسوداء والتنبيهات.

    File Name: ratelimit.rs
    Path:     src/security/ratelimit.rs

    File Role:
    Rate limiting module to protect systems from DoS/Brute-force/Abuse attacks.
    Provides flexible, customizable logic for per-IP/user/endpoint rate limiting, with support for whitelists, blacklists, and alerting.
******************************************************************************************/

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

const PRUNE_THRESHOLD_IPS: usize = 1024;
const STALE_WINDOW_MULTIPLIER: u32 = 10;

/// إعدادات تحديد المعدل (قابلة للتخصيص)
/// Rate limiting settings (customizable)
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,          // الحد الأقصى للطلبات
    pub window: Duration,           // فترة السماح
    pub whitelist: HashSet<IpAddr>, // قائمة بيضاء (مستثناة)
    pub blacklist: HashSet<IpAddr>, // قائمة سوداء (محظورة)
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60, // 60 طلب في الدقيقة
            window: Duration::from_secs(60),
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
        }
    }
}

/// خطأ تحديد المعدل
/// Rate limiting error
#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("تم تجاوز الحد المسموح للطلبات. حاول لاحقًا.\nRate limit exceeded. Try again later.")]
    LimitExceeded,
    #[error("العنوان محظور (قائمة سوداء).\nIP is blacklisted.")]
    Blacklisted,
}

/// هيكل تتبع الطلبات لكل IP
/// Tracks requests per IP
#[derive(Debug)]
struct RequestInfo {
    count: u32,
    window_start: Instant,
}

/// محرك تحديد المعدل (آمن ومتزامن)
/// Rate Limiter Engine (thread-safe, async)
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    requests: RwLock<HashMap<IpAddr, RequestInfo>>,
}

impl RateLimiter {
    /// إنشاء محرك جديد مع إعدادات مخصصة
    /// Create a new rate limiter with custom config
    pub fn new(config: RateLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            requests: RwLock::new(HashMap::new()),
        })
    }

    /// تحقق من معدل الطلبات لهذا العنوان
    /// Check rate limit for this IP
    pub async fn check(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        if self.config.whitelist.contains(&ip) {
            return Ok(()); // مستثنى من التحديد
        }
        if self.config.blacklist.contains(&ip) {
            return Err(RateLimitError::Blacklisted);
        }
        let mut reqs = self.requests.write().await;
        let now = Instant::now();
        self.prune_if_needed(&mut reqs, now);

        let entry = reqs.entry(ip).or_insert(RequestInfo {
            count: 0,
            window_start: now,
        });
        if now.saturating_duration_since(entry.window_start) > self.config.window {
            entry.count = 1;
            entry.window_start = now;
        } else {
            entry.count += 1;
        }
        if entry.count > self.config.max_requests {
            return Err(RateLimitError::LimitExceeded);
        }
        Ok(())
    }

    fn prune_if_needed(&self, reqs: &mut HashMap<IpAddr, RequestInfo>, now: Instant) {
        if reqs.len() < PRUNE_THRESHOLD_IPS {
            return;
        }

        let stale_after = self.config.window.saturating_mul(STALE_WINDOW_MULTIPLIER);
        reqs.retain(|_, info| now.saturating_duration_since(info.window_start) <= stale_after);
    }

    /// أضف عنوان IP للقائمة البيضاء
    /// Add IP to whitelist
    pub fn add_whitelist(&mut self, ip: IpAddr) {
        self.config.whitelist.insert(ip);
    }
    /// أضف عنوان IP للقائمة السوداء
    /// Add IP to blacklist
    pub fn add_blacklist(&mut self, ip: IpAddr) {
        self.config.blacklist.insert(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_entries_are_pruned_when_map_grows() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests: 10,
            window: Duration::from_millis(5),
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
        });

        for i in 0..(PRUNE_THRESHOLD_IPS + 64) {
            let ip = IpAddr::from([10, 0, ((i / 256) & 0xff) as u8, (i % 256) as u8]);
            let _ = limiter.check(ip).await;
        }

        let before = limiter.requests.read().await.len();
        assert!(before >= PRUNE_THRESHOLD_IPS);

        tokio::time::sleep(Duration::from_millis(70)).await;

        let trigger_ip = IpAddr::from([127, 0, 0, 1]);
        let _ = limiter.check(trigger_ip).await;

        let after = limiter.requests.read().await.len();
        assert!(after < before);
        assert!(after <= 2);
    }

    #[tokio::test]
    async fn blacklisted_ip_is_denied_immediately() {
        let blocked_ip = IpAddr::from([203, 0, 113, 10]);
        let mut blacklist = HashSet::new();
        blacklist.insert(blocked_ip);

        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests: 10,
            window: Duration::from_secs(60),
            whitelist: HashSet::new(),
            blacklist,
        });

        let result = limiter.check(blocked_ip).await;
        assert!(matches!(result, Err(RateLimitError::Blacklisted)));
    }
}

/******************************************************************************************
    مثال ربط مع نقطة نهاية API:
    Example integration with API endpoint:

    use actix_web::{HttpRequest, HttpResponse};
    use crate::security::ratelimit::{RateLimiter, RateLimitError};

    async fn my_endpoint(req: HttpRequest, rate_limiter: Arc<RateLimiter>) -> HttpResponse {
        let ip = req.peer_addr().map(|a| a.ip()).unwrap_or_else(|| "0.0.0.0".parse().unwrap());
        match rate_limiter.check(ip).await {
            Ok(()) => {
                // أكمل منطق الطلب
                HttpResponse::Ok().body("Request allowed!")
            }
            Err(RateLimitError::LimitExceeded) => {
                HttpResponse::TooManyRequests().body("تم تجاوز الحد المسموح للطلبات. حاول لاحقًا.")
            }
            Err(RateLimitError::Blacklisted) => {
                HttpResponse::Forbidden().body("العنوان محظور (قائمة سوداء).")
            }
        }
    }
******************************************************************************************/
