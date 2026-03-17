use crate::core::composite_verification::CompositeVerifier;
use crate::core::cross_location::CrossValidationEngine;
use crate::core::weather_val::WeatherEngine;
use crate::security::ai_guard::RequestAiGuard;
use crate::security::jwt::JwtManager;
use crate::security::ratelimit::RateLimiter;
use crate::security::secret::SecureString;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type DbPool = tokio_rusqlite::Connection;

pub struct AlertMemoryStore {
    max_items: usize,
    items: RwLock<VecDeque<String>>,
}

impl AlertMemoryStore {
    #[must_use]
    pub fn new(max_items: usize) -> Self {
        Self {
            max_items,
            items: RwLock::new(VecDeque::new()),
        }
    }

    pub async fn push(&self, alert_type: String) {
        let mut items = self.items.write().await;
        if items.len() >= self.max_items {
            let _ = items.pop_front();
        }
        items.push_back(alert_type);
    }
}

/// Arabic: الحالة المشتركة للتطبيق (تُستخدم من API والخادم)
/// English: Shared application state (used by API and the server)
pub struct AppState {
    pub x_engine: Arc<CrossValidationEngine>,
    pub composite_verifier: Arc<CompositeVerifier>,
    pub weather_engine: Arc<WeatherEngine>,
    pub jwt_manager: Arc<JwtManager>,
    pub rate_limiter: Arc<RateLimiter>,
    pub ai_guard: Arc<RequestAiGuard>,
    pub api_key: Option<SecureString>,
    pub alert_memory: Arc<AlertMemoryStore>,
    pub db_pool: Option<DbPool>,
}
