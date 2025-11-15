#[cfg(feature = "core_full")]
use crate::core::cross_location::CrossValidationEngine;
#[cfg(feature = "db_mysql")]
use mysql_async::Pool;
use std::sync::Arc;

/// Arabic: الحالة المشتركة للتطبيق (تُستخدم من API والخادم)
/// English: Shared application state (used by API and the server)
pub struct AppState {
    #[cfg(feature = "core_full")]
    pub x_engine: Arc<CrossValidationEngine>,
    #[cfg(feature = "db_mysql")]
    pub db_pool: Option<Pool>,
}
