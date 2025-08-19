use crate::core::cross_location::CrossValidationEngine;
use mysql_async::Pool;
use std::sync::Arc;

/// Arabic: الحالة المشتركة للتطبيق (تُستخدم من API والخادم)
/// English: Shared application state (used by API and the server)
pub struct AppState {
    pub x_engine: Arc<CrossValidationEngine>,
    pub db_pool: Option<Pool>,
}


