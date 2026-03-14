use crate::core::composite_verification::CompositeVerifier;
use crate::core::cross_location::CrossValidationEngine;
use std::sync::Arc;

#[cfg(feature = "db-mysql")]
compile_error!(
    "Feature 'db-mysql' is temporarily disabled for security hardening until a non-vulnerable backend is integrated."
);

pub struct DbPool;

/// Arabic: الحالة المشتركة للتطبيق (تُستخدم من API والخادم)
/// English: Shared application state (used by API and the server)
pub struct AppState {
    pub x_engine: Arc<CrossValidationEngine>,
    pub composite_verifier: Arc<CompositeVerifier>,
    pub db_pool: Option<DbPool>,
}
