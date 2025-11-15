/*!
نظام OAuth2 كامل من الصفر - بدون تبعيات خارجية
Complete OAuth2 system from scratch - zero external dependencies

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)

🎯 الميزات الرئيسية / Key Features:
- OAuth2 RFC 6749 compliant
- OpenID Connect support
- AI-driven security adaptation
- Zero external dependencies
- Per-client adaptive security
- Geographic-aware authentication
- Behavioral pattern analysis
- Real-time threat detection
*/

pub mod adaptive;
pub mod ai;
pub mod clients;
pub mod core;
pub mod endpoints;
pub mod flows;
pub mod grants;
pub mod guards_oauth2;
pub mod introspection;
pub mod security;
pub mod tokens;
pub mod userinfo;

// Re-export main types for easy access
pub use adaptive::*;
pub use ai::*;
pub use clients::*;
pub use core::*;
pub use grants::*;
pub use security::*;
pub use tokens::*;

/// Arabic: إصدار OAuth2 المطبق
/// English: Implemented OAuth2 version
pub const OAUTH2_VERSION: &str = "2.0";

/// Arabic: إصدار OpenID Connect المطبق  
/// English: Implemented OpenID Connect version
pub const OIDC_VERSION: &str = "1.0";

/// Arabic: معرف النظام الأساسي
/// English: System identifier
pub const SYSTEM_ISSUER: &str = "mkt-ksa-geolocation-security";

/// Arabic: المجال الافتراضي للجمهور
/// English: Default audience domain
pub const DEFAULT_AUDIENCE: &str = "mkt-ksa-api";

/// Arabic: أقصى عمر للرمز المصدق (Authorization Code)
/// English: Maximum authorization code lifetime
pub const MAX_AUTH_CODE_LIFETIME_SEC: u64 = 600; // 10 minutes

/// Arabic: أقصى عمر للرمز المحدود (Access Token)
/// English: Maximum access token lifetime
pub const MAX_ACCESS_TOKEN_LIFETIME_SEC: u64 = 3600; // 1 hour

/// Arabic: أقصى عمر للرمز المنعش (Refresh Token)
/// English: Maximum refresh token lifetime
pub const MAX_REFRESH_TOKEN_LIFETIME_SEC: u64 = 86400 * 30; // 30 days

/// Arabic: أقصى عمر للرمز المعرف (ID Token)
/// English: Maximum ID token lifetime
pub const MAX_ID_TOKEN_LIFETIME_SEC: u64 = 3600; // 1 hour

/// Arabic: الحد الأدنى لطول مفتاح العميل
/// English: Minimum client secret length
pub const MIN_CLIENT_SECRET_LENGTH: usize = 32;

/// Arabic: الحد الأقصى لعدد محاولات المصادقة الفاشلة
/// English: Maximum failed authentication attempts
pub const MAX_AUTH_ATTEMPTS: u32 = 5;

/// Arabic: فترة حظر الحساب بعد محاولات فاشلة (بالثواني)
/// English: Account lockout duration after failed attempts (seconds)
pub const ACCOUNT_LOCKOUT_DURATION_SEC: u64 = 900; // 15 minutes
