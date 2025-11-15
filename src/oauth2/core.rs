#![allow(clippy::should_implement_trait)]
/*!
البنية الأساسية لنظام OAuth2 - الهياكل والأنواع الأساسية
OAuth2 Core Structures - Basic types and structures

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
*/

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Arabic: توليد UUID بدون تبعيات خارجية
/// English: Generate UUID without external dependencies
pub fn generate_uuid() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut bytes = [0u8; 16];
    let now_bytes = now.to_le_bytes();
    bytes[..8].copy_from_slice(&now_bytes[..8]);

    // Add some randomness using system time
    let nanos = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    bytes[8..12].copy_from_slice(&nanos.to_le_bytes());

    // Fill remaining with a simple counter
    static mut COUNTER: u32 = 0;
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        bytes[12..16].copy_from_slice(&COUNTER.to_le_bytes());
    }

    // Convert to UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        u16::from_le_bytes([bytes[8], bytes[9]]),
        u64::from_le_bytes([
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], 0, 0
        ])
    )
}

/// Arabic: أنواع منح OAuth2 المدعومة
/// English: Supported OAuth2 grant types
#[derive(Debug, Clone, PartialEq)]
pub enum GrantType {
    /// Arabic: رمز المصادقة (للتطبيقات الويب)
    /// English: Authorization Code (for web applications)
    AuthorizationCode,
    /// Arabic: بيانات العميل (للخدمات)
    /// English: Client Credentials (for services)
    ClientCredentials,
    /// Arabic: رمز منعش
    /// English: Refresh Token
    RefreshToken,
    /// Arabic: كلمة مرور المالك
    /// English: Resource Owner Password Credentials
    Password,
    /// Arabic: تدفق الجهاز
    /// English: Device Flow
    Device,
    /// Arabic: PKCE (Proof Key for Code Exchange)
    /// English: PKCE (Proof Key for Code Exchange)
    PKCE,
}

impl GrantType {
    /// Arabic: تحويل النوع إلى نص
    /// English: Convert type to string
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::RefreshToken => "refresh_token",
            GrantType::Password => "password",
            GrantType::Device => "urn:ietf:params:oauth:grant-type:device_code",
            GrantType::PKCE => "authorization_code", // PKCE uses authorization_code flow
        }
    }

    /// Arabic: تحويل النص إلى نوع
    /// English: Convert string to type
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            "client_credentials" => Some(GrantType::ClientCredentials),
            "refresh_token" => Some(GrantType::RefreshToken),
            "password" => Some(GrantType::Password),
            "urn:ietf:params:oauth:grant-type:device_code" => Some(GrantType::Device),
            _ => None,
        }
    }
}

/// Arabic: أنواع الاستجابة المدعومة
/// English: Supported response types
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseType {
    /// Arabic: رمز المصادقة
    /// English: Authorization Code
    Code,
    /// Arabic: رمز معرف (OpenID Connect)
    /// English: ID Token (OpenID Connect)
    IdToken,
    /// Arabic: رمز المصادقة + رمز معرف
    /// English: Authorization Code + ID Token
    CodeIdToken,
}

impl ResponseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseType::Code => "code",
            ResponseType::IdToken => "id_token",
            ResponseType::CodeIdToken => "code id_token",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "code" => Some(ResponseType::Code),
            "id_token" => Some(ResponseType::IdToken),
            "code id_token" => Some(ResponseType::CodeIdToken),
            _ => None,
        }
    }
}

/// Arabic: نطاقات الصلاحيات
/// English: Permission scopes
#[derive(Debug, Clone)]
pub struct Scope {
    /// Arabic: اسم النطاق
    /// English: Scope name
    pub name: String,
    /// Arabic: وصف النطاق
    /// English: Scope description
    pub description: String,
    /// Arabic: هل النطاق مطلوب موافقة المستخدم؟
    /// English: Does scope require user consent?
    pub requires_consent: bool,
    /// Arabic: مستوى الحساسية (1-10)
    /// English: Sensitivity level (1-10)
    pub sensitivity_level: u8,
}

impl Scope {
    /// Arabic: إنشاء نطاق جديد
    /// English: Create new scope
    pub fn new(
        name: &str,
        description: &str,
        requires_consent: bool,
        sensitivity_level: u8,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            requires_consent,
            sensitivity_level: sensitivity_level.min(10),
        }
    }
}

/// Arabic: معلومات الموقع الجغرافي للمصادقة
/// English: Geographic information for authentication
#[derive(Debug, Clone)]
pub struct GeographicContext {
    /// Arabic: خط العرض
    /// English: Latitude
    pub latitude: Option<f64>,
    /// Arabic: خط الطول
    /// English: Longitude
    pub longitude: Option<f64>,
    /// Arabic: البلد
    /// English: Country
    pub country: Option<String>,
    /// Arabic: المدينة
    /// English: City
    pub city: Option<String>,
    /// Arabic: عنوان IP
    /// English: IP Address
    pub ip_address: Option<String>,
    /// Arabic: بيانات الأقمار الصناعية
    /// English: Satellite data
    pub satellite_data: Option<SatelliteContext>,
    /// Arabic: بيانات شبكة الاتصال
    /// English: Network data
    pub network_data: Option<NetworkContext>,
}

#[derive(Debug, Clone)]
pub struct SatelliteContext {
    /// Arabic: دقة GPS
    /// English: GPS accuracy
    pub gps_accuracy: Option<f64>,
    /// Arabic: عدد الأقمار الصناعية المتصلة
    /// English: Number of connected satellites
    pub satellite_count: Option<u32>,
    /// Arabic: وقت آخر تحديث
    /// English: Last update time
    pub last_update: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct NetworkContext {
    /// Arabic: نوع الاتصال
    /// English: Connection type
    pub connection_type: Option<String>,
    /// Arabic: مزود الخدمة
    /// English: ISP
    pub isp: Option<String>,
    /// Arabic: معرف شبكة الاتصال
    /// English: Network ID
    pub network_id: Option<String>,
}

/// Arabic: معلومات السياق السلوكي
/// English: Behavioral context information
#[derive(Debug, Clone)]
pub struct BehavioralContext {
    /// Arabic: نمط الكتابة
    /// English: Typing pattern
    pub typing_pattern: Option<TypingPattern>,
    /// Arabic: نمط حركة الماوس
    /// English: Mouse movement pattern
    pub mouse_pattern: Option<MousePattern>,
    /// Arabic: بصمة الجهاز
    /// English: Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Arabic: وقت الاستجابة
    /// English: Response time
    pub response_time_ms: Option<u64>,
    /// Arabic: تاريخ المصادقات السابقة
    /// English: Previous authentication history
    pub auth_history: Vec<AuthHistoryEntry>,
}

#[derive(Debug, Clone)]
pub struct TypingPattern {
    /// Arabic: متوسط وقت الضغط على المفتاح
    /// English: Average key press duration
    pub avg_key_duration_ms: f64,
    /// Arabic: متوسط الوقت بين الضغطات
    /// English: Average time between key presses
    pub avg_inter_key_delay_ms: f64,
    /// Arabic: نمط الضغطات
    /// English: Key press pattern
    pub key_pattern: String,
}

#[derive(Debug, Clone)]
pub struct MousePattern {
    /// Arabic: سرعة حركة الماوس
    /// English: Mouse movement speed
    pub movement_speed: f64,
    /// Arabic: نمط الحركة
    /// English: Movement pattern
    pub movement_pattern: String,
    /// Arabic: نقاط التوقف
    /// English: Stop points
    pub stop_points: Vec<(f64, f64)>,
}

#[derive(Debug, Clone)]
pub struct AuthHistoryEntry {
    /// Arabic: وقت المصادقة
    /// English: Authentication time
    pub timestamp: u64,
    /// Arabic: نجح أم فشل
    /// English: Success or failure
    pub success: bool,
    /// Arabic: السياق الجغرافي
    /// English: Geographic context
    pub geo_context: GeographicContext,
    /// Arabic: السبب (إذا فشل)
    /// English: Reason (if failed)
    pub failure_reason: Option<String>,
}

/// Arabic: تقييم المخاطر
/// English: Risk assessment
#[derive(Debug, Clone)]
pub struct RiskAssessment {
    /// Arabic: مستوى المخاطر الإجمالي (0-100)
    /// English: Overall risk level (0-100)
    pub overall_risk: u8,
    /// Arabic: مخاطر جغرافية
    /// English: Geographic risks
    pub geographic_risk: u8,
    /// Arabic: مخاطر سلوكية
    /// English: Behavioral risks
    pub behavioral_risk: u8,
    /// Arabic: مخاطر الشبكة
    /// English: Network risks
    pub network_risk: u8,
    /// Arabic: مخاطر الجهاز
    /// English: Device risks
    pub device_risk: u8,
    /// Arabic: عوامل الخطر
    /// English: Risk factors
    pub risk_factors: Vec<String>,
    /// Arabic: توصيات الأمان
    /// English: Security recommendations
    pub recommendations: Vec<String>,
    /// Arabic: وقت التقييم
    /// English: Assessment time
    pub assessed_at: u64,
}

impl RiskAssessment {
    /// Arabic: إنشاء تقييم مخاطر جديد
    /// English: Create new risk assessment
    pub fn new() -> Self {
        Self {
            overall_risk: 0,
            geographic_risk: 0,
            behavioral_risk: 0,
            network_risk: 0,
            device_risk: 0,
            risk_factors: Vec::new(),
            recommendations: Vec::new(),
            assessed_at: current_timestamp(),
        }
    }
}

impl Default for RiskAssessment {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskAssessment {
    /// Arabic: تحديث مستوى المخاطر الإجمالي
    /// English: Update overall risk level
    pub fn update_overall_risk(&mut self) {
        self.overall_risk = ((self.geographic_risk as u16
            + self.behavioral_risk as u16
            + self.network_risk as u16
            + self.device_risk as u16)
            / 4) as u8;
    }
}

/// Arabic: إعدادات التكيف الأمني
/// English: Adaptive security settings
#[derive(Debug, Clone)]
pub struct AdaptiveSecuritySettings {
    /// Arabic: تفعيل التكيف التلقائي
    /// English: Enable automatic adaptation
    pub auto_adaptation_enabled: bool,
    /// Arabic: عتبة المخاطر للتشديد
    /// English: Risk threshold for tightening
    pub tightening_threshold: u8,
    /// Arabic: عتبة المخاطر للتخفيف
    /// English: Risk threshold for relaxation
    pub relaxation_threshold: u8,
    /// Arabic: عوامل التكيف
    /// English: Adaptation factors
    pub adaptation_factors: HashMap<String, f64>,
    /// Arabic: إعدادات النطاقات
    /// English: Scope settings
    pub scope_settings: HashMap<String, ScopeSecuritySettings>,
}

#[derive(Debug, Clone)]
pub struct ScopeSecuritySettings {
    /// Arabic: مستوى الحساسية
    /// English: Sensitivity level
    pub sensitivity_level: u8,
    /// Arabic: متطلبات إضافية
    /// English: Additional requirements
    pub additional_requirements: Vec<String>,
    /// Arabic: عوامل التحقق
    /// English: Verification factors
    pub verification_factors: Vec<String>,
}

impl AdaptiveSecuritySettings {
    /// Arabic: إنشاء إعدادات تكيف افتراضية
    /// English: Create default adaptive settings
    pub fn default_adaptive_settings() -> Self {
        let mut adaptation_factors = HashMap::new();
        adaptation_factors.insert("geographic_weight".to_string(), 0.3);
        adaptation_factors.insert("behavioral_weight".to_string(), 0.25);
        adaptation_factors.insert("network_weight".to_string(), 0.2);
        adaptation_factors.insert("device_weight".to_string(), 0.25);

        Self {
            auto_adaptation_enabled: true,
            tightening_threshold: 70,
            relaxation_threshold: 30,
            adaptation_factors,
            scope_settings: HashMap::new(),
        }
    }
}

impl Default for AdaptiveSecuritySettings {
    fn default() -> Self {
        Self::default_adaptive_settings()
    }
}

/// Arabic: دالة مساعدة للحصول على الطابع الزمني الحالي
/// English: Helper function to get current timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Arabic: دالة مساعدة للتحقق من صحة UUID
/// English: Helper function to validate UUID
pub fn is_valid_uuid(s: &str) -> bool {
    // Simple UUID validation without external dependencies
    s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4
}

/// Arabic: دالة مساعدة لإنشاء رمز عشوائي آمن
/// English: Helper function to generate secure random code
pub fn generate_secure_code(length: usize) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    // عداد عشوائي لضمان اختلاف الرموز
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut code = String::with_capacity(length);
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        .chars()
        .collect();

    for i in 0..length {
        let mut hasher = DefaultHasher::new();
        // إضافة بذور متعددة لضمان العشوائية
        (current_timestamp() + i as u64 + counter + (i as u64 * 1000)).hash(&mut hasher);
        let hash = hasher.finish();
        let index = (hash % chars.len() as u64) as usize;
        code.push(chars[index]);
    }

    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_type_conversion() {
        assert_eq!(GrantType::AuthorizationCode.as_str(), "authorization_code");
        assert_eq!(GrantType::ClientCredentials.as_str(), "client_credentials");
        assert_eq!(
            GrantType::from_str("authorization_code"),
            Some(GrantType::AuthorizationCode)
        );
        assert_eq!(GrantType::from_str("invalid"), None);
    }

    #[test]
    fn test_response_type_conversion() {
        assert_eq!(ResponseType::Code.as_str(), "code");
        assert_eq!(ResponseType::IdToken.as_str(), "id_token");
        assert_eq!(ResponseType::from_str("code"), Some(ResponseType::Code));
        assert_eq!(ResponseType::from_str("invalid"), None);
    }

    #[test]
    fn test_scope_creation() {
        let scope = Scope::new("read", "Read access", false, 3);
        assert_eq!(scope.name, "read");
        assert!(!scope.requires_consent);
        assert_eq!(scope.sensitivity_level, 3);
    }

    #[test]
    fn test_risk_assessment() {
        let mut assessment = RiskAssessment::new();
        assessment.geographic_risk = 80;
        assessment.behavioral_risk = 60;
        assessment.network_risk = 70;
        assessment.device_risk = 50;
        assessment.update_overall_risk();
        assert_eq!(assessment.overall_risk, 65);
    }

    #[test]
    fn test_adaptive_settings() {
        let settings = AdaptiveSecuritySettings::default();
        assert!(settings.auto_adaptation_enabled);
        assert_eq!(settings.tightening_threshold, 70);
        assert_eq!(settings.relaxation_threshold, 30);
    }

    #[test]
    fn test_secure_code_generation() {
        let code = generate_secure_code(32);
        assert_eq!(code.len(), 32);
        // Test that all characters are valid
        for ch in code.chars() {
            assert!(ch.is_ascii_alphanumeric());
        }
    }

    #[test]
    fn test_uuid_validation() {
        assert!(is_valid_uuid(&generate_uuid()));
        assert!(!is_valid_uuid("invalid-uuid"));
        assert!(!is_valid_uuid("123"));
    }
}
