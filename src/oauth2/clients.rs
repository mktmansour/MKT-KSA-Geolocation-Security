/*!
إدارة العملاء في نظام OAuth2 - تسجيل وتوثيق العملاء
OAuth2 Client Management - Client registration and authentication

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)

🔐 ميزات إدارة العملاء / Client Management Features:
- Dynamic client registration
- Client authentication methods
- Scope-based authorization
- Client security policies
- Rate limiting per client
- Geographic restrictions
- Behavioral analysis integration
*/

use crate::oauth2::core::*;
use crate::security::secret::SecureBytes;
// Removed serde dependency
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Arabic: نوع العميل
/// English: Client type
#[derive(Debug, Clone, PartialEq)]
pub enum ClientType {
    /// Arabic: تطبيق ويب (سر)
    /// English: Web application (confidential)
    Web,
    /// Arabic: تطبيق محمول (عام)
    /// English: Mobile application (public)
    Mobile,
    /// Arabic: تطبيق سطح المكتب
    /// English: Desktop application
    Desktop,
    /// Arabic: خدمة (Server-to-Server)
    /// English: Service (Server-to-Server)
    Service,
    /// Arabic: جهاز (IoT)
    /// English: Device (IoT)
    Device,
    /// Arabic: تطبيق صفحة واحدة (SPA)
    /// English: Single Page Application (SPA)
    SPA,
}

impl ClientType {
    /// Arabic: هل العميل سري؟
    /// English: Is client confidential?
    pub fn is_confidential(&self) -> bool {
        matches!(self, ClientType::Web | ClientType::Service)
    }

    /// Arabic: هل العميل عام؟
    /// English: Is client public?
    pub fn is_public(&self) -> bool {
        matches!(
            self,
            ClientType::Mobile | ClientType::Desktop | ClientType::Device | ClientType::SPA
        )
    }

    /// Arabic: تحويل إلى نص
    /// English: Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientType::Web => "web",
            ClientType::Mobile => "mobile",
            ClientType::Desktop => "desktop",
            ClientType::Service => "service",
            ClientType::Device => "device",
            ClientType::SPA => "spa",
        }
    }
}

/// Arabic: طريقة مصادقة العميل
/// English: Client authentication method
#[derive(Debug, Clone, PartialEq)]
pub enum ClientAuthMethod {
    /// Arabic: مفتاح سري
    /// English: Client secret
    ClientSecret,
    /// Arabic: شهادة العميل
    /// English: Client certificate
    ClientCertificate,
    /// Arabic: مصادقة خاصة
    /// English: Private key authentication
    PrivateKey,
    /// Arabic: بدون مصادقة (للعملاء العامين)
    /// English: No authentication (for public clients)
    None,
}

impl ClientAuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientAuthMethod::ClientSecret => "client_secret_basic",
            ClientAuthMethod::ClientCertificate => "tls_client_auth",
            ClientAuthMethod::PrivateKey => "private_key_jwt",
            ClientAuthMethod::None => "none",
        }
    }
}

/// Arabic: سياسة أمان العميل
/// English: Client security policy
#[derive(Debug, Clone)]
pub struct ClientSecurityPolicy {
    /// Arabic: الحد الأقصى لعدد الطلبات في الدقيقة
    /// English: Maximum requests per minute
    pub max_requests_per_minute: u32,
    /// Arabic: الحد الأقصى لعدد الطلبات في الساعة
    /// English: Maximum requests per hour
    pub max_requests_per_hour: u32,
    /// Arabic: الحد الأقصى لحجم الطلب
    /// English: Maximum request size
    pub max_request_size: usize,
    /// Arabic: نطاقات مسموحة
    /// English: Allowed scopes
    pub allowed_scopes: Vec<String>,
    /// Arabic: نطاقات محظورة
    /// English: Denied scopes
    pub denied_scopes: Vec<String>,
    /// Arabic: طرق منح مسموحة
    /// English: Allowed grant types
    pub allowed_grant_types: Vec<GrantType>,
    /// Arabic: طرق استجابة مسموحة
    /// English: Allowed response types
    pub allowed_response_types: Vec<ResponseType>,
    /// Arabic: عناوين URL مسموحة للاسترداد
    /// English: Allowed redirect URIs
    pub allowed_redirect_uris: Vec<String>,
    /// Arabic: قيود جغرافية
    /// English: Geographic restrictions
    pub geographic_restrictions: GeographicRestrictions,
    /// Arabic: متطلبات التحقق الإضافية
    /// English: Additional verification requirements
    pub verification_requirements: Vec<String>,
    /// Arabic: تفعيل مراقبة السلوك
    /// English: Enable behavioral monitoring
    pub enable_behavioral_monitoring: bool,
    /// Arabic: تفعيل التحليل الجغرافي
    /// English: Enable geographic analysis
    pub enable_geographic_analysis: bool,
}

#[derive(Debug, Clone)]
pub struct GeographicRestrictions {
    /// Arabic: البلدان المسموحة
    /// English: Allowed countries
    pub allowed_countries: Vec<String>,
    /// Arabic: البلدان المحظورة
    /// English: Denied countries
    pub denied_countries: Vec<String>,
    /// Arabic: المدن المسموحة
    /// English: Allowed cities
    pub allowed_cities: Vec<String>,
    /// Arabic: المدن المحظورة
    /// English: Denied cities
    pub denied_cities: Vec<String>,
    /// Arabic: نطاقات IP مسموحة
    /// English: Allowed IP ranges
    pub allowed_ip_ranges: Vec<String>,
    /// Arabic: نطاقات IP محظورة
    /// English: Denied IP ranges
    pub denied_ip_ranges: Vec<String>,
}

impl ClientSecurityPolicy {
    /// Arabic: إنشاء سياسة أمان افتراضية
    /// English: Create default security policy
    pub fn default_security_policy() -> Self {
        Self {
            max_requests_per_minute: 100,
            max_requests_per_hour: 1000,
            max_request_size: 1024 * 1024, // 1MB
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
            denied_scopes: Vec::new(),
            allowed_grant_types: vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
            allowed_response_types: vec![ResponseType::Code],
            allowed_redirect_uris: Vec::new(),
            geographic_restrictions: GeographicRestrictions::default_geographic_restrictions(),
            verification_requirements: Vec::new(),
            enable_behavioral_monitoring: true,
            enable_geographic_analysis: true,
        }
    }
}

impl Default for ClientSecurityPolicy {
    fn default() -> Self {
        Self::default_security_policy()
    }
}

impl ClientSecurityPolicy {
    /// Arabic: إنشاء سياسة أمان صارمة
    /// English: Create strict security policy
    pub fn strict() -> Self {
        Self {
            max_requests_per_minute: 20,
            max_requests_per_hour: 200,
            max_request_size: 512 * 1024, // 512KB
            allowed_scopes: vec!["read".to_string()],
            denied_scopes: vec!["admin".to_string(), "system".to_string()],
            allowed_grant_types: vec![GrantType::AuthorizationCode],
            allowed_response_types: vec![ResponseType::Code],
            allowed_redirect_uris: Vec::new(),
            geographic_restrictions: GeographicRestrictions::strict(),
            verification_requirements: vec!["multi_factor".to_string()],
            enable_behavioral_monitoring: true,
            enable_geographic_analysis: true,
        }
    }

    /// Arabic: التحقق من صحة النطاق
    /// English: Validate scope
    pub fn is_scope_allowed(&self, scope: &str) -> bool {
        if self.denied_scopes.contains(&scope.to_string()) {
            return false;
        }
        self.allowed_scopes.contains(&scope.to_string())
    }

    /// Arabic: التحقق من صحة طريقة المنح
    /// English: Validate grant type
    pub fn is_grant_type_allowed(&self, grant_type: &GrantType) -> bool {
        self.allowed_grant_types.contains(grant_type)
    }

    /// Arabic: التحقق من صحة نوع الاستجابة
    /// English: Validate response type
    pub fn is_response_type_allowed(&self, response_type: &ResponseType) -> bool {
        self.allowed_response_types.contains(response_type)
    }

    /// Arabic: التحقق من صحة عنوان URL للاسترداد
    /// English: Validate redirect URI
    pub fn is_redirect_uri_allowed(&self, uri: &str) -> bool {
        if self.allowed_redirect_uris.is_empty() {
            return true; // لا توجد قيود
        }
        self.allowed_redirect_uris
            .iter()
            .any(|allowed| uri.starts_with(allowed))
    }
}

impl GeographicRestrictions {
    pub fn default_geographic_restrictions() -> Self {
        Self {
            allowed_countries: Vec::new(),
            denied_countries: Vec::new(),
            allowed_cities: Vec::new(),
            denied_cities: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
        }
    }
}

impl Default for GeographicRestrictions {
    fn default() -> Self {
        Self::default_geographic_restrictions()
    }
}

impl GeographicRestrictions {
    pub fn strict() -> Self {
        Self {
            allowed_countries: vec!["SA".to_string()], // السعودية فقط
            denied_countries: Vec::new(),
            allowed_cities: vec![
                "Riyadh".to_string(),
                "Jeddah".to_string(),
                "Dammam".to_string(),
            ],
            denied_cities: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
        }
    }

    /// Arabic: التحقق من القيود الجغرافية
    /// English: Check geographic restrictions
    pub fn is_location_allowed(&self, context: &GeographicContext) -> bool {
        // فحص البلد
        if let Some(country) = &context.country {
            if !self.allowed_countries.is_empty() && !self.allowed_countries.contains(country) {
                return false;
            }
            if self.denied_countries.contains(country) {
                return false;
            }
        }

        // فحص المدينة
        if let Some(city) = &context.city {
            if !self.allowed_cities.is_empty() && !self.allowed_cities.contains(city) {
                return false;
            }
            if self.denied_cities.contains(city) {
                return false;
            }
        }

        // فحص عنوان IP
        if let Some(ip) = &context.ip_address {
            for denied_range in &self.denied_ip_ranges {
                if self.is_ip_in_range(ip, denied_range) {
                    return false;
                }
            }
            if !self.allowed_ip_ranges.is_empty() {
                let is_allowed = self
                    .allowed_ip_ranges
                    .iter()
                    .any(|allowed_range| self.is_ip_in_range(ip, allowed_range));
                if !is_allowed {
                    return false;
                }
            }
        }

        true
    }

    /// Arabic: التحقق من وجود IP في نطاق
    /// English: Check if IP is in range
    fn is_ip_in_range(&self, ip: &str, range: &str) -> bool {
        // تحليل بسيط للنطاقات (يمكن تحسينه لاحقاً)
        if range.contains('/') {
            // CIDR notation
            self.is_ip_in_cidr(ip, range)
        } else if range.contains('-') {
            // IP range
            self.is_ip_in_range_format(ip, range)
        } else {
            // Single IP
            ip == range
        }
    }

    fn is_ip_in_cidr(&self, _ip: &str, _cidr: &str) -> bool {
        // TODO: تنفيذ تحليل CIDR كامل
        false
    }

    fn is_ip_in_range_format(&self, _ip: &str, _range: &str) -> bool {
        // TODO: تنفيذ تحليل نطاق IP كامل
        false
    }
}

/// Arabic: معلومات العميل المسجل
/// English: Registered client information
#[derive(Debug, Clone)]
pub struct Client {
    /// Arabic: معرف العميل
    /// English: Client ID
    pub client_id: String,
    /// Arabic: اسم العميل
    /// English: Client name
    pub client_name: String,
    /// Arabic: نوع العميل
    /// English: Client type
    pub client_type: ClientType,
    /// Arabic: مفتاح العميل السري
    /// English: Client secret
    pub client_secret: Option<SecureBytes>,
    /// Arabic: طريقة مصادقة العميل
    /// English: Client authentication method
    pub auth_method: ClientAuthMethod,
    /// Arabic: سياسة الأمان
    /// English: Security policy
    pub security_policy: ClientSecurityPolicy,
    /// Arabic: تاريخ التسجيل
    /// English: Registration date
    pub registered_at: u64,
    /// Arabic: آخر تحديث
    /// English: Last updated
    pub last_updated: u64,
    /// Arabic: حالة العميل (نشط/معطل)
    /// English: Client status (active/disabled)
    pub is_active: bool,
    /// Arabic: تاريخ آخر نشاط
    /// English: Last activity date
    pub last_activity: Option<u64>,
    /// Arabic: عدد الطلبات في الدقيقة الحالية
    /// English: Current minute request count
    pub current_minute_requests: u32,
    /// Arabic: عدد الطلبات في الساعة الحالية
    /// English: Current hour request count
    pub current_hour_requests: u32,
    /// Arabic: آخر إعادة تعيين للعدادات
    /// English: Last counter reset
    pub last_counter_reset: u64,
}

impl Client {
    /// Arabic: إنشاء عميل جديد
    /// English: Create new client
    pub fn new(
        client_id: String,
        client_name: String,
        client_type: ClientType,
        auth_method: ClientAuthMethod,
    ) -> Self {
        let now = current_timestamp();

        Self {
            client_id,
            client_name,
            client_type,
            client_secret: if auth_method == ClientAuthMethod::ClientSecret {
                Some(SecureBytes::new(
                    generate_secure_code(64).as_bytes().to_vec(),
                ))
            } else {
                None
            },
            auth_method,
            security_policy: ClientSecurityPolicy::default(),
            registered_at: now,
            last_updated: now,
            is_active: true,
            last_activity: None,
            current_minute_requests: 0,
            current_hour_requests: 0,
            last_counter_reset: now,
        }
    }

    /// Arabic: التحقق من صحة العميل
    /// English: Validate client
    pub fn validate(&self, secret: Option<&str>) -> Result<(), ClientValidationError> {
        if !self.is_active {
            return Err(ClientValidationError::ClientDisabled);
        }

        if let Some(provided_secret) = secret {
            if let Some(client_secret) = &self.client_secret {
                if provided_secret.as_bytes() != client_secret.expose() {
                    return Err(ClientValidationError::InvalidSecret);
                }
            }
        }

        Ok(())
    }

    /// Arabic: تحديث نشاط العميل
    /// English: Update client activity
    pub fn update_activity(&mut self) {
        let now = current_timestamp();
        self.last_activity = Some(now);

        // إعادة تعيين العدادات إذا مرت دقيقة أو ساعة
        if now - self.last_counter_reset >= 60 {
            self.current_minute_requests = 0;
            if now - self.last_counter_reset >= 3600 {
                self.current_hour_requests = 0;
                self.last_counter_reset = now;
            }
        }
    }

    /// Arabic: تسجيل طلب جديد
    /// English: Record new request
    pub fn record_request(&mut self) -> Result<(), ClientValidationError> {
        self.update_activity();

        self.current_minute_requests += 1;
        self.current_hour_requests += 1;

        // فحص حدود المعدل
        if self.current_minute_requests > self.security_policy.max_requests_per_minute {
            return Err(ClientValidationError::RateLimitExceeded);
        }

        if self.current_hour_requests > self.security_policy.max_requests_per_hour {
            return Err(ClientValidationError::RateLimitExceeded);
        }

        Ok(())
    }

    /// Arabic: التحقق من صحة النطاق
    /// English: Validate scope
    pub fn validate_scope(&self, scope: &str) -> Result<(), ClientValidationError> {
        if !self.security_policy.is_scope_allowed(scope) {
            return Err(ClientValidationError::ScopeNotAllowed);
        }
        Ok(())
    }

    /// Arabic: التحقق من صحة طريقة المنح
    /// English: Validate grant type
    pub fn validate_grant_type(&self, grant_type: &GrantType) -> Result<(), ClientValidationError> {
        if !self.security_policy.is_grant_type_allowed(grant_type) {
            return Err(ClientValidationError::GrantTypeNotAllowed);
        }
        Ok(())
    }
}

/// Arabic: أخطاء التحقق من العميل
/// English: Client validation errors
#[derive(Debug, Clone)]
pub enum ClientValidationError {
    /// Arabic: العميل غير موجود
    /// English: Client not found
    ClientNotFound,
    /// Arabic: العميل معطل
    /// English: Client disabled
    ClientDisabled,
    /// Arabic: مفتاح سري غير صحيح
    /// English: Invalid secret
    InvalidSecret,
    /// Arabic: النطاق غير مسموح
    /// English: Scope not allowed
    ScopeNotAllowed,
    /// Arabic: طريقة المنح غير مسموحة
    /// English: Grant type not allowed
    GrantTypeNotAllowed,
    /// Arabic: تجاوز حد المعدل
    /// English: Rate limit exceeded
    RateLimitExceeded,
    /// Arabic: القيود الجغرافية
    /// English: Geographic restrictions
    GeographicRestriction,
}

impl ClientValidationError {
    pub fn message(&self) -> &'static str {
        match self {
            ClientValidationError::ClientNotFound => "Client not found",
            ClientValidationError::ClientDisabled => "Client is disabled",
            ClientValidationError::InvalidSecret => "Invalid client secret",
            ClientValidationError::ScopeNotAllowed => "Scope not allowed for this client",
            ClientValidationError::GrantTypeNotAllowed => "Grant type not allowed for this client",
            ClientValidationError::RateLimitExceeded => "Rate limit exceeded",
            ClientValidationError::GeographicRestriction => "Geographic restriction applied",
        }
    }
}

/// Arabic: مدير العملاء
/// English: Client manager
pub struct ClientManager {
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

impl ClientManager {
    /// Arabic: إنشاء مدير عملاء جديد
    /// English: Create new client manager
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for ClientManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientManager {
    /// Arabic: تسجيل عميل جديد
    /// English: Register new client
    pub fn register_client(
        &self,
        client_id: String,
        client_name: String,
        client_type: ClientType,
        auth_method: ClientAuthMethod,
    ) -> Result<Client, ClientValidationError> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        if clients.contains_key(&client_id) {
            return Err(ClientValidationError::ClientNotFound); // العميل موجود بالفعل
        }

        let client = Client::new(client_id.clone(), client_name, client_type, auth_method);
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    /// Arabic: الحصول على عميل
    /// English: Get client
    pub fn get_client(&self, client_id: &str) -> Option<Client> {
        let clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        clients.get(client_id).cloned()
    }

    /// Arabic: التحقق من صحة العميل
    /// English: Validate client
    pub fn validate_client(
        &self,
        client_id: &str,
        secret: Option<&str>,
    ) -> Result<Client, ClientValidationError> {
        let client = self
            .get_client(client_id)
            .ok_or(ClientValidationError::ClientNotFound)?;

        client.validate(secret)?;
        Ok(client)
    }

    /// Arabic: تحديث سياسة أمان العميل
    /// English: Update client security policy
    pub fn update_client_security_policy(
        &self,
        client_id: &str,
        policy: ClientSecurityPolicy,
    ) -> Result<(), ClientValidationError> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(client) = clients.get_mut(client_id) {
            client.security_policy = policy;
            client.last_updated = current_timestamp();
            Ok(())
        } else {
            Err(ClientValidationError::ClientNotFound)
        }
    }

    /// Arabic: تفعيل/تعطيل العميل
    /// English: Enable/disable client
    pub fn set_client_status(
        &self,
        client_id: &str,
        is_active: bool,
    ) -> Result<(), ClientValidationError> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(client) = clients.get_mut(client_id) {
            client.is_active = is_active;
            client.last_updated = current_timestamp();
            Ok(())
        } else {
            Err(ClientValidationError::ClientNotFound)
        }
    }

    /// Arabic: حذف العميل
    /// English: Delete client
    pub fn delete_client(&self, client_id: &str) -> Result<(), ClientValidationError> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        if clients.remove(client_id).is_some() {
            Ok(())
        } else {
            Err(ClientValidationError::ClientNotFound)
        }
    }

    /// Arabic: قائمة جميع العملاء
    /// English: List all clients
    pub fn list_clients(&self) -> Vec<Client> {
        let clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        clients.values().cloned().collect()
    }

    /// Arabic: البحث عن العملاء
    /// English: Search clients
    pub fn search_clients(&self, query: &str) -> Vec<Client> {
        let clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        clients
            .values()
            .filter(|client| client.client_id.contains(query) || client.client_name.contains(query))
            .cloned()
            .collect()
    }
}

// Global instance
static CLIENT_MANAGER: OnceLock<ClientManager> = OnceLock::new();

/// Arabic: الحصول على مدير العملاء العام
/// English: Get global client manager
pub fn get_client_manager() -> &'static ClientManager {
    CLIENT_MANAGER.get_or_init(ClientManager::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_type_classification() {
        assert!(ClientType::Web.is_confidential());
        assert!(ClientType::Service.is_confidential());
        assert!(ClientType::Mobile.is_public());
        assert!(ClientType::Desktop.is_public());
        assert!(ClientType::SPA.is_public());
    }

    #[test]
    fn test_client_creation() {
        let client = Client::new(
            "test_client".to_string(),
            "Test Client".to_string(),
            ClientType::Web,
            ClientAuthMethod::ClientSecret,
        );

        assert_eq!(client.client_id, "test_client");
        assert_eq!(client.client_name, "Test Client");
        assert_eq!(client.client_type, ClientType::Web);
        assert!(client.client_secret.is_some());
        assert!(client.is_active);
    }

    #[test]
    fn test_security_policy_validation() {
        let policy = ClientSecurityPolicy::default();

        assert!(policy.is_scope_allowed("read"));
        assert!(!policy.is_scope_allowed("admin"));

        assert!(policy.is_grant_type_allowed(&GrantType::AuthorizationCode));
        assert!(!policy.is_grant_type_allowed(&GrantType::Password));
    }

    #[test]
    fn test_client_manager() {
        let manager = ClientManager::new();

        let client = manager
            .register_client(
                "test_client".to_string(),
                "Test Client".to_string(),
                ClientType::Web,
                ClientAuthMethod::ClientSecret,
            )
            .unwrap();

        assert_eq!(client.client_id, "test_client");

        let retrieved = manager.get_client("test_client").unwrap();
        assert_eq!(retrieved.client_name, "Test Client");

        let validation = manager.validate_client("test_client", None);
        assert!(validation.is_ok());
    }

    #[test]
    fn test_rate_limiting() {
        let mut client = Client::new(
            "test_client".to_string(),
            "Test Client".to_string(),
            ClientType::Web,
            ClientAuthMethod::ClientSecret,
        );

        // تعيين حد منخفض للاختبار
        client.security_policy.max_requests_per_minute = 5;

        // تسجيل 5 طلبات (يجب أن تنجح)
        for _ in 0..5 {
            assert!(client.record_request().is_ok());
        }

        // الطلب السادس يجب أن يفشل
        assert!(client.record_request().is_err());
    }

    #[test]
    fn test_geographic_restrictions() {
        let restrictions = GeographicRestrictions::strict();

        let allowed_context = GeographicContext {
            country: Some("SA".to_string()),
            city: Some("Riyadh".to_string()),
            ..GeographicContext {
                latitude: None,
                longitude: None,
                country: None,
                city: None,
                ip_address: None,
                satellite_data: None,
                network_data: None,
            }
        };

        assert!(restrictions.is_location_allowed(&allowed_context));

        let denied_context = GeographicContext {
            country: Some("US".to_string()),
            ..allowed_context.clone()
        };

        assert!(!restrictions.is_location_allowed(&denied_context));
    }
}
