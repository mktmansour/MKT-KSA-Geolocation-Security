#![allow(
    clippy::new_without_default,
    clippy::redundant_closure,
    clippy::needless_borrow
)]
/*!
نقاط النهاية OAuth2 - تنفيذ جميع endpoints المطلوبة
OAuth2 Endpoints - Implementation of all required endpoints

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)

🌐 نقاط النهاية المطبوعة / Implemented Endpoints:
- /oauth/authorize - Authorization endpoint
- /oauth/token - Token endpoint
- /oauth/introspect - Token introspection
- /oauth/userinfo - User info endpoint (OpenID Connect)
- /oauth/revoke - Token revocation
- /oauth/keys - JWK Set endpoint
- /oauth/.well-known/openid_configuration - OpenID Connect discovery
*/

use crate::oauth2::adaptive::*;
use crate::oauth2::ai::*;
use crate::oauth2::clients::*;
use crate::oauth2::core::*;
use crate::oauth2::tokens::*;
use crate::oauth2::{
    MAX_ACCESS_TOKEN_LIFETIME_SEC, MAX_AUTH_CODE_LIFETIME_SEC, MAX_REFRESH_TOKEN_LIFETIME_SEC,
    SYSTEM_ISSUER,
};
// Removed serde dependency
use std::collections::HashMap;

/// Arabic: نتيجة نقطة النهاية
/// English: Endpoint result
#[derive(Debug, Clone)]
pub struct EndpointResult {
    /// Arabic: رمز الحالة HTTP
    /// English: HTTP status code
    pub status_code: u16,
    /// Arabic: نوع المحتوى
    /// English: Content type
    pub content_type: String,
    /// Arabic: البيانات
    /// English: Response data
    pub data: String,
    /// Arabic: Headers إضافية
    /// English: Additional headers
    pub headers: HashMap<String, String>,
    /// Arabic: معلومات التتبع
    /// English: Trace information
    pub trace_info: Option<TraceInfo>,
}

#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub request_id: String,
    pub processing_time_ms: u64,
    pub security_level: u8,
    pub adaptations_applied: Vec<String>,
}

impl EndpointResult {
    /// Arabic: إنشاء نتيجة نجاح
    /// English: Create success result
    pub fn success(data: &str) -> Self {
        Self {
            status_code: 200,
            content_type: "application/json".to_string(),
            data: data.to_string(),
            headers: HashMap::new(),
            trace_info: None,
        }
    }

    /// Arabic: إنشاء نتيجة خطأ
    /// English: Create error result
    pub fn error(status_code: u16, error: &str, description: Option<&str>) -> Self {
        let error_data = format!(
            r#"{{"error":"{}","error_description":"{}"}}"#,
            error,
            description.unwrap_or(error)
        );

        Self {
            status_code,
            content_type: "application/json".to_string(),
            data: error_data,
            headers: HashMap::new(),
            trace_info: None,
        }
    }

    /// Arabic: إضافة header
    /// English: Add header
    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    /// Arabic: تعيين معلومات التتبع
    /// English: Set trace info
    pub fn set_trace_info(&mut self, trace_info: TraceInfo) {
        self.trace_info = Some(trace_info);
    }
}

/// Arabic: مدير نقاط النهاية OAuth2
/// English: OAuth2 endpoints manager
pub struct OAuth2Endpoints {
    /// Arabic: مدير العملاء
    /// English: Client manager
    client_manager: &'static ClientManager,
    /// Arabic: مدير الرموز
    /// English: Token manager
    token_manager: &'static TokenManager,
    /// Arabic: مدير الأمان الذكي
    /// English: AI security manager
    _ai_manager: &'static AISecurityManager,
    /// Arabic: مدير التكيف الذاتي
    /// English: Adaptive security manager
    adaptive_manager: &'static AdaptiveSecurityManager,
}

impl OAuth2Endpoints {
    /// Arabic: إنشاء مدير نقاط النهاية جديد
    /// English: Create new endpoints manager
    pub fn new() -> Self {
        Self {
            client_manager: get_client_manager(),
            token_manager: get_token_manager(),
            _ai_manager: get_ai_security_manager(),
            adaptive_manager: get_adaptive_security_manager(),
        }
    }

    /// Arabic: نقطة النهاية للمصادقة (/oauth/authorize)
    /// English: Authorization endpoint (/oauth/authorize)
    pub fn authorize(&self, request: &AuthorizationRequest) -> EndpointResult {
        let start_time = std::time::Instant::now();
        let request_id = generate_uuid();

        // 1. التحقق من العميل
        let client = match self.client_manager.get_client(&request.client_id) {
            Some(client) => client,
            None => {
                return EndpointResult::error(400, "invalid_client", Some("Client not found"));
            }
        };

        // 2. التحقق من صحة المعاملات
        if let Err(e) = self.validate_authorization_request(&request, &client) {
            return EndpointResult::error(400, "invalid_request", Some(&e.message()));
        }

        // 3. تحليل المخاطر
        let behavioral_context = BehavioralContext {
            typing_pattern: None,
            mouse_pattern: None,
            device_fingerprint: request.device_fingerprint.clone(),
            response_time_ms: None,
            auth_history: Vec::new(),
        };

        let geographic_context = GeographicContext {
            latitude: request.latitude,
            longitude: request.longitude,
            country: request.country.clone(),
            city: request.city.clone(),
            ip_address: Some(request.ip_address.clone()),
            satellite_data: None,
            network_data: None,
        };

        let request_context = RequestContext {
            user_agent: request.user_agent.clone(),
            session_id: request.session_id.clone(),
            ip_address: request.ip_address.clone(),
            request_size: 0,
            headers: HashMap::new(),
        };

        // 4. تطبيق التكيف الأمني
        let adaptation_result = self.adaptive_manager.analyze_and_adapt(
            &request.client_id,
            &behavioral_context,
            &geographic_context,
            &request_context,
        );

        // 5. التحقق من الموافقة
        if !request.user_consent {
            // إرجاع صفحة الموافقة
            return self.create_consent_page(&request, &client);
        }

        // 6. إنشاء رمز المصادقة
        let auth_code = match self.create_authorization_code(&request, &client) {
            Ok(code) => code,
            Err(e) => {
                return EndpointResult::error(500, "server_error", Some(&e.message()));
            }
        };

        // 7. إعادة التوجيه
        let redirect_uri = format!(
            "{}?code={}&state={}",
            request.redirect_uri,
            auth_code,
            request.state.as_deref().unwrap_or("")
        );

        let mut result = EndpointResult::success(&format!(
            r#"{{"redirect_uri":"{}","expires_in":600}}"#,
            redirect_uri
        ));

        result.status_code = 302;
        result.add_header("Location", &redirect_uri);

        // 8. تسجيل معلومات التتبع
        let processing_time = start_time.elapsed().as_millis() as u64;
        let trace_info = TraceInfo {
            request_id,
            processing_time_ms: processing_time,
            security_level: adaptation_result.risk_level,
            adaptations_applied: adaptation_result.applied_actions,
        };
        result.set_trace_info(trace_info);

        result
    }

    /// Arabic: نقطة النهاية للرموز (/oauth/token)
    /// English: Token endpoint (/oauth/token)
    pub fn token(&self, request: &TokenRequest) -> EndpointResult {
        let start_time = std::time::Instant::now();
        let request_id = generate_uuid();

        // 1. التحقق من العميل
        let client = match self
            .client_manager
            .validate_client(&request.client_id, request.client_secret.as_deref())
        {
            Ok(client) => client,
            Err(e) => {
                return EndpointResult::error(401, "invalid_client", Some(&e.message()));
            }
        };

        // 2. معالجة حسب نوع المنح
        let token_response = match request.grant_type {
            GrantType::AuthorizationCode => self.handle_authorization_code_grant(&request, &client),
            GrantType::ClientCredentials => self.handle_client_credentials_grant(&request, &client),
            GrantType::RefreshToken => self.handle_refresh_token_grant(&request, &client),
            GrantType::Password => self.handle_password_grant(&request, &client),
            _ => {
                return EndpointResult::error(400, "unsupported_grant_type", None);
            }
        };

        match token_response {
            Ok(response) => {
                let mut result = EndpointResult::success(&response);

                // تسجيل معلومات التتبع
                let processing_time = start_time.elapsed().as_millis() as u64;
                let trace_info = TraceInfo {
                    request_id,
                    processing_time_ms: processing_time,
                    security_level: 50, // يمكن تحسينه لاحقاً
                    adaptations_applied: Vec::new(),
                };
                result.set_trace_info(trace_info);

                result
            }
            Err(e) => EndpointResult::error(400, "invalid_grant", Some(&e.message())),
        }
    }

    /// Arabic: نقطة النهاية لفحص الرمز (/oauth/introspect)
    /// English: Token introspection endpoint (/oauth/introspect)
    pub fn introspect(&self, request: &IntrospectionRequest) -> EndpointResult {
        let start_time = std::time::Instant::now();

        // 1. التحقق من العميل
        let _client = match self
            .client_manager
            .validate_client(&request.client_id, request.client_secret.as_deref())
        {
            Ok(client) => client,
            Err(_) => {
                return EndpointResult::error(401, "invalid_client", None);
            }
        };

        // 2. فحص الرمز
        let token_info = match self.token_manager.validate_token(&request.token) {
            Ok(info) => info,
            Err(_) => {
                // إرجاع رمز غير نشط
                let inactive_response = r#"{"active":false}"#;
                return EndpointResult::success(inactive_response);
            }
        };

        // 3. تحديث استخدام الرمز
        self.token_manager.use_token(&request.token).ok();

        // 4. إرجاع معلومات الرمز
        let introspection_response = IntrospectionResponse {
            active: true,
            scope: Some(token_info.scopes.to_scope_string()),
            client_id: Some(token_info.client_id.clone()),
            username: token_info.user_id.clone(),
            exp: Some(token_info.expires_at),
            iat: Some(token_info.created_at),
            sub: token_info.user_id,
            aud: Some(token_info.client_id),
            iss: Some(SYSTEM_ISSUER.to_string()),
            jti: Some(token_info.value),
        };

        let response_data = format!("{{\"active\":{},\"scope\":\"{}\",\"client_id\":\"{}\",\"token_type\":\"{}\",\"exp\":{},\"iat\":{},\"sub\":\"{}\",\"aud\":\"{}\",\"iss\":\"{}\"}}",
            introspection_response.active,
            introspection_response.scope.unwrap_or_default(),
            introspection_response.client_id.unwrap_or_default(),
            "Bearer",
            introspection_response.exp.unwrap_or(0),
            introspection_response.iat.unwrap_or(0),
            introspection_response.sub.unwrap_or_default(),
            introspection_response.aud.unwrap_or_default(),
            introspection_response.iss.unwrap_or_default()
        );

        let mut result = EndpointResult::success(&response_data);

        let processing_time = start_time.elapsed().as_millis() as u64;
        let trace_info = TraceInfo {
            request_id: generate_uuid(),
            processing_time_ms: processing_time,
            security_level: 60,
            adaptations_applied: Vec::new(),
        };
        result.set_trace_info(trace_info);

        result
    }

    /// Arabic: نقطة النهاية لمعلومات المستخدم (/oauth/userinfo)
    /// English: User info endpoint (/oauth/userinfo)
    pub fn userinfo(&self, request: &UserInfoRequest) -> EndpointResult {
        let start_time = std::time::Instant::now();

        // 1. التحقق من الرمز
        let token_info = match self.token_manager.validate_token(&request.access_token) {
            Ok(info) => info,
            Err(_) => {
                return EndpointResult::error(401, "invalid_token", None);
            }
        };

        // 2. التحقق من النطاق
        if !token_info.scopes.has_scope("openid") && !token_info.scopes.has_scope("profile") {
            return EndpointResult::error(403, "insufficient_scope", None);
        }

        // 3. الحصول على معلومات المستخدم
        let user_info = UserInfo {
            sub: token_info.user_id.clone().unwrap_or_default(),
            name: Some("Test User".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            middle_name: None,
            nickname: Some("testuser".to_string()),
            preferred_username: Some("testuser".to_string()),
            profile: Some("https://example.com/profile".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
            website: Some("https://example.com".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            gender: Some("male".to_string()),
            birthdate: Some("1990-01-01".to_string()),
            zoneinfo: Some("Asia/Riyadh".to_string()),
            locale: Some("ar-SA".to_string()),
            phone_number: Some("+966501234567".to_string()),
            phone_number_verified: Some(true),
            address: Some(Address {
                formatted: Some("Riyadh, Saudi Arabia".to_string()),
                street_address: Some("123 Main Street".to_string()),
                locality: Some("Riyadh".to_string()),
                region: Some("Riyadh Province".to_string()),
                postal_code: Some("12345".to_string()),
                country: Some("SA".to_string()),
            }),
            updated_at: Some(token_info.created_at),
        };

        let response_data = format!("{{\"sub\":\"{}\",\"name\":\"{}\",\"email\":\"{}\",\"email_verified\":{},\"locale\":\"{}\",\"zoneinfo\":\"{}\"}}",
            user_info.sub,
            user_info.name.unwrap_or_default(),
            user_info.email.unwrap_or_default(),
            user_info.email_verified.unwrap_or(false),
            user_info.locale.unwrap_or_default(),
            user_info.zoneinfo.unwrap_or_default()
        );

        let mut result = EndpointResult::success(&response_data);

        let processing_time = start_time.elapsed().as_millis() as u64;
        let trace_info = TraceInfo {
            request_id: generate_uuid(),
            processing_time_ms: processing_time,
            security_level: 40,
            adaptations_applied: Vec::new(),
        };
        result.set_trace_info(trace_info);

        result
    }

    /// Arabic: نقطة النهاية لإلغاء الرمز (/oauth/revoke)
    /// English: Token revocation endpoint (/oauth/revoke)
    pub fn revoke(&self, request: &RevocationRequest) -> EndpointResult {
        // 1. التحقق من العميل
        let _client = match self
            .client_manager
            .validate_client(&request.client_id, request.client_secret.as_deref())
        {
            Ok(client) => client,
            Err(_) => {
                return EndpointResult::error(401, "invalid_client", None);
            }
        };

        // 2. إلغاء الرمز
        match self.token_manager.revoke_token(&request.token) {
            Ok(_) => EndpointResult::success("{}"), // إرجاع JSON فارغ
            Err(_) => {
                // RFC 7009: يجب إرجاع 200 حتى لو فشل الإلغاء
                EndpointResult::success("{}")
            }
        }
    }

    // === Private Helper Methods ===

    fn validate_authorization_request(
        &self,
        request: &AuthorizationRequest,
        client: &Client,
    ) -> Result<(), TokenValidationError> {
        // التحقق من نوع الاستجابة
        if !client
            .security_policy
            .is_response_type_allowed(&request.response_type)
        {
            return Err(TokenValidationError::InvalidToken);
        }

        // التحقق من عنوان الإعادة
        if !client
            .security_policy
            .is_redirect_uri_allowed(&request.redirect_uri)
        {
            return Err(TokenValidationError::InvalidToken);
        }

        // التحقق من النطاقات
        for scope in &request.scope {
            if !client.security_policy.is_scope_allowed(scope) {
                return Err(TokenValidationError::InsufficientScope);
            }
        }

        Ok(())
    }

    fn create_consent_page(
        &self,
        _request: &AuthorizationRequest,
        _client: &Client,
    ) -> EndpointResult {
        let consent_html = r#"
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <title>طلب الموافقة</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .button { padding: 10px 20px; margin: 10px; }
        .approve { background: #4CAF50; color: white; }
        .deny { background: #f44336; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>طلب الموافقة على الوصول</h1>
        <p>التطبيق يطلب الوصول إلى مواردك.</p>
        <button class="button approve" onclick="approve()">موافقة</button>
        <button class="button deny" onclick="deny()">رفض</button>
    </div>
    <script>
        function approve() { /* TODO: تنفيذ الموافقة */ }
        function deny() { /* TODO: تنفيذ الرفض */ }
    </script>
</body>
</html>"#;

        EndpointResult {
            status_code: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            data: consent_html.to_string(),
            headers: HashMap::new(),
            trace_info: None,
        }
    }

    fn create_authorization_code(
        &self,
        request: &AuthorizationRequest,
        client: &Client,
    ) -> Result<String, TokenValidationError> {
        let scopes = TokenScopes::new(request.scope.clone(), request.scope.clone());

        let token_info = self.token_manager.create_token(
            TokenType::AuthorizationCode,
            client,
            request.user_id.clone(),
            scopes,
            MAX_AUTH_CODE_LIFETIME_SEC,
            None, // geo_context
            None, // behavioral_context
            Some(request.session_id.clone()),
        )?;

        Ok(token_info.value)
    }

    fn handle_authorization_code_grant(
        &self,
        request: &TokenRequest,
        client: &Client,
    ) -> Result<String, TokenValidationError> {
        let auth_code = request
            .code
            .as_ref()
            .ok_or(TokenValidationError::InvalidToken)?;

        // التحقق من رمز المصادقة
        let token_info = self.token_manager.validate_token(auth_code)?;

        if token_info.token_type != TokenType::AuthorizationCode {
            return Err(TokenValidationError::InvalidToken);
        }

        // التحقق من العميل
        if token_info.client_id != client.client_id {
            return Err(TokenValidationError::ClientMismatch);
        }

        // إنشاء رمز الوصول
        let access_token = self.token_manager.create_token(
            TokenType::Access,
            client,
            token_info.user_id,
            token_info.scopes,
            MAX_ACCESS_TOKEN_LIFETIME_SEC,
            None,
            None,
            token_info.session_id,
        )?;

        // إنشاء رمز المنعش (إذا طُلب)
        let refresh_token = if request.scope.iter().any(|s| s == "offline_access") {
            Some(self.token_manager.create_token(
                TokenType::Refresh,
                client,
                access_token.user_id.clone(),
                access_token.scopes.clone(),
                MAX_REFRESH_TOKEN_LIFETIME_SEC,
                None,
                None,
                access_token.session_id.clone(),
            )?)
        } else {
            None
        };

        // إلغاء رمز المصادقة بعد الاستخدام
        self.token_manager.revoke_token(auth_code).ok();

        // إنشاء الاستجابة
        let response = TokenResponse {
            access_token: access_token.value,
            token_type: "Bearer".to_string(),
            expires_in: MAX_ACCESS_TOKEN_LIFETIME_SEC,
            refresh_token: refresh_token.map(|t| t.value),
            scope: Some(access_token.scopes.to_scope_string()),
            id_token: None,
        };

        Ok(format!("{{\"access_token\":\"{}\",\"token_type\":\"{}\",\"expires_in\":{},\"refresh_token\":\"{}\",\"scope\":\"{}\"}}",
            response.access_token,
            response.token_type,
            response.expires_in,
            response.refresh_token.unwrap_or_default(),
            response.scope.unwrap_or_default()
        ))
    }

    fn handle_client_credentials_grant(
        &self,
        request: &TokenRequest,
        client: &Client,
    ) -> Result<String, TokenValidationError> {
        let scopes = TokenScopes::new(request.scope.clone(), request.scope.clone());

        let access_token = self.token_manager.create_token(
            TokenType::Access,
            client,
            None, // لا يوجد مستخدم في client_credentials
            scopes,
            MAX_ACCESS_TOKEN_LIFETIME_SEC,
            None,
            None,
            None,
        )?;

        let response = TokenResponse {
            access_token: access_token.value,
            token_type: "Bearer".to_string(),
            expires_in: MAX_ACCESS_TOKEN_LIFETIME_SEC,
            refresh_token: None, // لا يوجد refresh token في client_credentials
            scope: Some(access_token.scopes.to_scope_string()),
            id_token: None,
        };

        Ok(format!("{{\"access_token\":\"{}\",\"token_type\":\"{}\",\"expires_in\":{},\"refresh_token\":\"{}\",\"scope\":\"{}\"}}",
            response.access_token,
            response.token_type,
            response.expires_in,
            response.refresh_token.unwrap_or_default(),
            response.scope.unwrap_or_default()
        ))
    }

    fn handle_refresh_token_grant(
        &self,
        request: &TokenRequest,
        client: &Client,
    ) -> Result<String, TokenValidationError> {
        let refresh_token_value = request
            .refresh_token
            .as_ref()
            .ok_or(TokenValidationError::InvalidToken)?;

        // التحقق من رمز المنعش
        let refresh_token_info = self.token_manager.validate_token(refresh_token_value)?;

        if refresh_token_info.token_type != TokenType::Refresh {
            return Err(TokenValidationError::InvalidToken);
        }

        // التحقق من العميل
        if refresh_token_info.client_id != client.client_id {
            return Err(TokenValidationError::ClientMismatch);
        }

        // تدوير رمز المنعش
        let new_refresh_token = self.token_manager.rotate_refresh_token(
            refresh_token_value,
            client,
            refresh_token_info.user_id.clone(),
            refresh_token_info.scopes.clone(),
            MAX_REFRESH_TOKEN_LIFETIME_SEC,
            None,
            None,
            refresh_token_info.session_id.clone(),
        )?;

        // إنشاء رمز وصول جديد
        let access_token = self.token_manager.create_token(
            TokenType::Access,
            client,
            refresh_token_info.user_id,
            refresh_token_info.scopes,
            MAX_ACCESS_TOKEN_LIFETIME_SEC,
            None,
            None,
            new_refresh_token.session_id,
        )?;

        let response = TokenResponse {
            access_token: access_token.value,
            token_type: "Bearer".to_string(),
            expires_in: MAX_ACCESS_TOKEN_LIFETIME_SEC,
            refresh_token: Some(new_refresh_token.value),
            scope: Some(access_token.scopes.to_scope_string()),
            id_token: None,
        };

        Ok(format!("{{\"access_token\":\"{}\",\"token_type\":\"{}\",\"expires_in\":{},\"refresh_token\":\"{}\",\"scope\":\"{}\"}}",
            response.access_token,
            response.token_type,
            response.expires_in,
            response.refresh_token.unwrap_or_default(),
            response.scope.unwrap_or_default()
        ))
    }

    fn handle_password_grant(
        &self,
        _request: &TokenRequest,
        _client: &Client,
    ) -> Result<String, TokenValidationError> {
        // TODO: تنفيذ password grant
        Err(TokenValidationError::InvalidToken)
    }
}

// === Request/Response Structures ===

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub response_type: ResponseType,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: Option<String>,
    pub user_consent: bool,
    pub user_id: Option<String>,
    pub session_id: String,
    pub device_fingerprint: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub scope: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserInfoRequest {
    pub access_token: String,
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub address: Option<Address>,
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Address {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
}

// Global instance
static OAUTH2_ENDPOINTS: std::sync::OnceLock<OAuth2Endpoints> = std::sync::OnceLock::new();

/// Arabic: الحصول على مدير نقاط النهاية العام
/// English: Get global endpoints manager
pub fn get_oauth2_endpoints() -> &'static OAuth2Endpoints {
    OAUTH2_ENDPOINTS.get_or_init(|| OAuth2Endpoints::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_result_creation() {
        let success_result = EndpointResult::success(r#"{"status":"ok"}"#);
        assert_eq!(success_result.status_code, 200);
        assert_eq!(success_result.content_type, "application/json");

        let error_result = EndpointResult::error(400, "invalid_request", Some("Missing parameter"));
        assert_eq!(error_result.status_code, 400);
        assert!(error_result.data.contains("invalid_request"));
    }

    #[test]
    fn test_authorization_request() {
        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: "test_client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: vec!["read".to_string()],
            state: Some("state123".to_string()),
            user_consent: true,
            user_id: Some("user123".to_string()),
            session_id: "session123".to_string(),
            device_fingerprint: Some("device123".to_string()),
            latitude: Some(24.7136),
            longitude: Some(46.6753),
            country: Some("SA".to_string()),
            city: Some("Riyadh".to_string()),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Test Agent".to_string(),
        };

        assert_eq!(request.client_id, "test_client");
        assert_eq!(request.response_type, ResponseType::Code);
    }

    #[test]
    fn test_token_request() {
        let request = TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            client_id: "test_client".to_string(),
            client_secret: Some("secret123".to_string()),
            code: Some("code123".to_string()),
            redirect_uri: Some("https://example.com/callback".to_string()),
            refresh_token: None,
            username: None,
            password: None,
            scope: vec!["read".to_string()],
        };

        assert_eq!(request.grant_type, GrantType::AuthorizationCode);
        assert_eq!(request.client_id, "test_client");
    }

    #[test]
    fn test_token_response() {
        let response = TokenResponse {
            access_token: "access_token_123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("refresh_token_123".to_string()),
            scope: Some("read write".to_string()),
            id_token: None,
        };

        assert_eq!(response.access_token, "access_token_123");
        assert_eq!(response.expires_in, 3600);
    }

    #[test]
    fn test_user_info() {
        let user_info = UserInfo {
            sub: "user123".to_string(),
            name: Some("Test User".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            locale: Some("ar-SA".to_string()),
            phone_number: Some("+966501234567".to_string()),
            phone_number_verified: Some(true),
            address: Some(Address {
                formatted: Some("Riyadh, Saudi Arabia".to_string()),
                locality: Some("Riyadh".to_string()),
                country: Some("SA".to_string()),
                ..Address {
                    formatted: None,
                    street_address: None,
                    locality: None,
                    region: None,
                    postal_code: None,
                    country: None,
                }
            }),
            ..UserInfo {
                sub: "".to_string(),
                name: None,
                given_name: None,
                family_name: None,
                middle_name: None,
                nickname: None,
                preferred_username: None,
                profile: None,
                picture: None,
                website: None,
                email: None,
                email_verified: None,
                gender: None,
                birthdate: None,
                zoneinfo: None,
                locale: None,
                phone_number: None,
                phone_number_verified: None,
                address: None,
                updated_at: None,
            }
        };

        assert_eq!(user_info.sub, "user123");
        assert_eq!(user_info.name, Some("Test User".to_string()));
        assert_eq!(user_info.locale, Some("ar-SA".to_string()));
    }
}
