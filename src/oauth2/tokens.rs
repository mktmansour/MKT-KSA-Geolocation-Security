#![allow(clippy::too_many_arguments)]
/*!
إدارة الرموز في نظام OAuth2 - إنشاء وتحقق وإدارة الرموز
OAuth2 Token Management - Token creation, validation, and management

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)

🔑 ميزات إدارة الرموز / Token Management Features:
- Access Token generation and validation
- Refresh Token management
- ID Token creation (OpenID Connect)
- Token introspection
- Token revocation
- Token rotation
- Secure token storage
- Geographic and behavioral context binding
*/

use crate::oauth2::clients::Client;
use crate::oauth2::core::*;
// Removed serde dependency
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Arabic: نوع الرمز
/// English: Token type
#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
    /// Arabic: رمز الوصول
    /// English: Access Token
    Access,
    /// Arabic: رمز المنعش
    /// English: Refresh Token
    Refresh,
    /// Arabic: رمز المعرف (OpenID Connect)
    /// English: ID Token (OpenID Connect)
    Id,
    /// Arabic: رمز المصادقة
    /// English: Authorization Code
    AuthorizationCode,
}

impl TokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenType::Access => "access_token",
            TokenType::Refresh => "refresh_token",
            TokenType::Id => "id_token",
            TokenType::AuthorizationCode => "authorization_code",
        }
    }
}

/// Arabic: نطاقات الرمز
/// English: Token scopes
#[derive(Debug, Clone)]
pub struct TokenScopes {
    /// Arabic: النطاقات الممنوحة
    /// English: Granted scopes
    pub granted: Vec<String>,
    /// Arabic: النطاقات المطلوبة
    /// English: Requested scopes
    pub requested: Vec<String>,
    /// Arabic: النطاقات المرفوضة
    /// English: Denied scopes
    pub denied: Vec<String>,
}

impl TokenScopes {
    pub fn new(granted: Vec<String>, requested: Vec<String>) -> Self {
        let denied: Vec<String> = requested
            .iter()
            .filter(|scope| !granted.contains(scope))
            .cloned()
            .collect();

        Self {
            granted,
            requested,
            denied,
        }
    }

    /// Arabic: التحقق من وجود نطاق
    /// English: Check if scope exists
    pub fn has_scope(&self, scope: &str) -> bool {
        self.granted.contains(&scope.to_string())
    }

    /// Arabic: الحصول على نص النطاقات
    /// English: Get scopes as string
    pub fn to_scope_string(&self) -> String {
        self.granted.join(" ")
    }
}

/// Arabic: معلومات الرمز الأساسية
/// English: Basic token information
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// Arabic: نوع الرمز
    /// English: Token type
    pub token_type: TokenType,
    /// Arabic: قيمة الرمز
    /// English: Token value
    pub value: String,
    /// Arabic: معرف العميل
    /// English: Client ID
    pub client_id: String,
    /// Arabic: معرف المستخدم (اختياري)
    /// English: User ID (optional)
    pub user_id: Option<String>,
    /// Arabic: النطاقات
    /// English: Scopes
    pub scopes: TokenScopes,
    /// Arabic: وقت الإنشاء
    /// English: Creation time
    pub created_at: u64,
    /// Arabic: وقت الانتهاء
    /// English: Expiration time
    pub expires_at: u64,
    /// Arabic: وقت آخر استخدام
    /// English: Last used time
    pub last_used_at: Option<u64>,
    /// Arabic: عدد مرات الاستخدام
    /// English: Usage count
    pub usage_count: u32,
    /// Arabic: السياق الجغرافي عند الإنشاء
    /// English: Geographic context at creation
    pub geo_context: Option<GeographicContext>,
    /// Arabic: السياق السلوكي عند الإنشاء
    /// English: Behavioral context at creation
    pub behavioral_context: Option<BehavioralContext>,
    /// Arabic: حالة الرمز
    /// English: Token status
    pub status: TokenStatus,
    /// Arabic: معرف الجلسة
    /// English: Session ID
    pub session_id: Option<String>,
}

/// Arabic: حالة الرمز
/// English: Token status
#[derive(Debug, Clone, PartialEq)]
pub enum TokenStatus {
    /// Arabic: نشط
    /// English: Active
    Active,
    /// Arabic: منتهي الصلاحية
    /// English: Expired
    Expired,
    /// Arabic: مُلغى
    /// English: Revoked
    Revoked,
    /// Arabic: معطل مؤقتاً
    /// English: Temporarily disabled
    Suspended,
}

impl TokenInfo {
    /// Arabic: إنشاء معلومات رمز جديدة
    /// English: Create new token info
    pub fn new(
        token_type: TokenType,
        value: String,
        client_id: String,
        user_id: Option<String>,
        scopes: TokenScopes,
        lifetime_sec: u64,
        geo_context: Option<GeographicContext>,
        behavioral_context: Option<BehavioralContext>,
        session_id: Option<String>,
    ) -> Self {
        let now = current_timestamp();

        Self {
            token_type,
            value,
            client_id,
            user_id,
            scopes,
            created_at: now,
            expires_at: now + lifetime_sec,
            last_used_at: None,
            usage_count: 0,
            geo_context,
            behavioral_context,
            status: TokenStatus::Active,
            session_id,
        }
    }

    /// Arabic: التحقق من صحة الرمز
    /// English: Validate token
    pub fn validate(&self) -> Result<(), TokenValidationError> {
        match self.status {
            TokenStatus::Revoked => return Err(TokenValidationError::TokenRevoked),
            TokenStatus::Suspended => return Err(TokenValidationError::TokenSuspended),
            TokenStatus::Expired => return Err(TokenValidationError::TokenExpired),
            TokenStatus::Active => {}
        }

        if current_timestamp() > self.expires_at {
            return Err(TokenValidationError::TokenExpired);
        }

        Ok(())
    }

    /// Arabic: تحديث استخدام الرمز
    /// English: Update token usage
    pub fn update_usage(&mut self) {
        self.last_used_at = Some(current_timestamp());
        self.usage_count += 1;
    }

    /// Arabic: إلغاء الرمز
    /// English: Revoke token
    pub fn revoke(&mut self) {
        self.status = TokenStatus::Revoked;
    }

    /// Arabic: تعطيل الرمز مؤقتاً
    /// English: Suspend token temporarily
    pub fn suspend(&mut self) {
        self.status = TokenStatus::Suspended;
    }

    /// Arabic: التحقق من صحة النطاق
    /// English: Validate scope
    pub fn validate_scope(&self, required_scope: &str) -> Result<(), TokenValidationError> {
        if !self.scopes.has_scope(required_scope) {
            return Err(TokenValidationError::InsufficientScope);
        }
        Ok(())
    }

    /// Arabic: تمديد صلاحية الرمز
    /// English: Extend token lifetime
    pub fn extend_lifetime(&mut self, additional_sec: u64) {
        self.expires_at += additional_sec;
    }
}

/// Arabic: أخطاء التحقق من الرمز
/// English: Token validation errors
#[derive(Debug, Clone)]
pub enum TokenValidationError {
    /// Arabic: الرمز غير موجود
    /// English: Token not found
    TokenNotFound,
    /// Arabic: الرمز منتهي الصلاحية
    /// English: Token expired
    TokenExpired,
    /// Arabic: الرمز مُلغى
    /// English: Token revoked
    TokenRevoked,
    /// Arabic: الرمز معطل
    /// English: Token suspended
    TokenSuspended,
    /// Arabic: نطاق غير كافي
    /// English: Insufficient scope
    InsufficientScope,
    /// Arabic: رمز غير صحيح
    /// English: Invalid token
    InvalidToken,
    /// Arabic: العميل غير مطابق
    /// English: Client mismatch
    ClientMismatch,
}

impl TokenValidationError {
    pub fn message(&self) -> &'static str {
        match self {
            TokenValidationError::TokenNotFound => "Token not found",
            TokenValidationError::TokenExpired => "Token has expired",
            TokenValidationError::TokenRevoked => "Token has been revoked",
            TokenValidationError::TokenSuspended => "Token is suspended",
            TokenValidationError::InsufficientScope => "Insufficient scope",
            TokenValidationError::InvalidToken => "Invalid token",
            TokenValidationError::ClientMismatch => "Client mismatch",
        }
    }
}

/// Arabic: مدير الرموز
/// English: Token manager
pub struct TokenManager {
    tokens: Arc<Mutex<HashMap<String, TokenInfo>>>,
    access_tokens: Arc<Mutex<HashMap<String, String>>>, // token -> client_id
    refresh_tokens: Arc<Mutex<HashMap<String, String>>>, // token -> client_id
    id_tokens: Arc<Mutex<HashMap<String, String>>>,     // token -> client_id
    auth_codes: Arc<Mutex<HashMap<String, String>>>,    // code -> client_id
}

impl TokenManager {
    /// Arabic: إنشاء مدير رموز جديد
    /// English: Create new token manager
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            id_tokens: Arc::new(Mutex::new(HashMap::new())),
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenManager {
    /// Arabic: إنشاء رمز جديد
    /// English: Create new token
    pub fn create_token(
        &self,
        token_type: TokenType,
        client: &Client,
        user_id: Option<String>,
        scopes: TokenScopes,
        lifetime_sec: u64,
        geo_context: Option<GeographicContext>,
        behavioral_context: Option<BehavioralContext>,
        session_id: Option<String>,
    ) -> Result<TokenInfo, TokenValidationError> {
        let value = self.generate_secure_token(&token_type);

        let token_info = TokenInfo::new(
            token_type.clone(),
            value.clone(),
            client.client_id.clone(),
            user_id,
            scopes,
            lifetime_sec,
            geo_context,
            behavioral_context,
            session_id,
        );

        // تخزين الرمز
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens.insert(value.clone(), token_info.clone());

        // إضافة إلى الفهرس المناسب
        match token_type {
            TokenType::Access => {
                let mut access_tokens =
                    self.access_tokens.lock().unwrap_or_else(|e| e.into_inner());
                access_tokens.insert(value, client.client_id.clone());
            }
            TokenType::Refresh => {
                let mut refresh_tokens = self
                    .refresh_tokens
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                refresh_tokens.insert(value, client.client_id.clone());
            }
            TokenType::Id => {
                let mut id_tokens = self.id_tokens.lock().unwrap_or_else(|e| e.into_inner());
                id_tokens.insert(value, client.client_id.clone());
            }
            TokenType::AuthorizationCode => {
                let mut auth_codes = self.auth_codes.lock().unwrap_or_else(|e| e.into_inner());
                auth_codes.insert(value, client.client_id.clone());
            }
        }

        Ok(token_info)
    }

    /// Arabic: الحصول على معلومات الرمز
    /// English: Get token info
    pub fn get_token(&self, token_value: &str) -> Option<TokenInfo> {
        let tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens.get(token_value).cloned()
    }

    /// Arabic: التحقق من صحة الرمز
    /// English: Validate token
    pub fn validate_token(&self, token_value: &str) -> Result<TokenInfo, TokenValidationError> {
        let token_info = self
            .get_token(token_value)
            .ok_or(TokenValidationError::TokenNotFound)?;

        token_info.validate()?;
        Ok(token_info)
    }

    /// Arabic: استخدام الرمز (تحديث إحصائيات الاستخدام)
    /// English: Use token (update usage statistics)
    pub fn use_token(&self, token_value: &str) -> Result<TokenInfo, TokenValidationError> {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());

        let token_info = tokens
            .get_mut(token_value)
            .ok_or(TokenValidationError::TokenNotFound)?;

        token_info.validate()?;
        token_info.update_usage();

        Ok(token_info.clone())
    }

    /// Arabic: إلغاء الرمز
    /// English: Revoke token
    pub fn revoke_token(&self, token_value: &str) -> Result<(), TokenValidationError> {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(token_info) = tokens.get_mut(token_value) {
            token_info.revoke();

            // إزالة من الفهارس
            match token_info.token_type {
                TokenType::Access => {
                    let mut access_tokens =
                        self.access_tokens.lock().unwrap_or_else(|e| e.into_inner());
                    access_tokens.remove(token_value);
                }
                TokenType::Refresh => {
                    let mut refresh_tokens = self
                        .refresh_tokens
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    refresh_tokens.remove(token_value);
                }
                TokenType::Id => {
                    let mut id_tokens = self.id_tokens.lock().unwrap_or_else(|e| e.into_inner());
                    id_tokens.remove(token_value);
                }
                TokenType::AuthorizationCode => {
                    let mut auth_codes = self.auth_codes.lock().unwrap_or_else(|e| e.into_inner());
                    auth_codes.remove(token_value);
                }
            }

            Ok(())
        } else {
            Err(TokenValidationError::TokenNotFound)
        }
    }

    /// Arabic: إلغاء جميع رموز العميل
    /// English: Revoke all client tokens
    pub fn revoke_client_tokens(&self, client_id: &str) -> Result<u32, TokenValidationError> {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let mut revoked_count = 0;

        for (_token_value, token_info) in tokens.iter_mut() {
            if token_info.client_id == client_id && token_info.status == TokenStatus::Active {
                token_info.revoke();
                revoked_count += 1;
            }
        }

        // تنظيف الفهارس
        self.cleanup_indexes();

        Ok(revoked_count)
    }

    /// Arabic: إلغاء جميع رموز المستخدم
    /// English: Revoke all user tokens
    pub fn revoke_user_tokens(&self, user_id: &str) -> Result<u32, TokenValidationError> {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let mut revoked_count = 0;

        for (_token_value, token_info) in tokens.iter_mut() {
            if token_info.user_id.as_deref() == Some(user_id)
                && token_info.status == TokenStatus::Active
            {
                token_info.revoke();
                revoked_count += 1;
            }
        }

        self.cleanup_indexes();
        Ok(revoked_count)
    }

    /// Arabic: تنظيف الرموز المنتهية الصلاحية
    /// English: Clean up expired tokens
    pub fn cleanup_expired_tokens(&self) -> u32 {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let mut removed_count = 0;
        let now = current_timestamp();

        tokens.retain(|_token_value, token_info| {
            if token_info.expires_at < now || token_info.status == TokenStatus::Revoked {
                removed_count += 1;
                false
            } else {
                true
            }
        });

        self.cleanup_indexes();
        removed_count
    }

    /// Arabic: تدوير رمز المنعش
    /// English: Rotate refresh token
    pub fn rotate_refresh_token(
        &self,
        old_token: &str,
        client: &Client,
        user_id: Option<String>,
        scopes: TokenScopes,
        lifetime_sec: u64,
        geo_context: Option<GeographicContext>,
        behavioral_context: Option<BehavioralContext>,
        session_id: Option<String>,
    ) -> Result<TokenInfo, TokenValidationError> {
        // التحقق من الرمز القديم
        let old_token_info = self.validate_token(old_token)?;

        if old_token_info.token_type != TokenType::Refresh {
            return Err(TokenValidationError::InvalidToken);
        }

        // إلغاء الرمز القديم
        self.revoke_token(old_token)?;

        // إنشاء رمز جديد
        self.create_token(
            TokenType::Refresh,
            client,
            user_id,
            scopes,
            lifetime_sec,
            geo_context,
            behavioral_context,
            session_id,
        )
    }

    /// Arabic: الحصول على إحصائيات الرموز
    /// English: Get token statistics
    pub fn get_token_statistics(&self) -> TokenStatistics {
        let tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let now = current_timestamp();

        let mut stats = TokenStatistics::new();

        for token_info in tokens.values() {
            stats.total_tokens += 1;

            match token_info.token_type {
                TokenType::Access => stats.access_tokens += 1,
                TokenType::Refresh => stats.refresh_tokens += 1,
                TokenType::Id => stats.id_tokens += 1,
                TokenType::AuthorizationCode => stats.auth_codes += 1,
            }

            match token_info.status {
                TokenStatus::Active => {
                    if token_info.expires_at > now {
                        stats.active_tokens += 1;
                    } else {
                        stats.expired_tokens += 1;
                    }
                }
                TokenStatus::Expired => stats.expired_tokens += 1,
                TokenStatus::Revoked => stats.revoked_tokens += 1,
                TokenStatus::Suspended => stats.suspended_tokens += 1,
            }
        }

        stats
    }

    // === Private Helper Methods ===

    fn generate_secure_token(&self, token_type: &TokenType) -> String {
        let prefix = match token_type {
            TokenType::Access => "at_",
            TokenType::Refresh => "rt_",
            TokenType::Id => "id_",
            TokenType::AuthorizationCode => "ac_",
        };

        let random_part = generate_secure_code(32);
        format!("{}{}", prefix, random_part)
    }

    fn cleanup_indexes(&self) {
        let tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());

        // تنظيف فهرس رموز الوصول
        {
            let mut access_tokens = self.access_tokens.lock().unwrap_or_else(|e| e.into_inner());
            access_tokens.retain(|token, _| tokens.contains_key(token));
        }

        // تنظيف فهرس رموز المنعش
        {
            let mut refresh_tokens = self
                .refresh_tokens
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            refresh_tokens.retain(|token, _| tokens.contains_key(token));
        }

        // تنظيف فهرس رموز المعرف
        {
            let mut id_tokens = self.id_tokens.lock().unwrap_or_else(|e| e.into_inner());
            id_tokens.retain(|token, _| tokens.contains_key(token));
        }

        // تنظيف فهرس رموز المصادقة
        {
            let mut auth_codes = self.auth_codes.lock().unwrap_or_else(|e| e.into_inner());
            auth_codes.retain(|token, _| tokens.contains_key(token));
        }
    }
}

/// Arabic: إحصائيات الرموز
/// English: Token statistics
#[derive(Debug, Clone)]
pub struct TokenStatistics {
    /// Arabic: إجمالي الرموز
    /// English: Total tokens
    pub total_tokens: u32,
    /// Arabic: رموز نشطة
    /// English: Active tokens
    pub active_tokens: u32,
    /// Arabic: رموز منتهية الصلاحية
    /// English: Expired tokens
    pub expired_tokens: u32,
    /// Arabic: رموز مُلغاة
    /// English: Revoked tokens
    pub revoked_tokens: u32,
    /// Arabic: رموز معطلة
    /// English: Suspended tokens
    pub suspended_tokens: u32,
    /// Arabic: رموز الوصول
    /// English: Access tokens
    pub access_tokens: u32,
    /// Arabic: رموز المنعش
    /// English: Refresh tokens
    pub refresh_tokens: u32,
    /// Arabic: رموز المعرف
    /// English: ID tokens
    pub id_tokens: u32,
    /// Arabic: رموز المصادقة
    /// English: Authorization codes
    pub auth_codes: u32,
}

impl TokenStatistics {
    pub fn new() -> Self {
        Self {
            total_tokens: 0,
            active_tokens: 0,
            expired_tokens: 0,
            revoked_tokens: 0,
            suspended_tokens: 0,
            access_tokens: 0,
            refresh_tokens: 0,
            id_tokens: 0,
            auth_codes: 0,
        }
    }
}

impl Default for TokenStatistics {
    fn default() -> Self {
        Self::new()
    }
}

// Global instance
static TOKEN_MANAGER: OnceLock<TokenManager> = OnceLock::new();

/// Arabic: الحصول على مدير الرموز العام
/// English: Get global token manager
pub fn get_token_manager() -> &'static TokenManager {
    TOKEN_MANAGER.get_or_init(TokenManager::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::clients::{ClientAuthMethod, ClientType};

    fn create_test_client() -> Client {
        Client::new(
            "test_client".to_string(),
            "Test Client".to_string(),
            ClientType::Web,
            ClientAuthMethod::ClientSecret,
        )
    }

    #[test]
    fn test_token_creation() {
        let manager = TokenManager::new();
        let client = create_test_client();
        let scopes = TokenScopes::new(
            vec!["read".to_string(), "write".to_string()],
            vec!["read".to_string(), "write".to_string()],
        );

        let token = manager
            .create_token(
                TokenType::Access,
                &client,
                Some("user123".to_string()),
                scopes,
                3600, // 1 hour
                None,
                None,
                Some("session123".to_string()),
            )
            .unwrap();

        assert_eq!(token.client_id, "test_client");
        assert_eq!(token.user_id, Some("user123".to_string()));
        assert!(token.scopes.has_scope("read"));
        assert_eq!(token.status, TokenStatus::Active);
    }

    #[test]
    fn test_token_validation() {
        let manager = TokenManager::new();
        let client = create_test_client();
        let scopes = TokenScopes::new(vec!["read".to_string()], vec!["read".to_string()]);

        let token = manager
            .create_token(
                TokenType::Access,
                &client,
                None,
                scopes,
                3600,
                None,
                None,
                None,
            )
            .unwrap();

        // التحقق من الرمز الصحيح
        let validation = manager.validate_token(&token.value);
        assert!(validation.is_ok());

        // التحقق من الرمز غير الموجود
        let invalid_validation = manager.validate_token("invalid_token");
        assert!(invalid_validation.is_err());
    }

    #[test]
    fn test_token_usage() {
        let manager = TokenManager::new();
        let client = create_test_client();
        let scopes = TokenScopes::new(vec!["read".to_string()], vec!["read".to_string()]);

        let token = manager
            .create_token(
                TokenType::Access,
                &client,
                None,
                scopes,
                3600,
                None,
                None,
                None,
            )
            .unwrap();

        let initial_usage = token.usage_count;

        // استخدام الرمز
        let used_token = manager.use_token(&token.value).unwrap();
        assert_eq!(used_token.usage_count, initial_usage + 1);
        assert!(used_token.last_used_at.is_some());
    }

    #[test]
    fn test_token_revocation() {
        let manager = TokenManager::new();
        let client = create_test_client();
        let scopes = TokenScopes::new(vec!["read".to_string()], vec!["read".to_string()]);

        let token = manager
            .create_token(
                TokenType::Access,
                &client,
                None,
                scopes,
                3600,
                None,
                None,
                None,
            )
            .unwrap();

        // إلغاء الرمز
        let revocation = manager.revoke_token(&token.value);
        assert!(revocation.is_ok());

        // محاولة استخدام الرمز المُلغى
        let validation = manager.validate_token(&token.value);
        assert!(validation.is_err());
    }

    #[test]
    fn test_token_scope_validation() {
        let manager = TokenManager::new();
        let client = create_test_client();
        let scopes = TokenScopes::new(
            vec!["read".to_string()],
            vec!["read".to_string(), "write".to_string()],
        );

        let token = manager
            .create_token(
                TokenType::Access,
                &client,
                None,
                scopes,
                3600,
                None,
                None,
                None,
            )
            .unwrap();

        // التحقق من النطاق الموجود
        assert!(token.scopes.has_scope("read"));
        assert!(!token.scopes.has_scope("write"));

        // التحقق من النطاق المرفوض
        assert!(token.scopes.denied.contains(&"write".to_string()));
    }

    #[test]
    fn test_refresh_token_rotation() {
        let manager = TokenManager::new();
        let client = create_test_client();
        let scopes = TokenScopes::new(vec!["read".to_string()], vec!["read".to_string()]);

        let old_token = manager
            .create_token(
                TokenType::Refresh,
                &client,
                Some("user123".to_string()),
                scopes.clone(),
                86400, // 24 hours
                None,
                None,
                None,
            )
            .unwrap();

        // تدوير الرمز
        let new_token = manager
            .rotate_refresh_token(
                &old_token.value,
                &client,
                Some("user123".to_string()),
                scopes,
                86400,
                None,
                None,
                None,
            )
            .unwrap();

        assert_ne!(old_token.value, new_token.value);
        assert_eq!(new_token.user_id, Some("user123".to_string()));

        // الرمز القديم يجب أن يكون مُلغى
        let old_validation = manager.validate_token(&old_token.value);
        assert!(old_validation.is_err());

        // الرمز الجديد يجب أن يكون صالح
        let new_validation = manager.validate_token(&new_token.value);
        assert!(new_validation.is_ok());
    }

    #[test]
    fn test_token_statistics() {
        let manager = TokenManager::new();
        let client = create_test_client();
        let scopes = TokenScopes::new(vec!["read".to_string()], vec!["read".to_string()]);

        // إنشاء رموز مختلفة
        manager
            .create_token(
                TokenType::Access,
                &client,
                None,
                scopes.clone(),
                3600,
                None,
                None,
                None,
            )
            .unwrap();
        manager
            .create_token(
                TokenType::Refresh,
                &client,
                None,
                scopes.clone(),
                86400,
                None,
                None,
                None,
            )
            .unwrap();
        manager
            .create_token(TokenType::Id, &client, None, scopes, 3600, None, None, None)
            .unwrap();

        let stats = manager.get_token_statistics();
        assert_eq!(stats.total_tokens, 3);
        assert_eq!(stats.access_tokens, 1);
        assert_eq!(stats.refresh_tokens, 1);
        assert_eq!(stats.id_tokens, 1);
        assert_eq!(stats.active_tokens, 3);
    }
}
