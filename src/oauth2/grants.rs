/*!
أنواع المنح في OAuth2 - تنفيذ جميع أنواع المنح
OAuth2 Grant Types - Implementation of all grant types

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
*/

use crate::oauth2::core::*;
// Removed serde dependency

/// Arabic: معالج أنواع المنح
/// English: Grant types handler
pub struct GrantTypesHandler;

impl GrantTypesHandler {
    /// Arabic: التحقق من صحة نوع المنح
    /// English: Validate grant type
    pub fn validate_grant_type(grant_type: &str) -> Option<GrantType> {
        GrantType::from_str(grant_type)
    }

    /// Arabic: الحصول على معلومات نوع المنح
    /// English: Get grant type information
    pub fn get_grant_type_info(grant_type: &GrantType) -> GrantTypeInfo {
        match grant_type {
            GrantType::AuthorizationCode => GrantTypeInfo {
                name: "Authorization Code".to_string(),
                description: "يستخدم للتطبيقات الويب والتطبيقات المحمولة".to_string(),
                security_level: 8,
                requires_user_interaction: true,
                supports_refresh_token: true,
                rfc_section: "4.1".to_string(),
            },
            GrantType::ClientCredentials => GrantTypeInfo {
                name: "Client Credentials".to_string(),
                description: "يستخدم للخدمات والتطبيقات الخلفية".to_string(),
                security_level: 6,
                requires_user_interaction: false,
                supports_refresh_token: false,
                rfc_section: "4.4".to_string(),
            },
            GrantType::RefreshToken => GrantTypeInfo {
                name: "Refresh Token".to_string(),
                description: "يستخدم لتجديد رموز الوصول".to_string(),
                security_level: 7,
                requires_user_interaction: false,
                supports_refresh_token: false,
                rfc_section: "6".to_string(),
            },
            GrantType::Password => GrantTypeInfo {
                name: "Resource Owner Password Credentials".to_string(),
                description: "يستخدم للتطبيقات الموثوقة فقط".to_string(),
                security_level: 4,
                requires_user_interaction: true,
                supports_refresh_token: true,
                rfc_section: "4.3".to_string(),
            },
            GrantType::Device => GrantTypeInfo {
                name: "Device Flow".to_string(),
                description: "يستخدم للأجهزة المحدودة المدخلات".to_string(),
                security_level: 7,
                requires_user_interaction: true,
                supports_refresh_token: true,
                rfc_section: "RFC 8628".to_string(),
            },
            GrantType::PKCE => GrantTypeInfo {
                name: "PKCE (Proof Key for Code Exchange)".to_string(),
                description: "تحسين أمني لـ Authorization Code Flow".to_string(),
                security_level: 9,
                requires_user_interaction: true,
                supports_refresh_token: true,
                rfc_section: "RFC 7636".to_string(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct GrantTypeInfo {
    pub name: String,
    pub description: String,
    pub security_level: u8,
    pub requires_user_interaction: bool,
    pub supports_refresh_token: bool,
    pub rfc_section: String,
}
