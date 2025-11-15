/*!
معلومات المستخدم (UserInfo) - OpenID Connect
User Info - OpenID Connect

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
*/

use crate::oauth2::core::*;
// Removed serde dependency

/// Arabic: مدير معلومات المستخدم
/// English: User info manager
pub struct UserInfoManager;

impl UserInfoManager {
    /// Arabic: الحصول على معلومات المستخدم
    /// English: Get user information
    pub fn get_user_info(user_id: &str, scopes: &[String]) -> UserInfo {
        // معلومات افتراضية للمستخدم
        let mut user_info = UserInfo {
            sub: user_id.to_string(),
            name: Some("مستخدم تجريبي".to_string()),
            given_name: Some("تجريبي".to_string()),
            family_name: Some("مستخدم".to_string()),
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
                formatted: Some("الرياض، المملكة العربية السعودية".to_string()),
                street_address: Some("شارع الملك فهد".to_string()),
                locality: Some("الرياض".to_string()),
                region: Some("منطقة الرياض".to_string()),
                postal_code: Some("12345".to_string()),
                country: Some("SA".to_string()),
            }),
            updated_at: Some(current_timestamp()),
        };

        // تصفية المعلومات حسب النطاقات المطلوبة
        if !scopes.contains(&"profile".to_string()) {
            user_info.name = None;
            user_info.given_name = None;
            user_info.family_name = None;
            user_info.middle_name = None;
            user_info.nickname = None;
            user_info.preferred_username = None;
            user_info.profile = None;
            user_info.picture = None;
            user_info.website = None;
            user_info.gender = None;
            user_info.birthdate = None;
            user_info.zoneinfo = None;
            user_info.locale = None;
            user_info.updated_at = None;
        }

        if !scopes.contains(&"email".to_string()) {
            user_info.email = None;
            user_info.email_verified = None;
        }

        if !scopes.contains(&"phone".to_string()) {
            user_info.phone_number = None;
            user_info.phone_number_verified = None;
        }

        if !scopes.contains(&"address".to_string()) {
            user_info.address = None;
        }

        user_info
    }
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
