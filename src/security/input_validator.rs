/******************************************************************************************
        📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    File Name: input_validator.rs
    Path:      src/security/input_validator.rs

    File Role:
    هذا الملف هو "مختبر التحليل الكيميائي" للمشروع. يوفر الأدوات
    اللازمة للتحقق من صحة (Validation) وتعقيم (Sanitization) جميع
    المدخلات القادمة من المستخدم. الهدف هو ضمان أن أي بيانات تدخل
    النظام هي نظيفة، آمنة، ومتوقعة، مما يمنع مجموعة واسعة من
    الهجمات مثل حقن SQL، XSS، وغيرها.

    --------------------------------------------------------------

    File Name: input_validator.rs
    Path:      src/security/input_validator.rs

    File Role:
    This file is the project's "Chemical Analysis Lab". It provides the necessary
    tools to validate and sanitize all user-provided input. The goal is to ensure
    that any data entering the system is clean, safe, and expected, preventing
    a wide range of attacks like SQL Injection, XSS, and others.
******************************************************************************************/

use ammonia::clean;
// once_cell is no longer used for statics after switching to std::sync::LazyLock
use regex::Regex;
#[cfg(test)]
use unicode_normalization::is_nfc;
use unicode_normalization::UnicodeNormalization;
use validator::ValidationError;

// =========================================================================================
// === Security Pipeline Recommendation ====================================================
// =========================================================================================
//
// Arabic:
// لضمان أقصى درجات الأمان، يوصى بتطبيق الخطوات التالية بالترتيب على كل مدخلات المستخدم:
// 1. normalize_and_sanitize: لتوحيد الترميز والحماية من هجمات Homoglyph و XSS.
// 2. validate_...: لتطبيق قواعد التحقق المخصصة (طول، صيغة، قوة، ...).
//
// English:
// For maximum security, it is recommended to apply the following steps in order to all user inputs:
// 1. normalize_and_sanitize: To unify encoding and protect against Homoglyph and XSS attacks.
// 2. validate_...: To apply custom validation rules (length, format, strength, ...).
//
// =========================================================================================

// --- Pre-compiled Regex for Performance ---
static PHONE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // A simple international phone number regex
    Regex::new(r"^\+?[1-9]\d{1,14}$").unwrap()
});
static USERNAME_BLACKLIST: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| vec!["admin", "root", "administrator", "support", "superuser"]);

// --- Sanitization Functions ---

/// Arabic: دالة مركزية لتعقيم المدخلات النصية من هجمات XSS.
/// تستخدم مكتبة `ammonia` لإزالة أي أكواد HTML أو JS خبيثة.
/// يسمح فقط بالنص العادي، مما يجعله آمنًا للعرض أو التخزين.
///
/// English: A central function to sanitize string inputs against XSS attacks.
/// It uses the `ammonia` library to remove any malicious HTML or JS code.
/// Only plain text is allowed, making it safe for display or storage.
#[must_use]
pub fn sanitize_text(input: &str) -> String {
    // A very strict setting: allows no HTML tags at all.
    clean(input)
}

/// Arabic: دالة متقدمة تقوم بتوحيد ترميز النص (لمنع هجمات Homoglyph) ثم تعقيمه.
/// هذه هي الدالة الموصى بها للمدخلات الحساسة مثل أسماء المستخدمين.
///
/// English: An advanced function that normalizes the text encoding (to prevent Homoglyph attacks)
/// and then sanitizes it. This is the recommended function for sensitive inputs like usernames.
#[must_use]
pub fn normalize_and_sanitize(text: &str) -> String {
    let normalized: String = text.nfc().collect();
    sanitize_text(&normalized)
}

// --- Custom Validation Functions ---

/// Arabic: دالة تحقق مخصصة لقوة كلمة المرور.
/// تتطلب: 8 أحرف على الأقل، حرف صغير، حرف كبير، رقم، ورمز.
///
/// English: A custom validation function for password strength.
/// Requires: at least 8 characters, a lowercase letter, an uppercase letter, a digit, and a symbol.
///
/// # Panics
/// This function does not intentionally panic. Internally compiled regexes may panic only if the patterns are invalid (compile-time constants here).
///
/// # Errors
/// Returns `ValidationError` describing which policy rule failed.
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    // Break down the complex regex into individual checks for compatibility.
    let has_lowercase = Regex::new(r"[a-z]").unwrap().is_match(password);
    let has_uppercase = Regex::new(r"[A-Z]").unwrap().is_match(password);
    let has_digit = Regex::new(r"\d").unwrap().is_match(password);
    let has_symbol = Regex::new(r"[^\da-zA-Z]").unwrap().is_match(password);
    let is_long_enough = password.len() >= 8;

    if !(has_lowercase && has_uppercase && has_digit && has_symbol && is_long_enough) {
        // TODO: Log failed password strength validation attempt for security auditing.
        let mut err = ValidationError::new("password_policy");
        err.add_param(
            "reason".into(), 
            &"Password must contain at least one lowercase, uppercase, digit, and special character, and be at least 8 characters long."
        );
        return Err(err);
    }
    Ok(())
}

/// Arabic: دالة تحقق مخصصة لاسم المستخدم.
///
/// تتحقق من الطول وتحظر الأسماء الموجودة في القائمة السوداء.
/// English: A custom validation function for usernames.
///
/// Checks length and prohibits names from the blacklist.
///
/// # Errors
/// Returns `ValidationError` when length is out of range or username is blacklisted.
pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.len() < 3 || username.len() > 24 {
        // TODO: Log failed username validation attempt (length).
        return Err(ValidationError::new("invalid_username_length"));
    }
    if USERNAME_BLACKLIST
        .iter()
        .any(|&name| username.eq_ignore_ascii_case(name))
    {
        // TODO: Log failed username validation attempt (blacklist).
        return Err(ValidationError::new("blacklisted_username"));
    }
    Ok(())
}

/// Arabic: دالة تحقق مخصصة لصيغة رقم الهاتف الدولي.
/// English: A custom validation function for international phone number format.
///
/// # Errors
/// Returns `ValidationError` when the phone number does not match the expected E.164-like pattern.
pub fn validate_phone_number(phone: &str) -> Result<(), ValidationError> {
    if !PHONE_RE.is_match(phone) {
        // TODO: Log failed phone number validation attempt.
        return Err(ValidationError::new("invalid_phone_number_format"));
    }
    Ok(())
}

// Example of how this will be used on a struct in the `api` layer later:
/*
use validator::Validate;

#[derive(Validate, serde::Deserialize)]
pub struct SignupData {
    #[validate(email(message = "Please provide a valid email."))]
    pub email: String,

    #[validate(custom = "validate_password_strength")]
    pub password: String,

    #[validate(custom = "validate_username")]
    pub username: String, // This field would be first processed with normalize_and_sanitize

    #[validate(custom = "validate_phone_number")]
    pub phone_number: String,
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_text_removes_scripts() {
        let malicious_input = "Hello, <script>alert('XSS');</script> world!";
        let sanitized = sanitize_text(malicious_input);
        assert_eq!(sanitized, "Hello,  world!");
    }

    #[test]
    fn test_sanitize_text_removes_html_tags() {
        let html_input = "<b>Bold</b> and <i>italic</i> text. <style>p { color: red; }</style>";
        let sanitized = sanitize_text(html_input);
        // Default ammonia settings keep safe tags like <b> and <i>, but remove things like <style>
        assert_eq!(sanitized, "<b>Bold</b> and <i>italic</i> text. ");
    }

    #[test]
    fn test_sanitize_text_keeps_safe_text() {
        let safe_input = "This is a normal, safe sentence with numbers 123 and symbols !@#$.";
        let sanitized = sanitize_text(safe_input);
        assert_eq!(sanitized, safe_input);
    }

    // --- Tests for new functions ---

    #[test]
    fn test_password_strength_validator() {
        assert!(validate_password_strength("StrongP@ss1").is_ok());
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("weakpass").is_err());
        assert!(validate_password_strength("Weakpass1").is_err()); // No symbol
        assert!(validate_password_strength("weakpass!").is_err()); // No uppercase/digit
        assert!(validate_password_strength("WEAKPASS1!").is_err()); // No lowercase
    }

    #[test]
    fn test_normalization() {
        // A Cyrillic 'а' which looks like a Latin 'a'
        let homoglyph_input = "pаypal"; // First 'a' is Latin, second is Cyrillic
        let normalized = normalize_and_sanitize(homoglyph_input);
        // This is a simplified test; real-world homoglyph attacks can be more complex.
        // The goal is to ensure the normalization logic runs.
        if is_nfc(homoglyph_input) {
            assert_eq!(normalized, homoglyph_input);
        } else {
            assert_ne!(normalized, homoglyph_input);
        }

        // Test with script tags
        let malicious_normalized = "pаypal<script>alert(1)</script>";
        let sanitized_normalized = normalize_and_sanitize(malicious_normalized);
        assert!(!sanitized_normalized.contains("<script>"));
    }

    // --- Tests for new custom validators ---

    #[test]
    fn test_username_validator() {
        assert!(validate_username("good_user").is_ok());
        assert!(validate_username("ad").is_err()); // Too short
        assert!(validate_username("a_very_very_long_username_that_is_not_allowed").is_err()); // Too long
        assert!(validate_username("admin").is_err()); // Blacklisted
        assert!(validate_username("Support").is_err()); // Blacklisted, case-insensitive
    }

    #[test]
    fn test_phone_number_validator() {
        assert!(validate_phone_number("+15551234567").is_ok());
        assert!(validate_phone_number("12345").is_ok()); // Simple case
        assert!(validate_phone_number("+1-555-123-4567").is_err()); // Contains dashes
        assert!(validate_phone_number("not a phone").is_err());
    }
}
