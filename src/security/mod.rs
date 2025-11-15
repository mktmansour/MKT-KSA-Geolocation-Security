/******************************************************************************************
        📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: mod.rs
    المسار: src/security/mod.rs

    وظيفة الملف:
    هذا الملف يعمل كفهرس (index) لوحدة الأمان. يقوم بتجميع والإعلان عن جميع الوحدات
    الفرعية المتعلقة بالأمان (التحقق من المدخلات، JWT، السياسات، تحديد المعدل)،
    مما يسمح لباقي أجزاء المشروع باستخدامها بسهولة.

    File Name: mod.rs
    Path:     src/security/mod.rs

    File Role:
    This file serves as the index for the security module. It aggregates and declares
    all security-related sub-modules (input validation, JWT, policy, rate limiting),
    allowing other parts of the project to use them easily.
******************************************************************************************/

// Arabic: وحدة التحقق من المدخلات (Input Validator)
// English: Input Validator module
#[cfg(feature = "input_validation")]
pub mod input_validator;

// Arabic: وحدة التوكنات JWT (اختيارية)
// English: JWT module (optional)
#[cfg(feature = "jwt")]
pub mod jwt;

// Arabic: وحدة السياسات الأمنية (اختيارية)
// English: Security Policy module (optional)
#[cfg(feature = "validation")]
pub mod policy;

// تم حذف pub mod ratelimit; لأن الملف لم يعد موجودًا

// Arabic: وحدة التواقيع عالية الأمان بدون OpenSSL
// English: High-security signing utilities (no OpenSSL)
pub mod signing;

// Arabic: طبقة تغليف لوحدة الأسرار لتوحيد الاستدعاءات وعزل تغييرات الإصدارات
// English: Secret wrapper layer to unify calls and isolate version changes
pub mod secret;

// Arabic: وحدة توقيع/تحقق JWS اختيارية (Ed25519 + JCS)
// English: Optional JWS sign/verify module (Ed25519 + JCS)
#[cfg(feature = "jws")]
pub mod jws;

// Arabic: حارس الخروج/SSRF اختياري
// English: Optional egress/SSRF guard
#[cfg(feature = "egress")]
pub mod egress_guard;

// Arabic: مزوّد تشفير موحد صفر تبعيات (Trait) مع تنفيذ افتراضي NoCrypto
// English: Unified crypto provider trait (zero‑deps) with default NoCrypto implementation
pub mod crypto_provider;

// Arabic: تشفير ذكي وصارم (واجهات/مخزن مفاتيح/AAD/ظرف) – صفر تبعية
// English: Smart, strict crypto (traits/keystore/AAD/envelope) – zero‑deps
pub mod crypto_smart;

// Arabic: تفتيش صارم ومدقق سلامة (صفر تبعية)
// English: Strict inspector and integrity fingerprint (zero‑deps)
pub mod fingerprint;
pub mod inspection;
pub mod inspection_policy;
