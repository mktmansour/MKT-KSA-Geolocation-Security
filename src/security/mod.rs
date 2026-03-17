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
pub mod input_validator;

// Arabic: وحدة التوكنات JWT
// English: JWT module
pub mod jwt;

// Arabic: وحدة السياسات الأمنية
// English: Security Policy module
pub mod policy;

// Arabic: وحدة تحديد معدل الطلبات
// English: Rate limiting module
pub mod ratelimit;

// Arabic: وحدة التواقيع عالية الأمان بدون OpenSSL
// English: High-security signing utilities (no OpenSSL)
pub mod signing;

// Arabic: طبقة تغليف لوحدة الأسرار لتوحيد الاستدعاءات وعزل تغييرات الإصدارات
// English: Secret wrapper layer to unify calls and isolate version changes
pub mod secret;

// Arabic: طبقة حراسة ذكية مدعومة بقواعد AI heuristic
// English: AI-assisted adaptive request guard
pub mod ai_guard;
