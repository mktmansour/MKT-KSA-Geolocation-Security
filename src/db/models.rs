/******************************************************************************************
          📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.


    File Name: models.rs
    Path:     src/db/models.rs


    File Role:
    يحتوي هذا الملف على تعريفات هياكل البيانات (structs) التي تمثل الجداول
    في قاعدة البيانات. تعمل هذه النماذج كوسيط بين كود Rust وقاعدة بيانات PostgreSQL،
    مما يسمح بقراءة وكتابة البيانات بشكل آمن ومنظم باستخدام `sqlx`.

    Main Tasks:
    1. تعريف نماذج البيانات للجداول الرئيسية (Device, LocationRecord, etc.).
    2. استخدام `derive macros` من `sqlx` و`serde` للربط التلقائي.
    3. توثيق كل حقل لضمان وضوح مخطط قاعدة البيانات.

    --------------------------------------------------------------

    File Name: models.rs
    Path:     src/db/models.rs


    File Role:
    This file contains the struct definitions that represent tables in the database.
    These models act as an intermediary between the Rust code and the PostgreSQL database,
    allowing for safe and structured data reading and writing using `sqlx`.

    Main Tasks:
    1. Define data models for the main tables (Device, LocationRecord, etc.).
    2. Use `derive macros` from `sqlx` and `serde` for automatic binding.
    3. Document each field to ensure clarity of the database schema.
******************************************************************************************/

use serde::{Deserialize, Serialize};

// ===================== نماذج البيانات الأساسية =====================
// ===================== Core Data Models =====================

/// Arabic: يمثل مستخدمًا مسجلاً في النظام. هذا النموذج هو حجر الأساس للمصادقة والصلاحيات.
///
/// English: Represents a registered user in the system. This model is the cornerstone of authentication and authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub status: String,
    pub created_at: chrono::NaiveDateTime,
    /// آخر وقت دخول ناجح للمستخدم (يتم تحديثه تلقائيًا عند تسجيل الدخول)
    /// Last successful login time (auto-updated on login)
    pub last_login_at: Option<chrono::NaiveDateTime>,
}

/// Arabic: يمثل جهازًا مسجلاً في النظام. كل جهاز له هوية فريدة خاصة به.
/// English: Represents a registered device in the system. Each device has its own unique identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub device_fingerprint: String,
    pub friendly_name: String,
    pub metadata: serde_json::Value,
    pub created_at: chrono::NaiveDateTime,
}

/// Arabic: يمثل سجلاً لموقع جغرافي تم التحقق منه وتوقيعه.
/// هذا النموذج هو أساس "البصمة الوراثية للبيانات".
///
/// English: Represents a verified and signed geographic location record.
/// This model is the foundation of the "Data Genetic Fingerprint".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationRecord {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: f32,
    pub metadata: serde_json::Value,
    pub created_at: chrono::NaiveDateTime,
}

/// Arabic: يمثل حدثًا سلوكيًا تم تسجيله لأغراض التحليل والتدقيق.
/// English: Represents a behavioral event logged for analysis and auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvent {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub created_at: chrono::NaiveDateTime,
}

/// Arabic: يمثل تنبيهًا أمنيًا تم إطلاقه بواسطة النظام وتوقيعه.
/// التوقيع يثبت أن التنبيه صادر من نظامنا وليس تنبيهًا زائفًا تم حقنه.
///
/// English: Represents a security alert triggered and signed by the system.
/// The signature proves the alert originated from our system and is not a fake injected alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub alert_type: String,
    pub alert_data: serde_json::Value,
    pub created_at: chrono::NaiveDateTime,
}

// Models are backend-agnostic and currently used by the hardened SQLite path.
