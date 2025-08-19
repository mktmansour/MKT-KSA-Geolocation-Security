/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: dashboard.rs
    المسار: src/api/dashboard.rs
    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بعرض ملخصات لوحة التحكم عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) لعرض ملخص إحصائي عن النظام (عدد المستخدمين، الأجهزة، التنبيهات، وآخر نوع تنبيه).
    يتحقق من صلاحية المستخدم عبر JWT قبل عرض البيانات، ويعيد النتائج بشكل JSON موحد.
    الملف مصمم ليكون نقطة مركزية لأي نظام خارجي أو لوحة تحكم ترغب في عرض إحصائيات النظام بشكل آمن وموثوق.
    يمكن ربطه مستقبلاً بقاعدة البيانات لجلب الإحصائيات الحقيقية بدلاً من القيم الثابتة.

    File name: dashboard.rs
    Path: src/api/dashboard.rs

    File purpose:
    This file is responsible for all operations related to displaying dashboard summaries via the API.
    It provides an endpoint to show a statistical summary of the system (user count, device count, alert count, and last alert type).
    It verifies user authorization via JWT before displaying the data, and returns the results as a unified JSON response.
    The file is designed as a central point for any external system or dashboard wishing to display system statistics securely and reliably.
    It can be integrated with the database in the future to fetch real statistics instead of static values.
******************************************************************************************/
use crate::api::BearerToken;
use crate::security::jwt::JwtManager;
use actix_web::{get, HttpResponse, Responder};
use serde::Serialize;

/// نموذج الاستجابة لملخص لوحة التحكم.
/// Response model for dashboard summary.
#[derive(Serialize)]
pub struct DashboardSummary {
    pub user_count: usize, // عدد المستخدمين في النظام
    // Number of users in the system
    pub device_count: usize, // عدد الأجهزة المسجلة
    // Number of registered devices
    pub alert_count: usize, // عدد التنبيهات المسجلة
    // Number of registered alerts
    pub last_alert_type: Option<String>, // نوع آخر تنبيه تم تسجيله
                                         // Type of the last registered alert
}

/// نقطة نهاية لعرض ملخص لوحة التحكم عبر GET /dashboard/summary
/// Endpoint to show dashboard summary via GET /dashboard/summary
#[get("/dashboard/summary")]
pub async fn dashboard_summary(bearer: BearerToken) -> impl Responder {
    // --- استخراج التوكن من الهيدر عبر extractor ---
    let token = bearer.0;
    if token.is_empty() {
        return HttpResponse::Unauthorized().body("Missing Authorization token");
    }

    // --- تحقق JWT عبر security فقط ---
    // JWT validation using the security module only
    let jwt_manager = JwtManager::new(
        &crate::security::secret::SecureString::new(
            "a_very_secure_and_long_secret_key_that_is_at_least_32_bytes_long".to_string(),
        ),
        60,
        "my_app".to_string(),
        "user_service".to_string(),
    );
    if jwt_manager.decode_token(&token).is_err() {
        return HttpResponse::Unauthorized().body("Invalid or expired token");
    }

    // --- منطق وهمي للإحصائيات (يمكن ربطه بقاعدة البيانات لاحقًا) ---
    // Dummy logic for statistics (can be connected to the database later)
    let summary = DashboardSummary {
        user_count: 42, // عدد المستخدمين (قيمة ثابتة حالياً)
        // User count (currently static)
        device_count: 17, // عدد الأجهزة (قيمة ثابتة حالياً)
        // Device count (currently static)
        alert_count: 5, // عدد التنبيهات (قيمة ثابتة حالياً)
        // Alert count (currently static)
        last_alert_type: Some("ProxyDetected".to_string()), // نوع آخر تنبيه (قيمة ثابتة)
                                                            // Last alert type (currently static)
    };

    HttpResponse::Ok().json(summary) // إعادة ملخص لوحة التحكم بنجاح
                                     // Return dashboard summary on success
}
