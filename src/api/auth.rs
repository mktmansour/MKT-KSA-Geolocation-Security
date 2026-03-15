/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: auth.rs
    المسار: src/api/auth.rs
    وظيفة الملف:
    هذا الملف مسؤول عن جميع نقاط النهاية (Endpoints) المتعلقة بالمصادقة وإدارة المستخدمين عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية لجلب بيانات مستخدم معين بناءً على معرفه (UUID)، مع تطبيق فحص الصلاحيات.
    يعتمد على خدمة UserService من منطق المشروع (core/behavior_bio) لجلب بيانات المستخدم من قاعدة البيانات.
    حالياً، لا توجد عمليات تسجيل دخول أو تسجيل مستخدم جديدة في هذا الملف، بل يركز فقط على استرجاع بيانات المستخدم.
    الملف مصمم ليكون جزءًا من طبقة API التي تتعامل مع المستخدمين، ويمكن توسيعه مستقبلاً ليشمل عمليات تسجيل الدخول والتسجيل وتحديث بيانات المستخدم.

    File name: auth.rs
    Path: src/api/auth.rs

    File purpose:
    This file is responsible for all API endpoints related to authentication and user management.
    It provides an endpoint to fetch a specific user's data by their UUID, with permission checks.
    It relies on the UserService from the core logic (core/behavior_bio) to retrieve user data from the database.
    Currently, there are no login or registration operations in this file; it focuses only on fetching user data.
    The file is designed as part of the API layer that handles user-related operations, and can be extended in the future to include login, registration, and user data updates.
******************************************************************************************/

use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use uuid::Uuid;

use crate::api::authorize_request;
use crate::db::crud;
use crate::AppState;

/// نقطة نهاية لجلب بيانات مستخدم معين بناءً على معرفه.
/// Endpoint to fetch a specific user's data by their ID.
/// تطبق فحص الصلاحيات قبل إعادة البيانات.
/// Applies permission checks before returning data.
#[get("/users/{id}")]
pub async fn get_user(
    app_data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>, // معرف المستخدم المطلوب (من المسار)
    // Target user ID (from the path)
    bearer: crate::api::BearerToken,
    // pool: web::Data<PgPool>,       // الاتصال بقاعدة البيانات
    // Database connection
) -> impl Responder {
    let target_user_id = path.into_inner();

    let claims = match authorize_request(&app_data, &req, &bearer).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let can_read = claims.sub == target_user_id || claims.roles.iter().any(|r| r == "admin");
    if !can_read {
        return HttpResponse::Forbidden().body("Insufficient permissions");
    }

    let Some(pool) = &app_data.db_pool else {
        return HttpResponse::ServiceUnavailable()
            .body("Database backend is disabled. Configure DATABASE_URL=sqlite://...");
    };

    match crud::get_user_by_id(pool, &target_user_id).await {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => HttpResponse::NotFound().body("User not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("DB error: {e}")),
    }
}
