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

use actix_web::{get, web, HttpResponse, Responder};
// use sqlx::PgPool; // تم التعليق بعد التحويل إلى sea-orm
use uuid::Uuid;

use crate::core::behavior_bio::UserService;

/// نقطة نهاية لجلب بيانات مستخدم معين بناءً على معرفه.
/// Endpoint to fetch a specific user's data by their ID.
/// تطبق فحص الصلاحيات قبل إعادة البيانات.
/// Applies permission checks before returning data.
#[get("/users/{id}")]
pub async fn get_user(
    path: web::Path<Uuid>, // معرف المستخدم المطلوب (من المسار)
                           // Target user ID (from the path)
                           // pool: web::Data<PgPool>,       // الاتصال بقاعدة البيانات
                           // Database connection
) -> impl Responder {
    let target_user_id = path.into_inner();

    // ملاحظة: في التطبيق الحقيقي، يجب استخراج معرف المستخدم من توكن المصادقة (JWT)
    // Note: In a real application, the user ID should be extracted from the authentication token (JWT)
    let requester_id = target_user_id;

    // إنشاء خدمة المستخدمين مع قاعدة البيانات
    // Create the user service with the database connection
    let user_service = UserService::new();

    // محاولة جلب بيانات المستخدم مع فحص الصلاحيات
    // Try to fetch the user profile data with permission checks
    match user_service
        .get_user_profile_data(requester_id, target_user_id)
        .await
    {
        Ok(user) => HttpResponse::Ok().json(user), // إعادة البيانات بنجاح
        // Return user data on success
        Err(e) => {
            // معالجة الأخطاء بشكل بسيط (يفضل تحسينها مستقبلاً)
            // Basic error handling (should be improved in the future)
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}
