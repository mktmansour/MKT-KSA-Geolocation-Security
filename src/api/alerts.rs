/******************************************************************************************
     📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: alerts.rs
    المسار: src/api/alerts.rs

    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بتنبيهات الأمان عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) لإطلاق التنبيهات الأمنية من الأنظمة الخارجية أو واجهات المستخدم.
    عند استقبال طلب تنبيه، يتحقق من صلاحية المستخدم عبر JWT، ثم يبني نموذج التنبيه ويوقعه رقمياً (توقيع وهمي حالياً)،
    ويعيد استجابة JSON تحتوي على حالة العملية وبيانات التنبيه.
    الملف مصمم ليكون نقطة مركزية لإدارة التنبيهات الأمنية، ويمكن ربطه مستقبلاً بقاعدة البيانات أو أنظمة إشعار خارجية.

    File name: alerts.rs
    Path: src/api/alerts.rs

    File purpose:
    This file is responsible for all operations related to security alerts via the API.
    It provides an endpoint for triggering security alerts from external systems or user interfaces.
    Upon receiving an alert request, it verifies user authorization via JWT, constructs and (dummy) signs the alert model,
    and returns a JSON response with the operation status and alert data.
    The file is designed as a central point for managing security alerts, and can be integrated with a database or external notification systems in the future.
******************************************************************************************/
use crate::api::authorize_request;
use crate::api::BearerToken;
use crate::db::crud;
use crate::db::models::SecurityAlert;
use crate::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

/// نموذج الطلب لإطلاق التنبيه (يحدد الكيانات ونوع التنبيه والتفاصيل)
/// Request model for triggering an alert (specifies entities, alert type, and details)
#[derive(Deserialize)]
pub struct AlertTriggerRequest {
    pub entity_id: Uuid, // معرف الكيان المرتبط بالتنبيه (مثلاً مستخدم أو جهاز)
    // The entity ID related to the alert (e.g., user or device)
    pub entity_type: String, // نوع الكيان (مستخدم، جهاز، خدمة...)
    // Type of entity (user, device, service, etc.)
    pub alert_type: String, // نوع التنبيه (اختراق، محاولة دخول، إلخ)
    // Alert type (breach, login attempt, etc.)
    pub severity: String, // درجة الخطورة (عالي، متوسط، منخفض)
    // Severity level (high, medium, low)
    pub details: serde_json::Value, // تفاصيل إضافية (JSON)
                                    // Additional details (JSON)
}

/// نقطة نهاية لإطلاق التنبيه الأمني عبر POST /alerts/trigger
#[post("/alerts/trigger")]
pub async fn trigger_alert(
    app_data: web::Data<AppState>,
    req: HttpRequest,
    bearer: BearerToken,
    payload_bytes: web::Bytes,
) -> impl Responder {
    if let Err(resp) = authorize_request(&app_data, &req, &bearer).await {
        return resp;
    }

    let payload: AlertTriggerRequest = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid JSON payload: {e}")),
    };

    // --- بناء نموذج التنبيه ---
    // Build the alert model
    let alert = SecurityAlert {
        id: Uuid::new_v4(),
        user_id: payload.entity_id, // معرف الكيان المرتبط
        // Related entity ID
        alert_type: payload.alert_type.clone(), // نوع التنبيه
        // Alert type
        alert_data: json!({
            "entity_type": payload.entity_type,
            "severity": payload.severity,
            "details": payload.details,
        }), // تفاصيل إضافية
        // Additional details
        created_at: chrono::Utc::now().naive_utc(), // وقت الإنشاء
                                                    // Creation time
    };

    app_data.alert_memory.push(alert.alert_type.clone()).await;
    if let Some(pool) = &app_data.db_pool {
        if let Err(e) = crud::create_security_alert(pool, &alert).await {
            return HttpResponse::InternalServerError()
                .json(format!("Failed to persist alert: {e}"));
        }
    }
    // --- إرجاع استجابة JSON موحدة ---
    // Return a unified JSON response
    HttpResponse::Ok().json(json!({
        "status": "alert_triggered",
        "alert": alert
    }))
}
