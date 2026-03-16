/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: device.rs
    المسار: src/api/device.rs

    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بتحليل بصمة الجهاز عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) لتحليل بصمة الجهاز، حيث يستقبل الطلبات التي تحتوي على بيانات نظام التشغيل، معلومات الجهاز، وبيانات البيئة،
    ثم يمررها إلى محرك التحليل في طبقة core (AdaptiveFingerprintEngine)، ويعيد النتيجة النهائية بشكل JSON.
    يتحقق من صلاحية المستخدم عبر JWT قبل تنفيذ التحليل، ويضمن أن كل عملية تحليل تتم بشكل آمن وموثوق.
    الملف مصمم ليكون نقطة مركزية لأي نظام خارجي أو واجهة مستخدم ترغب في تحليل أو التحقق من بصمة الأجهزة.

    File name: device.rs
    Path: src/api/device.rs

    File purpose:
    This file is responsible for all operations related to device fingerprint analysis via the API.
    It provides an endpoint for device fingerprint analysis, receiving requests containing OS data, device info, and environment data,
    then passing them to the analysis engine in the core layer (AdaptiveFingerprintEngine), and returning the final result as JSON.
    It verifies user authorization via JWT before performing the analysis, ensuring every analysis operation is secure and reliable.
    The file is designed as a central point for any external system or user interface wishing to analyze or verify device fingerprints.
******************************************************************************************/
use crate::api::authorize_request;
use crate::api::BearerToken;
use crate::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;

/// نموذج الطلب لتحليل بصمة الجهاز.
/// Request model for device fingerprint analysis.
#[derive(Deserialize)]
pub struct DeviceResolveRequest {
    pub os: String, // نظام التشغيل للجهاز
    // Device operating system
    pub device_info: String, // معلومات الجهاز (موديل، نوع...)
    // Device information (model, type, ...)
    pub environment_data: String, // بيانات البيئة (شبكة، موقع، إلخ)
                                  // Environment data (network, location, etc.)
}

/// نقطة نهاية لحل بصمة الجهاز عبر POST /device/resolve
/// Endpoint to resolve device fingerprint via POST /device/resolve
#[post("/device/resolve")]
pub async fn resolve_device(
    app_data: web::Data<AppState>,
    req: HttpRequest,
    bearer: BearerToken,
    payload_bytes: web::Bytes,
) -> impl Responder {
    if let Err(resp) = authorize_request(&app_data, &req, &bearer).await {
        return resp;
    }

    let payload: DeviceResolveRequest = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid JSON payload: {e}")),
    };

    // --- تمرير الطلب لمحرك core ---
    let engine = &app_data.x_engine.fp_engine;
    match engine
        .generate_fingerprint(&payload.os, &payload.device_info, &payload.environment_data)
        .await
    {
        Ok(result) => HttpResponse::Ok().json(result), // إعادة نتيجة التحليل بنجاح
        // Return analysis result on success
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()), // معالجة الخطأ وإرجاعه
                                                                           // Handle and return error
    }
}
