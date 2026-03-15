/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: geo.rs
    المسار: src/api/geo.rs

    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بالتحقق الجغرافي وتحليل الموقع عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) للتحقق المتقاطع للموقع، حيث يستقبل الطلبات التي تحتوي على عنوان IP، بيانات GPS، معلومات النظام، تفاصيل الجهاز، وسياق البيئة والسلوك.
    يمرر هذه البيانات إلى محرك التحقق المتقاطع في طبقة core (CrossValidationEngine)، ويعيد النتيجة النهائية بشكل JSON.
    يتحقق من صلاحية المستخدم عبر JWT قبل تنفيذ التحليل، ويضمن أن كل عملية تحقق تتم بشكل آمن وموثوق.
    الملف مصمم ليكون نقطة مركزية لأي نظام خارجي أو واجهة مستخدم ترغب في التحقق من الموقع أو كشف الاحتيال الجغرافي.

    File name: geo.rs
    Path: src/api/geo.rs

    File purpose:
    This file is responsible for all operations related to geolocation validation and analysis via the API.
    It provides an endpoint for cross-location validation, receiving requests containing IP address, GPS data, OS info, device details, environment context, and behavior data.
    It passes this data to the cross-validation engine in the core layer (CrossValidationEngine), and returns the final result as JSON.
    It verifies user authorization via JWT before performing the analysis, ensuring every validation operation is secure and reliable.
    The file is designed as a central point for any external system or user interface wishing to validate location or detect geolocation fraud.
******************************************************************************************/
use crate::api::authorize_request;
use crate::api::BearerToken;
use crate::core::behavior_bio::BehaviorInput;
use crate::core::cross_location::CrossValidationInput;
use crate::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use std::net::IpAddr;

/// نموذج جسم الطلب (Request Body) لنقطة نهاية التحقق.
///
/// يجمع كل البيانات اللازمة من العميل لتشغيل عملية التحليل الكاملة.
/// The request body model for the validation endpoint.
/// It gathers all necessary data from the client to run the full analysis process.
#[derive(Deserialize)]
pub struct GeoResolveRequest {
    pub ip_address: Option<IpAddr>, // عنوان IP (اختياري)
    // IP address (optional)
    pub gps_data: Option<(f64, f64, u8, f64)>, // بيانات GPS (اختياري)
    // GPS data (optional)
    pub os_info: String, // معلومات نظام التشغيل
    // Operating system info
    pub device_details: String, // تفاصيل الجهاز
    // Device details
    pub environment_context: String, // سياق البيئة (شبكة، مكان، ...)
    // Environment context (network, place, ...)
    pub behavior_input: BehaviorInput, // بيانات السلوك
                                       // Behavior data
}

/// نقطة النهاية الرئيسية لحل وتحديد الموقع الجغرافي والتحقق منه عبر POST /geo/resolve
/// The main endpoint for resolving and validating geolocation via POST /geo/resolve
#[post("/geo/resolve")]
pub async fn resolve_geo(
    app_data: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<GeoResolveRequest>, // بيانات الطلب (التحقق الجغرافي)
    // Request payload (geolocation validation data)
    bearer: BearerToken,
) -> impl Responder {
    if let Err(resp) = authorize_request(&app_data, &req, &bearer).await {
        return resp;
    }

    // --- تجميع المدخلات من الطلب ---
    // Collect inputs from the request
    let input = CrossValidationInput {
        ip_address: payload.ip_address, // عنوان IP
        // IP address
        gps_data: payload.gps_data, // بيانات GPS
        // GPS data
        os_info: &payload.os_info, // معلومات نظام التشغيل
        // OS info
        device_details: &payload.device_details, // تفاصيل الجهاز
        // Device details
        environment_context: &payload.environment_context, // سياق البيئة
        // Environment context
        behavior_input: payload.behavior_input.clone(), // بيانات السلوك
                                                        // Behavior data
    };

    // --- تنفيذ التحليل وإرجاع النتيجة ---
    // Execute the analysis and return the result
    let engine = &app_data.x_engine;
    match engine.validate(input).await {
        Ok(result) => HttpResponse::Ok().json(result), // إعادة نتيجة التحقق بنجاح
        // Return validation result on success
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()), // معالجة الخطأ وإرجاعه
                                                                           // Handle and return error
    }
}
