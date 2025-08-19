/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: sensors.rs
    المسار: src/api/sensors.rs

    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بتحليل بيانات الحساسات عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) لتحليل بيانات الحساسات، حيث يستقبل الطلبات التي تحتوي على قراءة حساسات حالية وتاريخ قراءات سابقة،
    ثم يمررها إلى محرك تحليل الحساسات في طبقة core (SensorsAnalyzerEngine)، ويعيد النتيجة النهائية بشكل JSON.
    يتحقق من صلاحية المستخدم عبر JWT قبل تنفيذ التحليل، ويضمن أن كل عملية تحليل تتم بشكل آمن وموثوق.
    الملف مصمم ليكون نقطة مركزية لأي نظام خارجي أو واجهة مستخدم ترغب في تحليل أو مراقبة بيانات الحساسات (مثل الحركة، الحرارة، الرطوبة، إلخ).

    File name: sensors.rs
    Path: src/api/sensors.rs

    File purpose:
    This file is responsible for all operations related to sensor data analysis via the API.
    It provides an endpoint for sensor data analysis, receiving requests containing a current sensor reading and a history of previous readings,
    then passing them to the sensor analysis engine in the core layer (SensorsAnalyzerEngine), and returning the final result as JSON.
    It verifies user authorization via JWT before performing the analysis, ensuring every analysis operation is secure and reliable.
    The file is designed as a central point for any external system or user interface wishing to analyze or monitor sensor data (such as motion, temperature, humidity, etc.).
******************************************************************************************/
use crate::core::sensors_analyzer::SensorReading;
use crate::security::jwt::JwtManager;
use crate::AppState;
use actix_web::{dev::Payload, FromRequest};
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use std::future::{ready, Ready};

/// نموذج الطلب لتحليل بيانات الحساسات.
/// Request model for sensor data analysis.
#[derive(Deserialize)]
pub struct SensorsAnalyzeRequest {
    pub reading: SensorReading, // قراءة الحساس الحالية
    // Current sensor reading
    pub history: Vec<SensorReading>, // تاريخ قراءات الحساسات السابقة
                                     // History of previous sensor readings
}

// Extractor to obtain Bearer token from Authorization header without capturing HttpRequest in handler
pub struct BearerToken(pub String);

impl FromRequest for BearerToken {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.trim_start_matches("Bearer ").to_string())
            .unwrap_or_default();
        ready(Ok(Self(token)))
    }
}

/// نقطة نهاية لتحليل بيانات الحساسات عبر POST /sensors/analyze
/// Endpoint to analyze sensor data via POST /sensors/analyze
#[post("/sensors/analyze")]
pub async fn analyze_sensors(
    app_data: web::Data<AppState>,
    payload: web::Json<SensorsAnalyzeRequest>,
    bearer: BearerToken,
) -> impl Responder {
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

    // --- تمرير الطلب لمحرك core ---
    // Pass the request to the core sensor analysis engine
    let engine = &app_data.x_engine.sensors_engine;
    match engine
        .analyze(payload.reading.clone(), &payload.history)
        .await
    {
        Ok(result) => HttpResponse::Ok().json(result), // إعادة نتيجة التحليل بنجاح
        // Return analysis result on success
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()), // معالجة الخطأ وإرجاعه
                                                                           // Handle and return error
    }
}
