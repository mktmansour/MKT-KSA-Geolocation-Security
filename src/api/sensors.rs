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
use crate::api::api_error;
use crate::api::authorize_request;
use crate::api::ok_json_with_trace;
use crate::api::parse_json_payload;
use crate::api::BearerToken;
use crate::core::sensors_analyzer::SensorReading;
use crate::AppState;
use actix_web::http::StatusCode;
use actix_web::{post, web, HttpRequest, Responder};
use serde::Deserialize;

/// نموذج الطلب لتحليل بيانات الحساسات.
/// Request model for sensor data analysis.
#[derive(Deserialize)]
pub struct SensorsAnalyzeRequest {
    pub reading: SensorReading, // قراءة الحساس الحالية
    // Current sensor reading
    pub history: Vec<SensorReading>, // تاريخ قراءات الحساسات السابقة
                                     // History of previous sensor readings
}

/// نقطة نهاية لتحليل بيانات الحساسات عبر POST /sensors/analyze
/// Endpoint to analyze sensor data via POST /sensors/analyze
#[post("/sensors/analyze")]
pub async fn analyze_sensors(
    app_data: web::Data<AppState>,
    req: HttpRequest,
    bearer: BearerToken,
    payload_bytes: web::Bytes,
) -> impl Responder {
    if let Err(resp) = authorize_request(&app_data, &req, &bearer, &payload_bytes).await {
        return resp;
    }

    let payload: SensorsAnalyzeRequest = match parse_json_payload(&payload_bytes) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // --- تمرير الطلب لمحرك core ---
    // Pass the request to the core sensor analysis engine
    let engine = &app_data.x_engine.sensors_engine;
    match engine
        .analyze(payload.reading.clone(), &payload.history)
        .await
    {
        Ok(result) => ok_json_with_trace(&req, result), // إعادة نتيجة التحليل بنجاح
        // Return analysis result on success
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SENSORS_ANALYSIS_INTERNAL_ERROR",
            "Internal error while analyzing sensors",
        ),
    }
}
