/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: behavior.rs
    المسار: src/api/behavior.rs

    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بتحليل سلوك المستخدم أو الجهاز عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) لتحليل السلوك، حيث يستقبل الطلبات التي تحتوي على بيانات سلوكية،
    ثم يمررها إلى محرك التحليل في طبقة core (BehaviorEngine)، ويعيد النتيجة النهائية بشكل JSON.
    يتحقق من صلاحية المستخدم عبر JWT قبل تنفيذ التحليل، ويضمن أن كل عملية تحليل تتم بشكل آمن وموثوق.
    الملف مصمم ليكون نقطة مركزية لأي نظام خارجي أو واجهة مستخدم ترغب في تحليل سلوك المستخدمين أو الأجهزة.

    File name: behavior.rs
    Path: src/api/behavior.rs

    File purpose:
    This file is responsible for all operations related to user or device behavior analysis via the API.
    It provides an endpoint for behavior analysis, receiving requests containing behavioral data,
    then passing them to the analysis engine in the core layer (BehaviorEngine), and returning the final result as JSON.
    It verifies user authorization via JWT before performing the analysis, ensuring every analysis operation is secure and reliable.
    The file is designed as a central point for any external system or user interface wishing to analyze user or device behavior.
******************************************************************************************/
use crate::api::api_error;
use crate::api::authorize_request;
use crate::api::ok_json_with_trace;
use crate::api::parse_json_payload;
use crate::api::BearerToken;
use crate::core::behavior_bio::BehaviorInput;
use crate::AppState;
use actix_web::http::StatusCode;
use actix_web::{post, web, HttpRequest, Responder};
use serde::Deserialize;

/// نموذج الطلب لتحليل السلوك.
/// Request model for behavior analysis.
#[derive(Deserialize)]
pub struct BehaviorAnalyzeRequest {
    pub input: BehaviorInput, // بيانات السلوك المراد تحليلها
                              // Behavioral data to be analyzed
}

/// نقطة نهاية لتحليل السلوك عبر POST /behavior/analyze
/// Endpoint to analyze behavior via POST /behavior/analyze
#[post("/behavior/analyze")]
pub async fn analyze_behavior(
    app_data: web::Data<AppState>,
    req: HttpRequest,
    bearer: BearerToken,
    payload_bytes: web::Bytes,
) -> impl Responder {
    if let Err(resp) = authorize_request(&app_data, &req, &bearer, &payload_bytes).await {
        return resp;
    }

    let payload: BehaviorAnalyzeRequest = match parse_json_payload(&payload_bytes) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // --- تمرير الطلب لمحرك core ---
    let engine = &app_data.x_engine.behavior_engine;
    match engine.process(payload.input.clone()).await {
        Ok(result) => ok_json_with_trace(&req, result), // إعادة نتيجة التحليل بنجاح
        // Return analysis result on success
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BEHAVIOR_ANALYSIS_INTERNAL_ERROR",
            "Internal error while analyzing behavior",
        ),
    }
}
