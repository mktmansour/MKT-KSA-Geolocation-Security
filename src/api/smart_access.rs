/******************************************************************************************
    🚦 نقطة نهاية التحقق المركب للمدن الذكية MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Smart City Composite Verification API – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: smart_access.rs
    المسار:    src/api/smart_access.rs

    دور الملف:
    - يوفر نقطة نهاية (Endpoint) تحقق مركب للمدن الذكية عبر API.
    - يربط بين AppState و CompositeVerifier.
    - يسمح بتخصيص سياسات المناطق والأوقات بسهولة.

    File name: smart_access.rs
    Path:     src/api/smart_access.rs

    File role:
    - Provides a composite verification endpoint for smart cities via API.
    - Connects AppState and CompositeVerifier.
    - Allows easy customization of zone/time policies.
******************************************************************************************/

use crate::api::api_error;
use crate::api::authorize_request;
use crate::api::parse_json_payload;
use crate::api::BearerToken;
use crate::core::behavior_bio::BehaviorInput;
use crate::AppState;
use actix_web::http::StatusCode;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};

/// Arabic: نموذج الطلب لنقطة نهاية التحقق المركب
/// English: Request model for the composite verification endpoint
#[derive(serde::Deserialize, Clone)]
pub struct SmartAccessRequest {
    pub geo_input: Option<(std::net::IpAddr, (f64, f64, u8, f64))>,
    pub behavior_input: BehaviorInput,
    pub os_info: String,
    pub device_details: String,
    pub env_context: String,
}

/// Arabic: نقطة نهاية تحقق مركب للمدن الذكية
/// English: Smart city composite verification endpoint
#[post("/smart_access/verify")]
pub async fn smart_access_verify(
    data: web::Data<AppState>,
    req: HttpRequest,
    bearer: BearerToken,
    payload_bytes: web::Bytes,
) -> impl Responder {
    if let Err(resp) = authorize_request(&data, &req, &bearer, &payload_bytes).await {
        return resp;
    }

    let payload: SmartAccessRequest = match parse_json_payload(&payload_bytes) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // سياسات المناطق والأوقات (مثال، يمكن تخصيصها)
    let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
    let allowed_hours = Some((6, 18)); // من 6 صباحًا إلى 6 مساءً

    let result = data
        .composite_verifier
        .verify_smart_access(
            payload.geo_input,
            payload.behavior_input.clone(),
            (
                &payload.os_info,
                &payload.device_details,
                &payload.env_context,
            ),
            &allowed_zones,
            allowed_hours,
        )
        .await;

    match result {
        Ok(true) => HttpResponse::Ok().body("Access granted"),
        Ok(false) => api_error(
            StatusCode::FORBIDDEN,
            "SMART_ACCESS_DENIED",
            "Access denied",
        ),
        Err(_) => api_error(
            StatusCode::FORBIDDEN,
            "SMART_ACCESS_POLICY_DENIED",
            "Access denied by policy",
        ),
    }
}
