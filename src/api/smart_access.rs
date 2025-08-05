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

use actix_web::{web, HttpResponse, Responder, post};
use crate::AppState;
use crate::core::behavior_bio::BehaviorInput;
use uuid::Uuid;

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
    payload: web::Json<SmartAccessRequest>,
) -> impl Responder {
    // سياسات المناطق والأوقات (مثال، يمكن تخصيصها)
    let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
    let allowed_hours = Some((6, 18)); // من 6 صباحًا إلى 6 مساءً

    let result = data.composite_verifier.verify_smart_access(
        payload.geo_input.clone(),
        payload.behavior_input.clone(),
        (&payload.os_info, &payload.device_details, &payload.env_context),
        &allowed_zones,
        allowed_hours,
    ).await;

    match result {
        Ok(true) => HttpResponse::Ok().body("Access granted"),
        Ok(false) => HttpResponse::Forbidden().body("Access denied"),
        Err(e) => HttpResponse::Forbidden().body(format!("Access denied: {e}")),
    }
}