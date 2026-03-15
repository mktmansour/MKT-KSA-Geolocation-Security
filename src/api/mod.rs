/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     File Name: mod.rs
    Path:      src/api/mod.rs


    File Role:
    هذا الملف هو "موجه المرور" لطبقة الـ API. يقوم بتجميع وتسجيل جميع
    نقاط النهاية (Endpoints) من الوحدات المختلفة (مثل auth, geo, device)
    في مكان واحد، لتقديمها إلى خادم `actix-web` الرئيسي.

    Main Tasks:
    1.  الإعلان عن جميع وحدات API الفرعية.
    2.  توفير دالة `config` واحدة لتسجيل جميع خدمات API.
    --------------------------------------------------------------
    File Name: mod.rs
    Path:      src/api/mod.rs

    File Role:
    This file is the "traffic director" for the API layer. It aggregates and
    registers all endpoints from the different modules (like auth, geo, device)
    in a single place to be served by the main `actix-web` server.

    Main Tasks:
    1.  Declare all API sub-modules.
    2.  Provide a single `config` function to register all API services.
******************************************************************************************/

use actix_web::web;
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use actix_web::HttpResponse;
use zeroize::Zeroize;

use crate::security::jwt::Claims;
use crate::AppState;
use std::future::{ready, Ready};

// --- وحدات API الفرعية ---
// --- API Sub-modules ---
pub mod alerts;
pub mod auth;
pub mod behavior;
pub mod device;
pub mod geo;
pub mod network;
pub mod sensors;
pub mod smart_access;
pub mod weather;

/// Extractor موحّد للحصول على Bearer token من هيدر Authorization
/// Unified extractor to fetch Bearer token from Authorization header
pub struct BearerToken(pub String);

impl FromRequest for BearerToken {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|hv| hv.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_default();
        ready(Ok(Self(token)))
    }
}

pub async fn authorize_request(
    app_state: &web::Data<AppState>,
    req: &HttpRequest,
    bearer: &BearerToken,
) -> Result<Claims, HttpResponse> {
    let ip = req
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
    if app_state.rate_limiter.check(ip).await.is_err() {
        return Err(HttpResponse::TooManyRequests().body("Rate limit exceeded"));
    }

    let mut token = bearer.0.clone();
    if token.is_empty() {
        return Err(HttpResponse::Unauthorized().body("Missing Authorization token"));
    }

    let claims = app_state
        .jwt_manager
        .decode_token(&token)
        .map_err(|_| HttpResponse::Unauthorized().body("Invalid or expired token"));
    token.zeroize();
    claims
}

/// Arabic: تقوم هذه الدالة بتسجيل جميع مسارات API في التطبيق.
/// English: This function registers all API routes in the application.
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(auth::get_user)
            .service(geo::resolve_geo)
            .service(device::resolve_device)
            .service(behavior::analyze_behavior)
            .service(sensors::analyze_sensors)
            .service(network::analyze_network)
            .service(alerts::trigger_alert)
            .service(weather::weather_summary)
            .service(smart_access::smart_access_verify),
    );
}
