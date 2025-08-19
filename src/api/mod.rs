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
use std::future::{ready, Ready};

// --- وحدات API الفرعية ---
// --- API Sub-modules ---
pub mod alerts;
pub mod auth;
pub mod behavior;
pub mod dashboard;
pub mod device;
pub mod geo;
pub mod network;
pub mod sensors;
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
            .map(|s| s.trim_start_matches("Bearer ").to_string())
            .unwrap_or_default();
        ready(Ok(Self(token)))
    }
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
            .service(dashboard::dashboard_summary)
            .service(weather::weather_summary), // TODO: Register other services from geo, device, etc. here
    );
}
