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

use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use serde::de::DeserializeOwned;
use serde::Serialize;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::security::jwt::Claims;
use crate::security::ratelimit::RateLimitError;
use crate::security::request_guard::{validate_request_framing, RequestFramingError};
use crate::AppState;
use std::future::{ready, Ready};
use std::net::IpAddr;

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

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
    request_id: Option<String>,
}

pub fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> HttpResponse {
    HttpResponse::build(status).json(ApiErrorBody {
        code,
        message,
        request_id: None,
    })
}

pub fn api_error_with_request_id(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    request_id: &str,
) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header(("X-Request-ID", request_id.to_string()))
        .json(ApiErrorBody {
            code,
            message,
            request_id: Some(request_id.to_string()),
        })
}

pub fn parse_json_payload<T: DeserializeOwned>(
    payload_bytes: &web::Bytes,
) -> Result<T, HttpResponse> {
    serde_json::from_slice(payload_bytes).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_JSON_PAYLOAD",
            "Malformed JSON payload",
        )
    })
}

pub fn ok_json_with_trace<T: Serialize>(req: &HttpRequest, data: T) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "trace_id": request_id(req),
        "data": data,
    }))
}

pub fn client_ip(req: &HttpRequest) -> IpAddr {
    let trust_x_forwarded_for = std::env::var("TRUST_X_FORWARDED_FOR")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    if trust_x_forwarded_for {
        return req
            .headers()
            .get("X-Forwarded-For")
            .and_then(|hv| hv.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .or_else(|| req.peer_addr().map(|a| a.ip()))
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    }

    req.peer_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

pub fn request_id(req: &HttpRequest) -> String {
    req.headers()
        .get("X-Request-ID")
        .and_then(|hv| hv.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn log_security_event(req_id: &str, ip: IpAddr, path: &str, code: &str, detail: &str) {
    eprintln!(
        "security_event code={} request_id={} ip={} path={} detail={}",
        code, req_id, ip, path, detail
    );
}

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
    payload_bytes: &web::Bytes,
) -> Result<Claims, HttpResponse> {
    let ip = client_ip(req);
    let req_id = request_id(req);
    let path = req.path();

    if let Err(error) = validate_request_framing(req.headers()) {
        let (code, message) = match error {
            RequestFramingError::AmbiguousContentLength => (
                "AMBIGUOUS_CONTENT_LENGTH",
                "Ambiguous Content-Length headers are not allowed",
            ),
            RequestFramingError::ConflictingMessageFraming => (
                "CONFLICTING_MESSAGE_FRAMING",
                "Content-Length and Transfer-Encoding must not be combined",
            ),
            RequestFramingError::UnsupportedTransferEncoding => (
                "UNSUPPORTED_TRANSFER_ENCODING",
                "Unsupported Transfer-Encoding chain",
            ),
        };
        log_security_event(&req_id, ip, path, code, "request framing rejected");
        return Err(api_error_with_request_id(
            StatusCode::BAD_REQUEST,
            code,
            message,
            &req_id,
        ));
    }

    match app_state.rate_limiter.check(ip).await {
        Ok(()) => {}
        Err(RateLimitError::Blacklisted) => {
            log_security_event(
                &req_id,
                ip,
                path,
                "IP_BLACKLISTED",
                "request rejected by blacklist",
            );
            return Err(api_error_with_request_id(
                StatusCode::FORBIDDEN,
                "IP_BLACKLISTED",
                "Client IP is blocked",
                &req_id,
            ));
        }
        Err(RateLimitError::LimitExceeded) => {
            let retry_after = app_state.rate_limiter.retry_after_seconds(ip).await;
            log_security_event(
                &req_id,
                ip,
                path,
                "RATE_LIMIT_EXCEEDED",
                "request rejected by rate limit",
            );
            return Err(HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
                .insert_header(("Retry-After", retry_after.to_string()))
                .insert_header(("X-Request-ID", req_id.clone()))
                .json(ApiErrorBody {
                    code: "RATE_LIMIT_EXCEEDED",
                    message: "Too many requests",
                    request_id: Some(req_id.clone()),
                }));
        }
    }

    if let Some(expected_api_key) = &app_state.api_key {
        let provided = req
            .headers()
            .get("X-API-Key")
            .and_then(|hv| hv.to_str().ok())
            .map(str::trim)
            .unwrap_or_default();

        if provided.is_empty() {
            log_security_event(
                &req_id,
                ip,
                path,
                "MISSING_API_KEY",
                "request missing X-API-Key header",
            );
            return Err(api_error_with_request_id(
                StatusCode::UNAUTHORIZED,
                "MISSING_API_KEY",
                "Missing API key",
                &req_id,
            ));
        }

        if provided
            .as_bytes()
            .ct_eq(expected_api_key.expose().as_bytes())
            .unwrap_u8()
            == 0
        {
            log_security_event(
                &req_id,
                ip,
                path,
                "INVALID_API_KEY",
                "X-API-Key validation failed",
            );
            return Err(api_error_with_request_id(
                StatusCode::UNAUTHORIZED,
                "INVALID_API_KEY",
                "Invalid API key",
                &req_id,
            ));
        }
    }

    let mut token = bearer.0.clone();
    if token.is_empty() {
        log_security_event(
            &req_id,
            ip,
            path,
            "MISSING_BEARER_TOKEN",
            "missing Authorization bearer token",
        );
        return Err(api_error_with_request_id(
            StatusCode::UNAUTHORIZED,
            "MISSING_BEARER_TOKEN",
            "Missing Authorization token",
            &req_id,
        ));
    }

    let claims = app_state.jwt_manager.decode_token(&token).map_err(|_| {
        log_security_event(
            &req_id,
            ip,
            path,
            "INVALID_OR_EXPIRED_TOKEN",
            "JWT token validation failed",
        );
        api_error_with_request_id(
            StatusCode::UNAUTHORIZED,
            "INVALID_OR_EXPIRED_TOKEN",
            "Invalid or expired token",
            &req_id,
        )
    });
    token.zeroize();
    let claims = claims?;

    let ua = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok());
    let ai_decision = app_state
        .ai_guard
        .evaluate_request(ip, req.path(), ua, payload_bytes)
        .await;
    if ai_decision.blocked {
        let detail = format!(
            "ai_block score={} reasons={}",
            ai_decision.assessment.score,
            ai_decision.assessment.reasons.join("|")
        );
        log_security_event(&req_id, ip, path, "AI_RISK_BLOCKED", &detail);
        let mut builder = HttpResponse::build(StatusCode::FORBIDDEN);
        builder.insert_header(("X-Request-ID", req_id.clone()));
        if let Some(retry_after) = ai_decision.retry_after_seconds {
            builder.insert_header(("Retry-After", retry_after.to_string()));
        }
        return Err(builder.json(serde_json::json!({
            "code": "AI_RISK_BLOCKED",
            "message": "Request blocked by adaptive AI security policy",
            "request_id": req_id,
            "risk_score": ai_decision.assessment.score,
            "reasons": ai_decision.assessment.reasons,
            "retry_after_seconds": ai_decision.retry_after_seconds,
        })));
    }

    Ok(claims)
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
