/******************************************************************************************
    📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: network.rs
    المسار: src/api/network.rs

    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بتحليل الشبكة عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) لتحليل الشبكة، حيث يستقبل الطلبات التي تحتوي على عنوان IP ونوع الاتصال (WiFi، Ethernet، إلخ)،
    ثم يمررها إلى محرك تحليل الشبكة في طبقة core (NetworkAnalyzer)، ويعيد النتيجة النهائية بشكل JSON.
    يتحقق من صلاحية المستخدم عبر JWT قبل تنفيذ التحليل، ويضمن أن كل عملية تحليل تتم بشكل آمن وموثوق.
    الملف مصمم ليكون نقطة مركزية لأي نظام خارجي أو واجهة مستخدم ترغب في تحليل أو مراقبة حالة الشبكة أو كشف البروكسي/الـ VPN.

    File name: network.rs
    Path: src/api/network.rs
    File purpose:
    This file is responsible for all operations related to network analysis via the API.
    It provides an endpoint for network analysis, receiving requests containing IP address and connection type (WiFi, Ethernet, etc.),
    then passing them to the network analysis engine in the core layer (NetworkAnalyzer), and returning the final result as JSON.
    It verifies user authorization via JWT before performing the analysis, ensuring every analysis operation is secure and reliable.
    The file is designed as a central point for any external system or user interface wishing to analyze or monitor network status or detect proxies/VPNs.
******************************************************************************************/
use crate::core::network_analyzer::{ConnectionType, NetworkInfoProvider};
use crate::security::jwt::JwtManager;
use crate::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use std::net::IpAddr;

/// نموذج الطلب لتحليل الشبكة.
/// Request model for network analysis.
#[derive(Deserialize)]
pub struct NetworkAnalyzeRequest {
    pub ip: IpAddr, // عنوان IP المراد تحليله
    // IP address to be analyzed
    pub conn_type: ConnectionType, // نوع الاتصال (WiFi، Ethernet، ...)
                                   // Connection type (WiFi, Ethernet, ...)
}

/// نقطة نهاية لتحليل الشبكة عبر POST /network/analyze
/// Endpoint to analyze network via POST /network/analyze
#[post("/network/analyze")]
pub async fn analyze_network(
    req: HttpRequest, // الطلب الأصلي (للحصول على الهيدر)
    // The original request (to extract headers)
    payload: web::Json<NetworkAnalyzeRequest>, // بيانات الطلب (تحليل الشبكة)
                                               // Request payload (network analysis data)
) -> impl Responder {
    // --- استخراج التوكن من الهيدر ---
    // Extract the token from the header
    let token = match req.headers().get("Authorization") {
        Some(hv) => hv.to_str().unwrap_or("").replace("Bearer ", ""),
        None => String::new(),
    };
    if token.is_empty() {
        return HttpResponse::Unauthorized().body("Missing Authorization token");
    }

    // --- تحقق JWT عبر security فقط ---
    // JWT validation using the security module only
    let jwt_manager = JwtManager::new(
        secrecy::Secret::new(
            "a_very_secure_and_long_secret_key_that_is_at_least_32_bytes_long".to_string(),
        ),
        60,
        "my_app".to_string(),
        "user_service".to_string(),
    );
    match jwt_manager.decode_token(&token) {
        Ok(_) => {}
        Err(_) => return HttpResponse::Unauthorized().body("Invalid or expired token"),
    };

    // --- تمرير الطلب لمحرك core ---
    // Pass the request to the core network analysis engine
    struct SimpleProvider {
        ip: IpAddr, // عنوان IP
        // IP address
        conn_type: ConnectionType, // نوع الاتصال
                                   // Connection type
    }
    #[async_trait::async_trait]
    impl NetworkInfoProvider for SimpleProvider {
        async fn get_connection_type(&self) -> ConnectionType {
            self.conn_type.clone()
        }
        async fn get_public_ip(&self) -> Option<IpAddr> {
            Some(self.ip)
        }
    }
    let provider = SimpleProvider {
        ip: payload.ip,
        conn_type: payload.conn_type.clone(),
    };
    let engine = &req
        .app_data::<web::Data<AppState>>()
        .unwrap()
        .x_engine
        .network_engine;
    match engine.analyze(&provider).await {
        Ok(result) => HttpResponse::Ok().json(result), // إعادة نتيجة التحليل بنجاح
        // Return analysis result on success
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()), // معالجة الخطأ وإرجاعه
                                                                           // Handle and return error
    }
}
