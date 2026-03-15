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

use crate::api::BearerToken;
use crate::api::authorize_request;
use crate::core::network_analyzer::{ConnectionType, NetworkInfoProvider};
use crate::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use std::net::IpAddr;

struct SimpleProvider {
    ip: IpAddr,
    conn_type: ConnectionType,
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
    app_data: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<NetworkAnalyzeRequest>, // بيانات الطلب (تحليل الشبكة)
    // Request payload (network analysis data)
    bearer: BearerToken,
) -> impl Responder {
    if let Err(resp) = authorize_request(&app_data, &req, &bearer).await {
        return resp;
    }

    // --- تمرير الطلب لمحرك core ---
    // Pass the request to the core network analysis engine
    let provider = SimpleProvider {
        ip: payload.ip,
        conn_type: payload.conn_type.clone(),
    };
    let engine = &app_data.x_engine.network_engine;
    match engine.analyze(&provider).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
    }
}
