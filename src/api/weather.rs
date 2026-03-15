/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: weather.rs
    المسار: src/api/weather.rs

    وظيفة الملف:
    هذا الملف مسؤول عن جميع العمليات المتعلقة بجلب ملخصات الطقس عبر واجهة برمجة التطبيقات (API).
    يوفر نقطة نهاية (Endpoint) لجلب بيانات الطقس بناءً على إحداثيات الموقع (خط العرض والطول)،
    ثم يمررها إلى محرك الطقس في طبقة core (weather_val)، ويعيد النتيجة النهائية بشكل JSON.
    يتحقق من صلاحية المستخدم عبر JWT قبل جلب البيانات، ويضمن أن كل عملية استعلام تتم بشكل آمن وموثوق.
    الملف مصمم ليكون نقطة مركزية لأي نظام خارجي أو واجهة مستخدم ترغب في عرض أو تحليل بيانات الطقس.
    يمكن ربطه مستقبلاً بمحرك طقس حقيقي أو خدمة خارجية.

    File name: weather.rs
    Path: src/api/weather.rs
    File purpose:
    This file is responsible for all operations related to fetching weather summaries via the API.
    It provides an endpoint to fetch weather data based on location coordinates (latitude and longitude),
    then passes them to the weather engine in the core layer (weather_val), and returns the final result as JSON.
    It verifies user authorization via JWT before fetching the data, ensuring every query operation is secure and reliable.
    The file is designed as a central point for any external system or user interface wishing to display or analyze weather data.
    It can be integrated with a real weather engine or external service in the future.
******************************************************************************************/
use crate::api::authorize_request;
use crate::api::BearerToken;
use crate::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;

/// نموذج الطلب لجلب بيانات الطقس.
/// Request model for weather summary.
#[derive(Deserialize)]
pub struct WeatherSummaryRequest {
    pub latitude: f64, // خط العرض للموقع المطلوب
    // Latitude of the requested location
    pub longitude: f64, // خط الطول للموقع المطلوب
                        // Longitude of the requested location
}

/// نقطة نهاية لجلب ملخص الطقس عبر POST /weather/summary
/// Endpoint to get weather summary via POST /weather/summary
#[post("/weather/summary")]
pub async fn weather_summary(
    app_data: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<WeatherSummaryRequest>, // بيانات الطلب (إحداثيات الموقع)
    // Request payload (location coordinates)
    bearer: BearerToken,
) -> impl Responder {
    if let Err(resp) = authorize_request(&app_data, &req, &bearer).await {
        return resp;
    }

    match app_data
        .weather_engine
        .fetch_and_validate(payload.latitude, payload.longitude)
        .await
    {
        Ok(weather) => HttpResponse::Ok().json(weather),
        Err(e) => HttpResponse::BadGateway().json(e.to_string()),
    }
}
