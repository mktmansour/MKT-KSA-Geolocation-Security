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
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use crate::security::jwt::JwtManager;
use crate::core::weather_val::WeatherData;
use serde::Deserialize;

/// نموذج الطلب لجلب بيانات الطقس.
/// Request model for weather summary.
#[derive(Deserialize)]
pub struct WeatherSummaryRequest {
    pub latitude: f64,      // خط العرض للموقع المطلوب
                           // Latitude of the requested location
    pub longitude: f64,     // خط الطول للموقع المطلوب
                           // Longitude of the requested location
}

/// نقطة نهاية لجلب ملخص الطقس عبر POST /weather/summary
/// Endpoint to get weather summary via POST /weather/summary
#[post("/weather/summary")]
pub async fn weather_summary(
    req: HttpRequest,                  // الطلب الأصلي (للحصول على الهيدر)
    // The original request (to extract headers)
    _payload: web::Json<WeatherSummaryRequest> // بيانات الطلب (إحداثيات الموقع)
    // Request payload (location coordinates)
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
        secrecy::Secret::new("a_very_secure_and_long_secret_key_that_is_at_least_32_bytes_long".to_string()),
        60,
        "my_app".to_string(),
        "user_service".to_string(),
    );
    match jwt_manager.decode_token(&token) {
        Ok(_) => {},
        Err(_) => return HttpResponse::Unauthorized().body("Invalid or expired token"),
    };

    // --- منطق وهمي/اختباري لجلب بيانات الطقس (يمكن ربطه بمحرك الطقس لاحقًا) ---
    // Dummy/test logic for fetching weather data (can be connected to a real weather engine later)
    // في تطبيق حقيقي: استخدم state.x_engine.weather_engine.fetch_and_validate(...)
    // In a real application: use state.x_engine.weather_engine.fetch_and_validate(...)
    let weather = WeatherData {
        temperature_celsius: 23.5,   // درجة الحرارة الحالية (مئوية)
                                    // Current temperature (Celsius)
        humidity_percent: 55.0,      // نسبة الرطوبة
                                    // Humidity percentage
        wind_speed_kmh: 12.0,        // سرعة الرياح (كم/س)
                                    // Wind speed (km/h)
        precipitation_mm: 0.0,       // كمية الهطول (ملم)
                                    // Precipitation (mm)
        weather_code: 1,             // كود حالة الطقس
                                    // Weather condition code
    };

    HttpResponse::Ok().json(weather) // إعادة بيانات الطقس بنجاح
                                    // Return weather data on success
}
