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
******************************************************************************************/

// Legacy Actix-web API modules removed - using std_http instead

pub mod cloud_manager;
pub mod crash_protection;
pub mod performance_monitor;
#[cfg(feature = "api_std_http")]
pub mod std_http;
// Dashboard UI and pages removed for production-grade security; API/Webhook only

// Legacy Actix-web configuration removed - using std_http instead
