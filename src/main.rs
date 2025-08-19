#![allow(clippy::multiple_crate_versions)]
/******************************************************************************************
       📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.


    File Name: main.rs
    Path:      src/main.rs


    File Role:
    نقطة الدخول الرئيسية للتطبيق. هذا الملف مسؤول عن تهيئة وإطلاق الخادم،
    إعداد الاتصال بقاعدة البيانات، تحميل الإعدادات، وتسجيل مسارات API.
    إنه "المنظم" الذي يجمع كل أجزاء المشروع معًا.

    Main Tasks:
    1.  إعداد وتشغيل خادم `actix-web`.
    2.  تحميل متغيرات البيئة باستخدام `dotenv`.
    3.  إنشاء مجمع اتصالات قاعدة البيانات (`PgPool`) ومشاركته.
    4.  تسجيل وحدات المشروع الرئيسية (`api`, `core`, etc.).

    --------------------------------------------------------------

    File Name: main.rs
    Path:      src/main.rs


    File Role:
    The main entry point for the application. This file is responsible for initializing
    and launching the server, setting up the database connection, loading configurations,
    and registering API routes. It is the "orchestrator" that brings all project
    parts together.
******************************************************************************************/

// Arabic: استخدام وحدات المكتبة العامة بدل تضمينها في الثنائي
// English: Use library modules instead of re-declaring them in the bin target
use mkt_ksa_geo_sec as lib;
use mkt_ksa_geo_sec::{api, core, db, security, utils};

use actix_web::{web, App, HttpServer};
use config::Config;
use config::Environment;
use maxminddb::Reader;
use mysql_async::Pool;
use secrecy::SecretVec;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// --- استيراد شامل لجميع المحركات وتبعياتها ---
// --- Comprehensive import of all engines and their dependencies ---
use mkt_ksa_geo_sec::core::behavior_bio::{BehaviorEngine, DefaultAnomalyDetector, DefaultBehavioralModel};
use mkt_ksa_geo_sec::core::cross_location::{CrossValidationEngine, DefaultScoringStrategy};
use mkt_ksa_geo_sec::core::device_fp::{
    AdaptiveFingerprintEngine, DefaultAiProcessor as FpAiProcessor, DefaultQuantumEngine,
    DefaultSecurityMonitor,
};
use mkt_ksa_geo_sec::core::geo_resolver::{DefaultAiModel as GeoAiModel, DefaultBlockchain, GeoResolver};
use mkt_ksa_geo_sec::core::network_analyzer::NetworkAnalyzer;
use mkt_ksa_geo_sec::core::sensors_analyzer::SensorsAnalyzerEngine;
// إذا فعّلت النسخة من GitHub استخدم:
// use crate::security::ratelimit::rate_limiter_dynamic;

// ✅ تم حذف mod security::governor_middleware; لأنه غير صحيح في Rust
// ✅ Only use statement kept for GovernorMiddleware

// Arabic: تعريف الحالة المشتركة للتطبيق مع اتصال قاعدة البيانات اختياري
// English: Shared application state with optional database connection
use mkt_ksa_geo_sec::AppState;

// Arabic: نقطة الدخول الرئيسية للتطبيق
// English: Main entry point for the application
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // تحميل الإعدادات من متغيرات البيئة باستخدام config (الإصدار الحديث)
    let settings = Config::builder()
        .add_source(Environment::default())
        .build()
        .expect("Failed to build configuration from environment");
    let _api_key: String = settings.get_string("API_KEY").expect("API_KEY not set");

    // Arabic: إعداد نظام تسجيل الأحداث (سيتم تفعيله بالكامل لاحقًا في utils/logger.rs)
    // English: Setup logging system (will be fully enabled later in utils/logger.rs)
    // env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Arabic: محاولة الحصول على رابط قاعدة البيانات من متغيرات البيئة
    // English: Try to get the database URL from environment variables
    let database_url = std::env::var("DATABASE_URL").ok();
    // Arabic: تهيئة اتصال قاعدة البيانات بشكل متكيف
    // English: Adaptively initialize the database connection
    let db_pool = database_url.map_or_else(
        || {
            println!(
                "⚠️  لم يتم ضبط DATABASE_URL. سيعمل التطبيق في وضع التطوير (بدون قاعدة بيانات)."
            );
            None
        },
        |url| {
            let opts = mysql_async::Opts::from_url(&url)
                .map_err(|_| ())
                .expect("Invalid DATABASE_URL format for mysql_async");
            Some(Pool::new(opts))
        },
    );

    // Arabic: تهيئة المحركات والخدمات المشتركة فقط إذا كان التطبيق في وضع الإنتاج
    // English: Initialize engines/services only if not in development mode
    println!("🔧 Initializing application engines...");

    // Arabic: إذا كان التطبيق في وضع التطوير، استخدم كائن وهمي لقاعدة بيانات MaxMind عبر Enum موحد
    // English: In development mode, use a mock geo DB reader via unified enum
    let geo_reader: Arc<mkt_ksa_geo_sec::core::geo_resolver::GeoReaderEnum> = if db_pool.is_some() {
        let geo_db_bytes = hex::decode("4d4d44425f434954590000000000000002000000000000000c000000636f756e747279000700000049534f5f434f44450000").expect("Failed to decode mock geo DB");
        Arc::new(mkt_ksa_geo_sec::core::geo_resolver::GeoReaderEnum::Real(
            Reader::from_source(geo_db_bytes).expect("Failed to create geo DB reader"),
        ))
    } else {
        println!(
            "[DEV MODE] لن يتم تحميل قاعدة بيانات MaxMind geo DB. سيتم استخدام كائن وهمي عبر Enum."
        );
        Arc::new(mkt_ksa_geo_sec::core::geo_resolver::GeoReaderEnum::Mock(
            mkt_ksa_geo_sec::core::geo_resolver::MockGeoReader::new(),
        ))
    };

    let geo_resolver = Arc::new(GeoResolver::new(
        SecretVec::new(vec![1; 32]),
        Arc::new(GeoAiModel),
        Arc::new(DefaultBlockchain),
        true,
        false,
        geo_reader.clone(),
    ));

    // 2. إنشاء محرك DeviceFPEngine
    let fp_engine = Arc::new(AdaptiveFingerprintEngine::new(
        Arc::new(DefaultSecurityMonitor::new()),
        Arc::new(DefaultQuantumEngine::new().expect("Failed to create quantum engine")),
        Arc::new(FpAiProcessor),
        Arc::new(RwLock::new(HashMap::new())),
    ));

    // 3. إنشاء محرك BehaviorEngine
    let behavior_engine = Arc::new(BehaviorEngine::new(
        Arc::new(DefaultBehavioralModel),
        Arc::new(DefaultAnomalyDetector {
            max_speed_kmh: 1200.0,
        }),
        10,
    ));

    // 4. إنشاء استراتيجية حساب النقاط
    let scoring_strategy = Arc::new(DefaultScoringStrategy {
        location_weight: 0.4,
        fingerprint_weight: 0.3,
        behavior_weight: 0.3,
    });

    let sensors_engine = Arc::new(SensorsAnalyzerEngine::new(
        SecretVec::new(vec![42; 48]),
        Arc::new(mkt_ksa_geo_sec::core::sensors_analyzer::DefaultSensorAnomalyDetector::default()),
    ));

    let proxy_db = Arc::new(RwLock::new(
        mkt_ksa_geo_sec::core::network_analyzer::ProxyDatabase::default(),
    ));
    let network_engine = Arc::new(NetworkAnalyzer::new(
        SecretVec::new(vec![42; 32]),
        proxy_db,
        geo_reader.clone(),
        Arc::new(mkt_ksa_geo_sec::core::network_analyzer::DefaultAiNetworkAnalyzer),
    ));

    let x_engine = Arc::new(CrossValidationEngine::new(
        geo_resolver,
        fp_engine,
        behavior_engine,
        sensors_engine,
        network_engine,
        scoring_strategy,
        SecretVec::new(b"a_very_secret_final_verdict_key".to_vec()),
    ));

    // 6. تجميع كل الخدمات في الحالة المشتركة
    let app_state = web::Data::new(AppState {
        x_engine: Arc::clone(&x_engine),
        db_pool,
    });

    println!("✅ Engines initialized successfully.");
    println!("🚀 Server starting at http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            // Arabic: مشاركة الحالة الكاملة للتطبيق مع جميع المسارات
            // English: Share the full application state with all routes
            .app_data(app_state.clone())
            // Arabic: تفعيل درع تحديد المعدل الذكي باستخدام governor (pure Rust)
            // English: Enable smart rate limiting shield using governor (pure Rust)
            // .wrap(GovernorMiddleware::new(60, 60)) // This line is removed as per the edit hint
            // Arabic: تسجيل إعدادات واجهة برمجة التطبيقات
            // English: Register API configurations
            .configure(api::config)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
