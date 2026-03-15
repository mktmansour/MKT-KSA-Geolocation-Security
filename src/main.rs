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
use mkt_ksa_geo_sec::api;

use actix_web::{web, App, HttpServer};
use config::Config;
use config::Environment;
use maxminddb::Reader;
use mkt_ksa_geo_sec::core::weather_val::{OpenMeteoProvider, WeatherEngine, WeatherProvider};
use mkt_ksa_geo_sec::db::crud;
use mkt_ksa_geo_sec::db::models::User;
use mkt_ksa_geo_sec::security::jwt::JwtManager;
use mkt_ksa_geo_sec::security::ratelimit::RateLimitConfig;
use mkt_ksa_geo_sec::security::ratelimit::RateLimiter;
use mkt_ksa_geo_sec::security::secret::SecureBytes;
use mkt_ksa_geo_sec::security::secret::SecureString;
use rand::RngCore;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

// --- استيراد شامل لجميع المحركات وتبعياتها ---
// --- Comprehensive import of all engines and their dependencies ---
use mkt_ksa_geo_sec::core::behavior_bio::{
    BehaviorEngine, DefaultAnomalyDetector, DefaultBehavioralModel,
};
use mkt_ksa_geo_sec::core::composite_verification::CompositeVerifier;
use mkt_ksa_geo_sec::core::cross_location::{CrossValidationEngine, DefaultScoringStrategy};
use mkt_ksa_geo_sec::core::device_fp::{
    AdaptiveFingerprintEngine, DefaultAiProcessor as FpAiProcessor, DefaultQuantumEngine,
    DefaultSecurityMonitor,
};
use mkt_ksa_geo_sec::core::geo_resolver::{
    DefaultAiModel as GeoAiModel, DefaultBlockchain, GeoResolver,
};
use mkt_ksa_geo_sec::core::network_analyzer::NetworkAnalyzer;
use mkt_ksa_geo_sec::core::sensors_analyzer::SensorsAnalyzerEngine;
// إذا فعّلت النسخة من GitHub استخدم:
// use crate::security::ratelimit::rate_limiter_dynamic;

// ✅ تم حذف mod security::governor_middleware; لأنه غير صحيح في Rust
// ✅ Only use statement kept for GovernorMiddleware

// Arabic: تعريف الحالة المشتركة للتطبيق مع اتصال قاعدة البيانات اختياري
// English: Shared application state with optional database connection
use mkt_ksa_geo_sec::AppState;

fn random_secret_bytes(len: usize) -> SecureBytes {
    let mut bytes = vec![0_u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    SecureBytes::new(bytes)
}

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
    let jwt_secret = settings
        .get_string("JWT_SECRET")
        .expect("JWT_SECRET must be set and at least 32 bytes")
        .trim()
        .to_string();
    if jwt_secret.len() < 32 {
        panic!("JWT_SECRET must be at least 32 bytes");
    }

    // Arabic: إعداد نظام تسجيل الأحداث (سيتم تفعيله بالكامل لاحقًا في utils/logger.rs)
    // English: Setup logging system (will be fully enabled later in utils/logger.rs)
    // env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Arabic: محاولة الحصول على رابط قاعدة البيانات من متغيرات البيئة
    // English: Try to get the database URL from environment variables
    let db_pool: Option<mkt_ksa_geo_sec::app_state::DbPool> = if let Ok(database_url) =
        std::env::var("DATABASE_URL")
    {
        if !database_url.starts_with("sqlite:") {
            panic!("Only SQLite is allowed in hardened profile. Set DATABASE_URL like sqlite://data/app.db");
        }
        let sqlite_path = database_url.trim_start_matches("sqlite://");
        let pool = tokio_rusqlite::Connection::open(sqlite_path)
            .await
            .expect("Failed to connect to SQLite database");

        crud::init_schema(&pool)
            .await
            .expect("Failed to initialize SQLite schema");

        if let Ok(bootstrap_hash) = std::env::var("BOOTSTRAP_ADMIN_PASSWORD_HASH") {
            if !bootstrap_hash.trim().is_empty() {
                let seeded_user = User {
                    id: uuid::Uuid::new_v4(),
                    username: "bootstrap-admin".to_string(),
                    email: "admin@example.local".to_string(),
                    password_hash: bootstrap_hash,
                    status: "active".to_string(),
                    created_at: chrono::Utc::now().naive_utc(),
                    last_login_at: Some(chrono::Utc::now().naive_utc()),
                };
                let _ = crud::upsert_user(&pool, &seeded_user).await;
            } else {
                println!(
                    "⚠️  BOOTSTRAP_ADMIN_PASSWORD_HASH is empty. Skipping bootstrap admin seed."
                );
            }
        }

        Some(pool)
    } else {
        println!("⚠️  DATABASE_URL غير محدد. بعض المسارات التي تتطلب قاعدة بيانات ستعيد 503.");
        None
    };

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
        random_secret_bytes(32),
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
        random_secret_bytes(48),
        Arc::new(mkt_ksa_geo_sec::core::sensors_analyzer::DefaultSensorAnomalyDetector::default()),
    ));

    let proxy_db = Arc::new(RwLock::new(
        mkt_ksa_geo_sec::core::network_analyzer::ProxyDatabase::default(),
    ));
    let network_engine = Arc::new(NetworkAnalyzer::new(
        random_secret_bytes(32),
        proxy_db,
        geo_reader.clone(),
        Arc::new(mkt_ksa_geo_sec::core::network_analyzer::DefaultAiNetworkAnalyzer),
    ));

    let weather_providers: Vec<Arc<dyn WeatherProvider>> = vec![Arc::new(OpenMeteoProvider::new())];
    let weather_engine = Arc::new(WeatherEngine::new(weather_providers));

    let jwt_manager = Arc::new(JwtManager::new(
        &SecureString::new(jwt_secret),
        900,
        "mkt_ksa_geo_sec".to_string(),
        "api_clients".to_string(),
    ));

    let rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 120,
        window: std::time::Duration::from_secs(60),
        whitelist: HashSet::new(),
        blacklist: HashSet::new(),
    });

    // 5. إنشاء محرك التحقق المتقاطع (CrossValidationEngine)
    // 5. Create the cross-validation engine
    let x_engine = Arc::new(CrossValidationEngine::new(
        Arc::clone(&geo_resolver),
        Arc::clone(&fp_engine),
        Arc::clone(&behavior_engine),
        Arc::clone(&sensors_engine),
        Arc::clone(&network_engine),
        scoring_strategy,
        random_secret_bytes(32),
    ));

    // 6. إنشاء محرك التحقق المركب للمدن الذكية
    // 6. Create the composite verifier for smart city access
    let composite_verifier = Arc::new(CompositeVerifier {
        geo: geo_resolver,
        behavior: behavior_engine,
        device_fp: fp_engine,
        network: network_engine,
    });

    // 7. تجميع كل الخدمات في الحالة المشتركة
    // 7. Assemble all services into the shared application state
    let app_state = web::Data::new(AppState {
        x_engine: Arc::clone(&x_engine),
        composite_verifier,
        weather_engine,
        jwt_manager,
        rate_limiter,
        alert_memory: Arc::new(mkt_ksa_geo_sec::app_state::AlertMemoryStore::new(256)),
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
