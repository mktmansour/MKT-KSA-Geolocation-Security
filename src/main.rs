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

use actix_web::{
    dev::Service,
    http::header::{HeaderName, HeaderValue},
    http::KeepAlive,
    middleware::DefaultHeaders,
    web, App, HttpServer,
};
use config::Config;
use config::Environment;
use maxminddb::Reader;
use mkt_ksa_geo_sec::core::weather_val::{OpenMeteoProvider, WeatherEngine, WeatherProvider};
use mkt_ksa_geo_sec::db::crud;
use mkt_ksa_geo_sec::db::models::User;
use mkt_ksa_geo_sec::security::ai_guard::AiGuardConfig;
use mkt_ksa_geo_sec::security::ai_guard::RequestAiGuard;
use mkt_ksa_geo_sec::security::jwt::JwtManager;
use mkt_ksa_geo_sec::security::ratelimit::RateLimitConfig;
use mkt_ksa_geo_sec::security::ratelimit::RateLimiter;

/// Build the default fingerprint environment profiles map.
///
/// This centralizes the default configuration for the different device
/// categories (mobile, desktop, IoT, server) so that it can be reused
/// consistently from a single place.
fn build_default_fp_env_profiles(
) -> std::collections::HashMap<String, mkt_ksa_geo_sec::core::device_fp::EnvironmentProfile> {
    let mut fp_env_profiles = std::collections::HashMap::<
        String,
        mkt_ksa_geo_sec::core::device_fp::EnvironmentProfile,
    >::new();

    fp_env_profiles.insert(
        "mobile".to_string(),
        mkt_ksa_geo_sec::core::device_fp::EnvironmentProfile {
            os_type: "Mobile".to_string(),
            device_category: "Phone/Tablet".to_string(),
            threat_level: 6,
            resource_constraints: mkt_ksa_geo_sec::core::device_fp::ResourceConstraints {
                max_memory_kb: 512,
                max_processing_us: 5_000,
            },
        },
    );

    fp_env_profiles.insert(
        "desktop".to_string(),
        mkt_ksa_geo_sec::core::device_fp::EnvironmentProfile {
            os_type: "Desktop".to_string(),
            device_category: "PC/Workstation".to_string(),
            threat_level: 4,
            resource_constraints: mkt_ksa_geo_sec::core::device_fp::ResourceConstraints {
                max_memory_kb: 2_048,
                max_processing_us: 10_000,
            },
        },
    );

    fp_env_profiles.insert(
        "iot".to_string(),
        mkt_ksa_geo_sec::core::device_fp::EnvironmentProfile {
            os_type: "IoT".to_string(),
            device_category: "Embedded".to_string(),
            threat_level: 7,
            resource_constraints: mkt_ksa_geo_sec::core::device_fp::ResourceConstraints {
                max_memory_kb: 256,
                max_processing_us: 4_000,
            },
        },
    );

    fp_env_profiles.insert(
        "server".to_string(),
        mkt_ksa_geo_sec::core::device_fp::EnvironmentProfile {
            os_type: "Server".to_string(),
            device_category: "Datacenter Node".to_string(),
            threat_level: 8,
            resource_constraints: mkt_ksa_geo_sec::core::device_fp::ResourceConstraints {
                max_memory_kb: 8_192,
                max_processing_us: 15_000,
            },
        },
    );

    fp_env_profiles
}
use mkt_ksa_geo_sec::security::secret::SecureBytes;
use mkt_ksa_geo_sec::security::secret::SecureString;
use rand_core::OsRng;
use rand_core::RngCore;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    OsRng.fill_bytes(&mut bytes);
    SecureBytes::new(bytes)
}

fn env_u8_or_default(name: &str, default: u8) -> u8 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u8>().ok())
        .unwrap_or(default)
}

fn env_u64_or_default(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u32_or_default(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn env_usize_or_default(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn io_invalid_input(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message.into())
}

fn io_invalid_data(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidData, message.into())
}

// Arabic: نقطة الدخول الرئيسية للتطبيق
// English: Main entry point for the application
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // تحميل الإعدادات من متغيرات البيئة باستخدام config (الإصدار الحديث)
    let settings = Config::builder()
        .add_source(Environment::default())
        .build()
        .map_err(|e| {
            io_invalid_input(format!(
                "Failed to build configuration from environment: {e}"
            ))
        })?;

    let security_profile = std::env::var("SECURITY_PROFILE")
        .unwrap_or_else(|_| "strict".to_string())
        .to_lowercase();
    let ultra_strict = matches!(
        security_profile.as_str(),
        "ultra" | "ultra-strict" | "paranoid"
    );

    let default_rate_limit = if ultra_strict { 60 } else { 120 };
    let default_ai_threshold = if ultra_strict { 55 } else { 70 };
    let default_payload_bytes = if ultra_strict { 32 * 1024 } else { 64 * 1024 };
    let default_ai_base_block = if ultra_strict { 60 } else { 20 };
    let default_ai_max_block = if ultra_strict { 1800 } else { 900 };
    let default_ai_burst_soft_limit = if ultra_strict { 18 } else { 28 };
    let default_ai_burst_hard_limit = if ultra_strict { 42 } else { 72 };
    // Prefer direct environment reads for runtime-critical secrets, then fallback to config map keys.
    let api_key: String = std::env::var("API_KEY")
        .or_else(|_| settings.get_string("API_KEY"))
        .or_else(|_| settings.get_string("api_key"))
        .map_err(|_| io_invalid_input("API_KEY not set"))?
        .trim()
        .to_string();
    let min_api_key_len = if ultra_strict { 32 } else { 16 };
    if api_key.len() < min_api_key_len {
        return Err(io_invalid_input(format!(
            "API_KEY must be at least {min_api_key_len} characters in profile '{security_profile}'"
        )));
    }
    let jwt_secret = std::env::var("JWT_SECRET")
        .or_else(|_| settings.get_string("JWT_SECRET"))
        .or_else(|_| settings.get_string("jwt_secret"))
        .map_err(|_| io_invalid_input("JWT_SECRET must be set and at least 32 bytes"))?
        .trim()
        .to_string();
    if jwt_secret.len() < 32 {
        return Err(io_invalid_input("JWT_SECRET must be at least 32 bytes"));
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
            return Err(io_invalid_input(
                "Only SQLite is allowed in hardened profile. Set DATABASE_URL like sqlite://data/app.db",
            ));
        }
        let sqlite_path = database_url.trim_start_matches("sqlite://");
        let pool = tokio_rusqlite::Connection::open(sqlite_path)
            .await
            .map_err(|e| io_invalid_input(format!("Failed to connect to SQLite database: {e}")))?;

        crud::init_schema(&pool)
            .await
            .map_err(|e| io_invalid_data(format!("Failed to initialize SQLite schema: {e}")))?;

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

    if ultra_strict && db_pool.is_none() {
        return Err(io_invalid_input(
            "DATABASE_URL is required in ultra-strict profile",
        ));
    }

    // Arabic: تهيئة المحركات والخدمات المشتركة فقط إذا كان التطبيق في وضع الإنتاج
    // English: Initialize engines/services only if not in development mode
    println!("🔧 Initializing application engines...");

    // Arabic: في وضع قاعدة البيانات نُحمّل قاعدة GeoIP فعلية من ملف MMDB بشكل صارم
    // English: In DB mode, strictly load a real GeoIP MMDB file
    let geo_reader: Arc<mkt_ksa_geo_sec::core::geo_resolver::GeoReaderEnum> = if db_pool.is_some() {
        let geo_db_path = std::env::var("GEOIP_DB_PATH")
            .or_else(|_| std::env::var("MAXMIND_DB_PATH"))
            .unwrap_or_else(|_| "GeoLite2-City-Test.mmdb".to_string());

        let geo_db_bytes = std::fs::read(&geo_db_path).map_err(|e| {
            io_invalid_data(format!(
                "Failed to read GeoIP MMDB file at '{}': {}. Set GEOIP_DB_PATH or MAXMIND_DB_PATH to a valid MaxMind DB.",
                geo_db_path, e
            ))
        })?;

        let reader = Reader::from_source(geo_db_bytes).map_err(|e| {
            io_invalid_data(format!(
                "Failed to parse GeoIP MMDB file at '{}': {}. The file is not a valid MaxMind DB.",
                geo_db_path, e
            ))
        })?;

        Arc::new(mkt_ksa_geo_sec::core::geo_resolver::GeoReaderEnum::Real(
            reader,
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

    let mut fp_env_profiles = HashMap::new();
    // Populate the fingerprint environment profiles from the centralized defaults.
    fp_env_profiles.extend(build_default_fp_env_profiles());

    // 2. إنشاء محرك DeviceFPEngine
    let fp_engine = Arc::new(AdaptiveFingerprintEngine::new(
        Arc::new(DefaultSecurityMonitor::new()),
        Arc::new(
            DefaultQuantumEngine::new()
                .map_err(|e| io_invalid_data(format!("Failed to create quantum engine: {e}")))?,
        ),
        Arc::new(FpAiProcessor),
        Arc::new(RwLock::new(fp_env_profiles)),
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
        max_requests: env_u32_or_default("RATE_LIMIT_MAX_REQUESTS", default_rate_limit),
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
        ai_guard: Arc::new(RequestAiGuard::new(AiGuardConfig {
            block_threshold: env_u8_or_default("AI_GUARD_BLOCK_THRESHOLD", default_ai_threshold),
            max_payload_bytes: env_usize_or_default(
                "AI_GUARD_MAX_PAYLOAD_BYTES",
                default_payload_bytes,
            ),
            reputation_decay_seconds: env_u64_or_default("AI_GUARD_REPUTATION_DECAY_SECONDS", 300),
            base_block_seconds: env_u64_or_default(
                "AI_GUARD_BASE_BLOCK_SECONDS",
                default_ai_base_block,
            ),
            max_block_seconds: env_u64_or_default(
                "AI_GUARD_MAX_BLOCK_SECONDS",
                default_ai_max_block,
            ),
            max_tracked_ips: env_usize_or_default("AI_GUARD_MAX_TRACKED_IPS", 20_000),
            burst_window_seconds: env_u64_or_default("AI_GUARD_BURST_WINDOW_SECONDS", 10),
            burst_soft_limit: env_u32_or_default(
                "AI_GUARD_BURST_SOFT_LIMIT",
                default_ai_burst_soft_limit,
            ) as u16,
            burst_hard_limit: env_u32_or_default(
                "AI_GUARD_BURST_HARD_LIMIT",
                default_ai_burst_hard_limit,
            ) as u16,
        })),
        api_key: Some(SecureString::new(api_key)),
        alert_memory: Arc::new(mkt_ksa_geo_sec::app_state::AlertMemoryStore::new(256)),
        db_pool,
    });

    let default_worker_count = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4);
    let http_workers = env_usize_or_default("HTTP_WORKERS", default_worker_count);
    let http_backlog = env_u32_or_default("HTTP_BACKLOG", if ultra_strict { 4096 } else { 2048 });
    let http_max_connections = env_usize_or_default(
        "HTTP_MAX_CONNECTIONS",
        if ultra_strict { 50_000 } else { 25_000 },
    );
    let http_max_connection_rate = env_usize_or_default(
        "HTTP_MAX_CONNECTION_RATE",
        if ultra_strict { 1024 } else { 512 },
    );
    let http_keep_alive_seconds =
        env_u64_or_default("HTTP_KEEP_ALIVE_SECONDS", if ultra_strict { 10 } else { 5 });
    let http_client_request_timeout_seconds = env_u64_or_default(
        "HTTP_CLIENT_REQUEST_TIMEOUT_SECONDS",
        if ultra_strict { 30 } else { 20 },
    );
    let http_client_disconnect_timeout_seconds = env_u64_or_default(
        "HTTP_CLIENT_DISCONNECT_TIMEOUT_SECONDS",
        if ultra_strict { 10 } else { 7 },
    );
    let http_shutdown_timeout_seconds = env_u64_or_default(
        "HTTP_SHUTDOWN_TIMEOUT_SECONDS",
        if ultra_strict { 45 } else { 30 },
    );

    println!("✅ Engines initialized successfully.");
    println!("🚀 Server starting at http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            // Arabic: مشاركة الحالة الكاملة للتطبيق مع جميع المسارات
            // English: Share the full application state with all routes
            .app_data(app_state.clone())
            .app_data(web::PayloadConfig::new(env_usize_or_default(
                "GLOBAL_MAX_PAYLOAD_BYTES",
                default_payload_bytes,
            )))
            .wrap_fn(|mut req, srv| {
                let started = Instant::now();
                let method = req.method().to_string();
                let path = req.path().to_string();
                let peer_ip = req
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|| "0.0.0.0".to_string());
                let request_id = req
                    .headers()
                    .get("X-Request-ID")
                    .and_then(|hv| hv.to_str().ok())
                    .map(str::trim)
                    .filter(|v| !v.is_empty() && v.len() <= 128)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                if let Ok(request_id_value) = HeaderValue::from_str(&request_id) {
                    req.headers_mut()
                        .insert(HeaderName::from_static("x-request-id"), request_id_value);
                }

                let req_id_for_response = request_id.clone();
                let fut = srv.call(req);
                async move {
                    let mut response = fut.await?;
                    let status = response.status();
                    let latency_ms = started.elapsed().as_millis();
                    if !response.headers().contains_key("X-Request-ID") {
                        if let Ok(request_id_value) = HeaderValue::from_str(&req_id_for_response) {
                            response
                                .headers_mut()
                                .insert(HeaderName::from_static("x-request-id"), request_id_value);
                        }
                    }

                    if status.is_success() {
                        eprintln!(
                            "request_audit outcome=success request_id={} ip={} method={} path={} status={} latency_ms={}",
                            req_id_for_response,
                            peer_ip,
                            method,
                            path,
                            status.as_u16(),
                            latency_ms
                        );
                    }
                    Ok(response)
                }
            })
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Referrer-Policy", "no-referrer"))
                    .add((
                        "Permissions-Policy",
                        "geolocation=(), microphone=(), camera=()",
                    ))
                    .add((
                        "Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                    ))
                    .add(("Cache-Control", "no-store")),
            )
            // Arabic: تفعيل درع تحديد المعدل الذكي باستخدام governor (pure Rust)
            // English: Enable smart rate limiting shield using governor (pure Rust)
            // .wrap(GovernorMiddleware::new(60, 60)) // This line is removed as per the edit hint
            // Arabic: تسجيل إعدادات واجهة برمجة التطبيقات
            // English: Register API configurations
            .configure(api::config)
    })
    .workers(http_workers)
    .backlog(http_backlog)
    .max_connections(http_max_connections)
    .max_connection_rate(http_max_connection_rate)
    .keep_alive(KeepAlive::Timeout(Duration::from_secs(http_keep_alive_seconds)))
    .client_request_timeout(Duration::from_secs(http_client_request_timeout_seconds))
    .client_disconnect_timeout(Duration::from_secs(http_client_disconnect_timeout_seconds))
    .shutdown_timeout(http_shutdown_timeout_seconds)
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
