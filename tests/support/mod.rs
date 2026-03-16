use actix_web::web;
use mkt_ksa_geo_sec::app_state::AlertMemoryStore;
use mkt_ksa_geo_sec::app_state::AppState;
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
    DefaultAiModel as GeoAiModel, DefaultBlockchain, GeoReaderEnum, GeoResolver, MockGeoReader,
};
use mkt_ksa_geo_sec::core::network_analyzer::{
    DefaultAiNetworkAnalyzer, NetworkAnalyzer, ProxyDatabase,
};
use mkt_ksa_geo_sec::core::sensors_analyzer::{
    DefaultSensorAnomalyDetector, SensorsAnalyzerEngine,
};
use mkt_ksa_geo_sec::core::weather_val::{OpenMeteoProvider, WeatherEngine, WeatherProvider};
use mkt_ksa_geo_sec::db::crud;
use mkt_ksa_geo_sec::db::models::User;
use mkt_ksa_geo_sec::security::jwt::JwtManager;
use mkt_ksa_geo_sec::security::ratelimit::{RateLimitConfig, RateLimiter};
use mkt_ksa_geo_sec::security::secret::{SecureBytes, SecureString};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub async fn build_state_with_db(max_requests: u32) -> (web::Data<AppState>, Uuid, String, Uuid) {
    let geo_reader = Arc::new(GeoReaderEnum::Mock(MockGeoReader::new()));

    let geo_resolver = Arc::new(GeoResolver::new(
        SecureBytes::new(vec![1; 32]),
        Arc::new(GeoAiModel),
        Arc::new(DefaultBlockchain),
        true,
        false,
        geo_reader.clone(),
    ));

    let mut fp_env_profiles = HashMap::new();
    fp_env_profiles = mkt_ksa_geo_sec::core::device_fp::default_environment_profiles();

    let fp_engine = Arc::new(AdaptiveFingerprintEngine::new(
        Arc::new(DefaultSecurityMonitor::new()),
        Arc::new(DefaultQuantumEngine::new().expect("quantum init")),
        Arc::new(FpAiProcessor),
        Arc::new(RwLock::new(fp_env_profiles)),
    ));

    let behavior_engine = Arc::new(BehaviorEngine::new(
        Arc::new(DefaultBehavioralModel),
        Arc::new(DefaultAnomalyDetector {
            max_speed_kmh: 1200.0,
        }),
        10,
    ));

    let sensors_engine = Arc::new(SensorsAnalyzerEngine::new(
        SecureBytes::new(vec![42; 48]),
        Arc::new(DefaultSensorAnomalyDetector::default()),
    ));

    let network_engine = Arc::new(NetworkAnalyzer::new(
        SecureBytes::new(vec![42; 32]),
        Arc::new(RwLock::new(ProxyDatabase::default())),
        geo_reader,
        Arc::new(DefaultAiNetworkAnalyzer),
    ));

    let x_engine = Arc::new(CrossValidationEngine::new(
        Arc::clone(&geo_resolver),
        Arc::clone(&fp_engine),
        Arc::clone(&behavior_engine),
        Arc::clone(&sensors_engine),
        Arc::clone(&network_engine),
        Arc::new(DefaultScoringStrategy {
            location_weight: 0.4,
            fingerprint_weight: 0.3,
            behavior_weight: 0.3,
        }),
        SecureBytes::new(b"test_final_verdict_key_32_bytes_min".to_vec()),
    ));

    let composite_verifier = Arc::new(CompositeVerifier {
        geo: geo_resolver,
        behavior: behavior_engine,
        device_fp: fp_engine,
        network: network_engine,
    });

    let weather_providers: Vec<Arc<dyn WeatherProvider>> = vec![Arc::new(OpenMeteoProvider::new())];
    let weather_engine = Arc::new(WeatherEngine::new(weather_providers));

    let jwt_manager = Arc::new(JwtManager::new(
        &SecureString::new("integration_test_jwt_secret_key_more_than_32".to_string()),
        3600,
        "mkt_ksa_geo_sec".to_string(),
        "api_clients".to_string(),
    ));

    let rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests,
        window: std::time::Duration::from_secs(60),
        whitelist: HashSet::new(),
        blacklist: HashSet::new(),
    });

    let db = tokio_rusqlite::Connection::open_in_memory()
        .await
        .expect("open sqlite memory db");
    crud::init_schema(&db).await.expect("init schema");

    let user_id = Uuid::new_v4();
    let user = User {
        id: user_id,
        username: "integration-user".to_string(),
        email: "integration@example.local".to_string(),
        password_hash: "hash".to_string(),
        status: "active".to_string(),
        created_at: chrono::Utc::now().naive_utc(),
        last_login_at: Some(chrono::Utc::now().naive_utc()),
    };
    crud::upsert_user(&db, &user).await.expect("seed user");

    let token = jwt_manager
        .generate_token(user_id, vec!["user".to_string()])
        .expect("generate token");

    let other_user_id = Uuid::new_v4();

    let state = web::Data::new(AppState {
        x_engine,
        composite_verifier,
        weather_engine,
        jwt_manager,
        rate_limiter,
        alert_memory: Arc::new(AlertMemoryStore::new(64)),
        db_pool: Some(db),
    });

    (state, user_id, token, other_user_id)
}
