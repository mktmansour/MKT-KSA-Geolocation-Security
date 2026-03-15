use actix_web::http::header;
use actix_web::http::StatusCode;
use actix_web::{test, App};
use mkt_ksa_geo_sec::api;
use mkt_ksa_geo_sec::db::migrations;
use serde_json::json;

mod support;
use support::build_state_with_db;

fn sample_behavior_input() -> serde_json::Value {
    json!({
        "entity_id": "entity-1",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "location": [24.7136, 46.6753],
        "network_info": {
            "ip_address": "8.8.8.8",
            "is_vpn": false,
            "connection_type": "WiFi"
        },
        "device_fingerprint": "fp-demo"
    })
}

#[actix_web::test]
async fn rejects_missing_and_invalid_token_across_api_surface() {
    let (state, user_id, _token, _other_user_id) = build_state_with_db(100).await;

    let app = test::init_service(App::new().app_data(state.clone()).configure(api::config)).await;

    let routes = vec![
        (
            "/api/users/{id}"
                .to_string()
                .replace("{id}", &user_id.to_string()),
            "GET",
            None,
        ),
        (
            "/api/alerts/trigger".to_string(),
            "POST",
            Some(json!({
                "entity_id": user_id,
                "entity_type": "user",
                "alert_type": "suspicious_login",
                "severity": "high",
                "details": {"source": "integration-test"}
            })),
        ),
        (
            "/api/geo/resolve".to_string(),
            "POST",
            Some(json!({
                "ip_address": "8.8.8.8",
                "gps_data": [24.7136, 46.6753, 10, 0.95],
                "os_info": "Linux",
                "device_details": "DeviceX",
                "environment_context": "Office",
                "behavior_input": sample_behavior_input()
            })),
        ),
        (
            "/api/device/resolve".to_string(),
            "POST",
            Some(json!({
                "os": "Linux",
                "device_info": "DeviceX",
                "environment_data": "Office"
            })),
        ),
        (
            "/api/behavior/analyze".to_string(),
            "POST",
            Some(json!({"input": sample_behavior_input()})),
        ),
        (
            "/api/network/analyze".to_string(),
            "POST",
            Some(json!({"ip": "8.8.8.8", "conn_type": "WiFi"})),
        ),
        (
            "/api/sensors/analyze".to_string(),
            "POST",
            Some(json!({
                "reading": {
                    "sensor_type": "AccelerometerX",
                    "value": 1.0,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                },
                "history": []
            })),
        ),
        (
            "/api/weather/summary".to_string(),
            "POST",
            Some(json!({"latitude": 24.7136, "longitude": 46.6753})),
        ),
        (
            "/api/smart_access/verify".to_string(),
            "POST",
            Some(json!({
                "geo_input": ["8.8.8.8", [24.7136, 46.6753, 10, 0.95]],
                "behavior_input": sample_behavior_input(),
                "os_info": "Linux",
                "device_details": "DeviceX",
                "env_context": "Office"
            })),
        ),
    ];

    for (path, method, body) in &routes {
        let req = match (*method, body) {
            ("GET", _) => test::TestRequest::get().uri(path).to_request(),
            ("POST", Some(payload)) => test::TestRequest::post()
                .uri(path)
                .set_json(payload)
                .to_request(),
            _ => unreachable!(),
        };
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "missing token must be rejected for {path}"
        );

        let req_invalid = match (*method, body) {
            ("GET", _) => test::TestRequest::get()
                .uri(path)
                .insert_header((header::AUTHORIZATION, "Bearer invalid.token.value"))
                .to_request(),
            ("POST", Some(payload)) => test::TestRequest::post()
                .uri(path)
                .insert_header((header::AUTHORIZATION, "Bearer invalid.token.value"))
                .set_json(payload)
                .to_request(),
            _ => unreachable!(),
        };
        let resp_invalid = test::call_service(&app, req_invalid).await;
        assert_eq!(
            resp_invalid.status(),
            StatusCode::UNAUTHORIZED,
            "invalid token must be rejected for {path}"
        );
    }
}

#[actix_web::test]
async fn migrations_are_idempotent_and_versioned() {
    let db = tokio_rusqlite::Connection::open_in_memory()
        .await
        .expect("open sqlite in-memory");

    migrations::run_migrations(&db)
        .await
        .expect("first migrations run must succeed");
    migrations::run_migrations(&db)
        .await
        .expect("second migrations run must be idempotent");

    let versions_count: i64 = db
        .call(|conn| {
            let mut stmt = conn.prepare("SELECT COUNT(*) FROM schema_migrations")?;
            let count: i64 = stmt.query_row([], |row| row.get(0))?;
            Ok::<i64, rusqlite::Error>(count)
        })
        .await
        .expect("count migration versions");
    assert_eq!(versions_count, 2);

    let users_table_exists: i64 = db
        .call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'",
            )?;
            let count: i64 = stmt.query_row([], |row| row.get(0))?;
            Ok::<i64, rusqlite::Error>(count)
        })
        .await
        .expect("users table existence check");
    assert_eq!(users_table_exists, 1);
}

#[actix_web::test]
async fn burst_requests_trigger_strict_rate_limit() {
    let (state, user_id, token, _) = build_state_with_db(8).await;

    let app = test::init_service(App::new().app_data(state.clone()).configure(api::config)).await;

    let mut ok_count = 0usize;
    let mut limited_count = 0usize;

    for _ in 0..40 {
        let req = test::TestRequest::get()
            .uri(&format!("/api/users/{user_id}"))
            .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        match resp.status() {
            StatusCode::OK => ok_count += 1,
            StatusCode::TOO_MANY_REQUESTS => limited_count += 1,
            other => panic!("unexpected status in burst test: {other}"),
        }
    }

    assert!(
        ok_count <= 8,
        "OK responses must not exceed configured rate limit"
    );
    assert!(
        limited_count >= 32,
        "Most burst requests must be rate-limited"
    );
}
