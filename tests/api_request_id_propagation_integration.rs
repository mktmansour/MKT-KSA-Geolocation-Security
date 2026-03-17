use actix_web::http::header;
use actix_web::http::StatusCode;
use actix_web::{test, App};
use mkt_ksa_geo_sec::api;
use serde_json::json;

mod support;
use support::build_state_with_db;

#[actix_web::test]
async fn request_id_is_propagated_across_multiple_endpoints() {
    let (state, user_id, _token, _other_user_id) = build_state_with_db(200).await;

    let app = test::init_service(App::new().app_data(state.clone()).configure(api::config)).await;

    let checks = vec![
        (format!("/api/users/{user_id}"), "GET", None, "req-id-users"),
        (
            "/api/network/analyze".to_string(),
            "POST",
            Some(json!({"ip": "8.8.8.8", "conn_type": "WiFi"})),
            "req-id-network",
        ),
        (
            "/api/weather/summary".to_string(),
            "POST",
            Some(json!({"latitude": 24.7136, "longitude": 46.6753})),
            "req-id-weather",
        ),
    ];

    for (path, method, payload, req_id) in checks {
        let request = match (method, payload) {
            ("GET", None) => test::TestRequest::get()
                .uri(&path)
                .insert_header(("X-Request-ID", req_id))
                .to_request(),
            ("POST", Some(body)) => test::TestRequest::post()
                .uri(&path)
                .insert_header(("X-Request-ID", req_id))
                .set_json(body)
                .to_request(),
            _ => unreachable!(),
        };

        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let header_id = response
            .headers()
            .get("X-Request-ID")
            .and_then(|h| h.to_str().ok())
            .expect("x-request-id header must exist");
        assert_eq!(header_id, req_id);

        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(
            body.get("request_id").and_then(|v| v.as_str()),
            Some(req_id)
        );
    }
}

#[actix_web::test]
async fn successful_json_response_contains_trace_id_envelope() {
    let (state, user_id, token, _other_user_id) = build_state_with_db(200).await;

    let app = test::init_service(App::new().app_data(state.clone()).configure(api::config)).await;

    let req = test::TestRequest::get()
        .uri(&format!("/api/users/{user_id}"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .insert_header(("X-Request-ID", "req-id-success-user"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("trace_id").and_then(|v| v.as_str()),
        Some("req-id-success-user")
    );
    assert!(body.get("data").is_some());
}
