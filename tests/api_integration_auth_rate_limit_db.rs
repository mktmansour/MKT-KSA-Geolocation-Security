use actix_web::http::header;
use actix_web::http::StatusCode;
use actix_web::{test, App};
use mkt_ksa_geo_sec::api::auth;
mod support;
use support::build_state_with_db;

#[actix_web::test]
async fn auth_rate_limit_db_integration() {
    let (state, user_id, token, other_user_id) = build_state_with_db(3).await;

    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .service(auth::get_user),
    )
    .await;

    let req_ok_1 = test::TestRequest::get()
        .uri(&format!("/users/{user_id}"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_request();
    let resp_ok_1 = test::call_service(&app, req_ok_1).await;
    assert_eq!(resp_ok_1.status(), StatusCode::OK);

    let req_forbidden = test::TestRequest::get()
        .uri(&format!("/users/{other_user_id}"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_request();
    let resp_forbidden = test::call_service(&app, req_forbidden).await;
    assert_eq!(resp_forbidden.status(), StatusCode::FORBIDDEN);

    let req_ok_2 = test::TestRequest::get()
        .uri(&format!("/users/{user_id}"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_request();
    let resp_ok_2 = test::call_service(&app, req_ok_2).await;
    assert_eq!(resp_ok_2.status(), StatusCode::OK);

    let req_limited = test::TestRequest::get()
        .uri(&format!("/users/{user_id}"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_request();
    let resp_limited = test::call_service(&app, req_limited).await;
    assert_eq!(resp_limited.status(), StatusCode::TOO_MANY_REQUESTS);
}
