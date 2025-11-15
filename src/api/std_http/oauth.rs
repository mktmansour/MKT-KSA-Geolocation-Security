// Arabic: معالجات OAuth2 (authorize/token/introspect/userinfo/revoke)
// English: OAuth2 handlers (authorize/token/introspect/userinfo/revoke)

use crate::api::std_http::{Request, Response};

pub(crate) fn handle_oauth2_request(req: &Request) -> Response {
    let oauth2_endpoints = crate::oauth2::endpoints::get_oauth2_endpoints();

    // Ignore query for routing
    let path_no_query = req.path.split('?').next().unwrap_or("").to_string();

    match path_no_query.as_str() {
        "/oauth/authorize" if req.method.eq_ignore_ascii_case("GET") => {
            crate::telemetry::inc_oauth2_auth_requests();
            let auth_request = parse_authorization_request(req);
            let result = oauth2_endpoints.authorize(&auth_request);
            if result.status_code == 200 {
                crate::telemetry::inc_oauth2_auth_success();
            } else {
                crate::telemetry::inc_oauth2_auth_failed();
            }
            Response {
                status: result.status_code,
                content_type: "application/json",
                body: result.data.into_bytes(),
                fingerprint_hex: result.trace_info.map(|t| t.request_id),
                headers: result.headers.into_iter().collect(),
            }
        }
        "/oauth/token" if req.method.eq_ignore_ascii_case("POST") => {
            crate::telemetry::inc_oauth2_token_requests();
            let token_request = parse_token_request(req);
            let result = oauth2_endpoints.token(&token_request);
            if result.status_code == 200 {
                crate::telemetry::inc_oauth2_token_success();
            } else {
                crate::telemetry::inc_oauth2_token_failed();
            }
            Response {
                status: result.status_code,
                content_type: "application/json",
                body: result.data.into_bytes(),
                fingerprint_hex: result.trace_info.map(|t| t.request_id),
                headers: result.headers.into_iter().collect(),
            }
        }
        "/oauth/introspect" if req.method.eq_ignore_ascii_case("POST") => {
            crate::telemetry::inc_oauth2_introspect_requests();
            let introspection_request = parse_introspection_request(req);
            let result = oauth2_endpoints.introspect(&introspection_request);
            if result.status_code == 200 {
                crate::telemetry::inc_oauth2_introspect_success();
            } else {
                crate::telemetry::inc_oauth2_introspect_failed();
            }
            Response {
                status: result.status_code,
                content_type: "application/json",
                body: result.data.into_bytes(),
                fingerprint_hex: result.trace_info.map(|t| t.request_id),
                headers: result.headers.into_iter().collect(),
            }
        }
        "/oauth/userinfo" if req.method.eq_ignore_ascii_case("GET") => {
            let userinfo_request = parse_userinfo_request(req);
            let result = oauth2_endpoints.userinfo(&userinfo_request);
            Response {
                status: result.status_code,
                content_type: "application/json",
                body: result.data.into_bytes(),
                fingerprint_hex: result.trace_info.map(|t| t.request_id),
                headers: result.headers.into_iter().collect(),
            }
        }
        "/oauth/revoke" if req.method.eq_ignore_ascii_case("POST") => {
            let revocation_request = parse_revocation_request(req);
            let result = oauth2_endpoints.revoke(&revocation_request);
            Response {
                status: result.status_code,
                content_type: "application/json",
                body: result.data.into_bytes(),
                fingerprint_hex: result.trace_info.map(|t| t.request_id),
                headers: result.headers.into_iter().collect(),
            }
        }
        "/oauth/keys" if req.method.eq_ignore_ascii_case("GET") => {
            let jwk_set = r#"{"keys":[]}"#;
            Response::json(200, jwk_set)
        }
        "/oauth/.well-known/openid_configuration" if req.method.eq_ignore_ascii_case("GET") => {
            let discovery = r#"{
                "issuer": "mkt-ksa-geolocation-security",
                "authorization_endpoint": "/oauth/authorize",
                "token_endpoint": "/oauth/token",
                "userinfo_endpoint": "/oauth/userinfo",
                "jwks_uri": "/oauth/keys",
                "response_types_supported": ["code", "id_token", "code id_token"],
                "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["HS512"],
                "scopes_supported": ["openid", "profile", "email", "address", "phone"]
            }"#;
            Response::json(200, discovery)
        }
        _ => Response::json(404, "{\"error\":\"oauth2_endpoint_not_found\"}"),
    }
}

pub(crate) fn parse_authorization_request(
    req: &Request,
) -> crate::oauth2::endpoints::AuthorizationRequest {
    use crate::oauth2::core::*;
    let query_params = super::parser::parse_query_params(&req.path);
    crate::oauth2::endpoints::AuthorizationRequest {
        response_type: ResponseType::from_str(
            query_params
                .get("response_type")
                .unwrap_or(&"code".to_string()),
        )
        .unwrap_or(ResponseType::Code),
        client_id: query_params.get("client_id").cloned().unwrap_or_default(),
        redirect_uri: query_params
            .get("redirect_uri")
            .cloned()
            .unwrap_or_default(),
        scope: query_params
            .get("scope")
            .map(|s| s.split(' ').map(|s| s.to_string()).collect())
            .unwrap_or_default(),
        state: query_params.get("state").cloned(),
        user_consent: true,
        user_id: query_params.get("user_id").cloned(),
        session_id: crate::oauth2::core::generate_uuid(),
        device_fingerprint: query_params.get("device_fingerprint").cloned(),
        latitude: query_params.get("latitude").and_then(|s| s.parse().ok()),
        longitude: query_params.get("longitude").and_then(|s| s.parse().ok()),
        country: query_params.get("country").cloned(),
        city: query_params.get("city").cloned(),
        ip_address: "127.0.0.1".to_string(),
        user_agent: super::find_header(&req.headers, "user-agent")
            .unwrap_or("")
            .to_string(),
    }
}

pub(crate) fn parse_token_request(req: &Request) -> crate::oauth2::endpoints::TokenRequest {
    use crate::oauth2::core::*;
    let body_str = String::from_utf8_lossy(&req.body);
    let form_params = super::parser::parse_form_params(&body_str);
    crate::oauth2::endpoints::TokenRequest {
        grant_type: GrantType::from_str(
            form_params
                .get("grant_type")
                .unwrap_or(&"authorization_code".to_string()),
        )
        .unwrap_or(GrantType::AuthorizationCode),
        client_id: form_params.get("client_id").cloned().unwrap_or_default(),
        client_secret: form_params.get("client_secret").cloned(),
        code: form_params.get("code").cloned(),
        redirect_uri: form_params.get("redirect_uri").cloned(),
        refresh_token: form_params.get("refresh_token").cloned(),
        username: form_params.get("username").cloned(),
        password: form_params.get("password").cloned(),
        scope: form_params
            .get("scope")
            .map(|s| s.split(' ').map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

pub(crate) fn parse_introspection_request(
    req: &Request,
) -> crate::oauth2::endpoints::IntrospectionRequest {
    let body_str = String::from_utf8_lossy(&req.body);
    let form_params = super::parser::parse_form_params(&body_str);
    crate::oauth2::endpoints::IntrospectionRequest {
        token: form_params.get("token").cloned().unwrap_or_default(),
        token_type_hint: form_params.get("token_type_hint").cloned(),
        client_id: form_params.get("client_id").cloned().unwrap_or_default(),
        client_secret: form_params.get("client_secret").cloned(),
    }
}

pub(crate) fn parse_userinfo_request(req: &Request) -> crate::oauth2::endpoints::UserInfoRequest {
    let access_token = super::find_header(&req.headers, "authorization")
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    crate::oauth2::endpoints::UserInfoRequest { access_token }
}

pub(crate) fn parse_revocation_request(
    req: &Request,
) -> crate::oauth2::endpoints::RevocationRequest {
    let body_str = String::from_utf8_lossy(&req.body);
    let form_params = super::parser::parse_form_params(&body_str);
    crate::oauth2::endpoints::RevocationRequest {
        token: form_params.get("token").cloned().unwrap_or_default(),
        token_type_hint: form_params.get("token_type_hint").cloned(),
        client_id: form_params.get("client_id").cloned().unwrap_or_default(),
        client_secret: form_params.get("client_secret").cloned(),
    }
}
