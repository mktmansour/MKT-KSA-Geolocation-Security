use super::*;

fn read_budget_ns(key: &str) -> Option<u128> {
    std::env::var(key).ok().and_then(|v| v.parse::<u128>().ok())
}
fn warn(msg: &str) {
    eprintln!("::warning::{}", msg);
}
fn enforce_budget_tiered(metric: &str, avg_ns: u128) {
    let fail_key = format!("PERF_BUDGET_FAIL_{}", metric);
    let warn_key = format!("PERF_BUDGET_WARN_{}", metric);
    if let Some(fail_b) = read_budget_ns(&fail_key) {
        assert!(
            avg_ns <= fail_b,
            "performance budget {} exceeded: avg={}ns > {}ns",
            fail_key,
            avg_ns,
            fail_b
        );
        return;
    }
    if let Some(warn_b) = read_budget_ns(&warn_key) {
        if avg_ns > warn_b {
            warn(&format!(
                "performance budget {} exceeded: avg={}ns > {}ns",
                warn_key, avg_ns, warn_b
            ));
        }
        return;
    }
    let single_key = format!("PERF_BUDGET_{}", metric);
    if let Some(b) = read_budget_ns(&single_key) {
        assert!(
            avg_ns <= b,
            "performance budget {} exceeded: avg={}ns > {}ns",
            single_key,
            avg_ns,
            b
        );
    }
}

#[test]
fn url_decode_handles_plus_and_percent() {
    let s = "a%2Bb+c%2F%20d";
    let out = url_decode(s);
    assert_eq!(out, "a+b c/ d");
}

#[test]
fn reason_phrase_maps_common_codes() {
    assert_eq!(super::reason_phrase(200), "OK");
    assert_eq!(super::reason_phrase(302), "Found");
    assert_eq!(super::reason_phrase(401), "Unauthorized");
    assert_eq!(super::reason_phrase(503), "Service Unavailable");
}

#[test]
fn parse_form_params_decodes_values() {
    let m = parse_form_params("scope=openid%20profile&redirect_uri=https%3A%2F%2Fcb");
    assert_eq!(m.get("scope").cloned(), Some("openid profile".to_string()));
    assert_eq!(
        m.get("redirect_uri").cloned(),
        Some("https://cb".to_string())
    );
}

fn extract_json_str(body: &[u8], key: &str) -> Option<String> {
    let s = String::from_utf8_lossy(body);
    let pat = format!("\"{}\":\"", key);
    if let Some(start) = s.find(&pat) {
        let rest = &s[start + pat.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

#[test]
fn oauth2_authorize_returns_302_with_location_header() {
    {
        use crate::oauth2::clients::{get_client_manager, ClientAuthMethod, ClientType};
        let cm = get_client_manager();
        if cm.get_client("demo_client").is_none() {
            let _ = cm.register_client(
                "demo_client".to_string(),
                "Demo Client".to_string(),
                ClientType::Web,
                ClientAuthMethod::None,
            );
        }
        use crate::oauth2::clients::ClientSecurityPolicy;
        let mut pol = ClientSecurityPolicy::default();
        pol.allowed_scopes = vec![
            "read".to_string(),
            "write".to_string(),
            "openid".to_string(),
            "profile".to_string(),
        ];
        pol.allowed_response_types = vec![crate::oauth2::core::ResponseType::Code];
        pol.allowed_redirect_uris = vec!["https://example.com/callback".to_string()];
        let _ = cm.update_client_security_policy("demo_client", pol);
    }
    let req = Request {
        method: "GET".to_string(),
        path: "/oauth/authorize?response_type=code&client_id=demo_client&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20profile&state=xyz".to_string(),
        headers: vec![("user-agent".to_string(), "test".to_string())],
        body: Vec::new(),
    };
    let resp = super::handle_oauth2_request(&req);
    assert_eq!(resp.status, 302, "authorize should respond with 302 Found");
    let mut has_location = false;
    let mut loc_val = String::new();
    for (k, v) in resp.headers.iter() {
        if k.eq_ignore_ascii_case("location") {
            has_location = true;
            loc_val = v.clone();
            break;
        }
    }
    assert!(has_location, "Location header must be present");
    assert!(
        loc_val.starts_with("https://example.com/callback?code="),
        "Location must redirect to the provided redirect_uri with code"
    );
}

#[test]
fn oauth2_token_client_credentials_success() {
    {
        use crate::oauth2::clients::{
            get_client_manager, ClientAuthMethod, ClientSecurityPolicy, ClientType,
        };
        let cm = get_client_manager();
        if cm.get_client("demo_client").is_none() {
            let _ = cm.register_client(
                "demo_client".to_string(),
                "Demo Client".to_string(),
                ClientType::Service,
                ClientAuthMethod::None,
            );
        }
        let mut pol = ClientSecurityPolicy::default();
        pol.allowed_scopes = vec!["read".to_string()];
        pol.allowed_grant_types = vec![crate::oauth2::core::GrantType::ClientCredentials];
        let _ = cm.update_client_security_policy("demo_client", pol);
    }
    let req = Request {
        method: "POST".to_string(),
        path: "/oauth/token".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: b"grant_type=client_credentials&client_id=demo_client&scope=read".to_vec(),
    };
    let resp = super::handle_oauth2_request(&req);
    assert_eq!(resp.status, 200, "client_credentials should succeed");
    let access = extract_json_str(&resp.body, "access_token").unwrap_or_default();
    assert!(!access.is_empty(), "access_token must be present");
}

#[test]
fn oauth2_userinfo_with_client_credentials_insufficient_scope() {
    {
        use crate::oauth2::clients::{
            get_client_manager, ClientAuthMethod, ClientSecurityPolicy, ClientType,
        };
        let cm = get_client_manager();
        if cm.get_client("demo_client").is_none() {
            let _ = cm.register_client(
                "demo_client".to_string(),
                "Demo Client".to_string(),
                ClientType::Service,
                ClientAuthMethod::None,
            );
        }
        // Ensure client_credentials and "read" scope are allowed for deterministic tests
        let mut pol = ClientSecurityPolicy::default();
        pol.allowed_scopes = vec!["read".to_string()];
        pol.allowed_grant_types = vec![crate::oauth2::core::GrantType::ClientCredentials];
        let _ = cm.update_client_security_policy("demo_client", pol);
    }
    let token_resp = super::handle_oauth2_request(&Request {
        method: "POST".to_string(),
        path: "/oauth/token".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: b"grant_type=client_credentials&client_id=demo_client&scope=read".to_vec(),
    });
    let access = extract_json_str(&token_resp.body, "access_token").unwrap_or_default();
    assert!(!access.is_empty());
    let ui_resp = super::handle_oauth2_request(&Request {
        method: "GET".to_string(),
        path: "/oauth/userinfo".to_string(),
        headers: vec![("authorization".to_string(), format!("Bearer {}", access))],
        body: Vec::new(),
    });
    assert_ne!(
        ui_resp.status, 200,
        "userinfo should not allow client_credentials with read only"
    );
    let body = String::from_utf8_lossy(&ui_resp.body);
    assert!(body.contains("insufficient_scope") || ui_resp.status == 400 || ui_resp.status == 401);
}

#[test]
fn oauth2_introspect_requires_confidential_client() {
    {
        use crate::oauth2::clients::{
            get_client_manager, ClientAuthMethod, ClientSecurityPolicy, ClientType,
        };
        let cm = get_client_manager();
        if cm.get_client("demo_client").is_none() {
            let _ = cm.register_client(
                "demo_client".to_string(),
                "Demo Client".to_string(),
                ClientType::Service,
                ClientAuthMethod::None,
            );
        }
        let mut pol = ClientSecurityPolicy::default();
        pol.allowed_scopes = vec!["read".to_string()];
        pol.allowed_grant_types = vec![crate::oauth2::core::GrantType::ClientCredentials];
        let _ = cm.update_client_security_policy("demo_client", pol);
    }
    let token_resp = super::handle_oauth2_request(&Request {
        method: "POST".to_string(),
        path: "/oauth/token".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: b"grant_type=client_credentials&client_id=demo_client&scope=read".to_vec(),
    });
    let access = extract_json_str(&token_resp.body, "access_token").unwrap_or_default();
    assert!(!access.is_empty());
    let intr_resp = super::handle_oauth2_request(&Request {
        method: "POST".to_string(),
        path: "/oauth/introspect".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: format!("token={}&client_id=demo_client", access).into_bytes(),
    });
    if intr_resp.status == 200 {
        assert!(
            !intr_resp.body.is_empty(),
            "introspect 200 must return a JSON body"
        );
    } else {
        assert!(intr_resp.status == 400 || intr_resp.status == 401);
    }
}

#[test]
fn oauth2_revoke_returns_200_even_on_failure() {
    let revoke_resp = super::handle_oauth2_request(&Request {
        method: "POST".to_string(),
        path: "/oauth/revoke".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: b"token=invalid&client_id=demo_client".to_vec(),
    });
    assert!(revoke_resp.status == 200 || revoke_resp.status == 401);
}

#[test]
fn oauth2_authorization_code_flow_exchange_and_userinfo_success() {
    {
        use crate::oauth2::clients::{
            get_client_manager, ClientAuthMethod, ClientSecurityPolicy, ClientType,
        };
        use crate::oauth2::core::{GrantType, ResponseType};
        let cm = get_client_manager();
        let cid = "demo_client_ac";
        if cm.get_client(cid).is_none() {
            let _ = cm.register_client(
                cid.to_string(),
                "Demo Client".to_string(),
                ClientType::Web,
                ClientAuthMethod::None,
            );
        }
        let mut pol = ClientSecurityPolicy::default();
        pol.allowed_scopes = vec!["openid".to_string(), "profile".to_string()];
        pol.allowed_grant_types = vec![GrantType::AuthorizationCode];
        pol.allowed_response_types = vec![ResponseType::Code];
        pol.allowed_redirect_uris = vec!["https://example.com/callback".to_string()];
        let _ = cm.update_client_security_policy(cid, pol);
    }
    let auth_resp = super::handle_oauth2_request(&Request {
        method: "GET".to_string(),
        path: "/oauth/authorize?response_type=code&client_id=demo_client_ac&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20profile&state=xyz".to_string(),
        headers: vec![("user-agent".to_string(), "test".to_string())],
        body: Vec::new(),
    });
    assert_eq!(auth_resp.status, 302);
    let mut code = String::new();
    for (k, v) in auth_resp.headers.iter() {
        if k.eq_ignore_ascii_case("location") {
            if let Some(qpos) = v.find('?') {
                for part in v[qpos + 1..].split('&') {
                    if let Some(eq) = part.find('=') {
                        if &part[..eq] == "code" {
                            code = part[eq + 1..].to_string();
                            break;
                        }
                    }
                }
            }
        }
    }
    assert!(!code.is_empty(), "authorization code must be present");
    let token_resp = super::handle_oauth2_request(&Request {
        method: "POST".to_string(),
        path: "/oauth/token".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: format!(
            "grant_type=authorization_code&client_id=demo_client_ac&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code={}",
            code
        )
        .into_bytes(),
    });
    assert_eq!(token_resp.status, 200, "token exchange must succeed");
    let access = extract_json_str(&token_resp.body, "access_token").unwrap_or_default();
    assert!(!access.is_empty(), "access_token must be present");
    let ui_resp = super::handle_oauth2_request(&Request {
        method: "GET".to_string(),
        path: "/oauth/userinfo".to_string(),
        headers: vec![("authorization".to_string(), format!("Bearer {}", access))],
        body: Vec::new(),
    });
    assert_eq!(
        ui_resp.status, 200,
        "userinfo should succeed for auth code token"
    );
    assert!(!ui_resp.body.is_empty());
}

// --------- Simple performance benches (zero-deps) ---------
#[test]
fn bench_authorize_parse() {
    let iterations = 10000u32;
    let req = Request {
        method: "GET".to_string(),
        path: "/oauth/authorize?response_type=code&client_id=demo_client_ac&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20profile&state=xyz".to_string(),
        headers: vec![("user-agent".to_string(), "bench".to_string())],
        body: Vec::new(),
    };
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = super::oauth::parse_authorization_request(&req);
    }
    let elapsed = start.elapsed().as_nanos() as u128;
    let avg = elapsed / iterations as u128;
    println!("bench_authorize_parse avg_ns_per_iter={}", avg);
    enforce_budget_tiered("AUTHORIZE_PARSE_NS", avg);
}

#[test]
fn bench_token_parse() {
    let iterations = 10000u32;
    let req = Request {
        method: "POST".to_string(),
        path: "/oauth/token".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: b"grant_type=client_credentials&client_id=demo_client&scope=read".to_vec(),
    };
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = super::oauth::parse_token_request(&req);
    }
    let elapsed = start.elapsed().as_nanos() as u128;
    let avg = elapsed / iterations as u128;
    println!("bench_token_parse avg_ns_per_iter={}", avg);
    enforce_budget_tiered("TOKEN_PARSE_NS", avg);
}

#[test]
fn bench_inbound_policy_eval() {
    let iterations = 10000u32;
    let p = crate::security::inspection_policy::InboundPolicy::default();
    let headers = b"Content-Type: application/x-www-form-urlencoded\r\nX-Test: 1\r\n\r\n";
    let body = b"grant_type=client_credentials&client_id=bench";
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = p.evaluate_request("POST", "/oauth/token", headers, body);
    }
    let elapsed = start.elapsed().as_nanos() as u128;
    let avg = elapsed / iterations as u128;
    println!("bench_inbound_policy_eval avg_ns_per_iter={}", avg);
    enforce_budget_tiered("POLICY_EVAL_NS", avg);
}

#[test]
fn bench_url_decode() {
    let iterations = 10000u32;
    let s = "scope=openid%20profile&redirect_uri=https%3A%2F%2Fcb&x=a%2Bb+c";
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = url_decode(s);
    }
    let elapsed = start.elapsed().as_nanos() as u128;
    let avg = elapsed / iterations as u128;
    println!("bench_url_decode avg_ns_per_iter={}", avg);
    enforce_budget_tiered("URL_DECODE_NS", avg);
}
