// Arabic: إدارة حرّاس الويب‑هوك
// English: Webhook guards management

use crate::api::std_http::utils::{extract_str, extract_u64, extract_u8};
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/webhook/guard/set?") {
        let path = extract_str(&req.path, "path=").unwrap_or_else(|| "/webhook/in".to_string());
        let alg = extract_str(&req.path, "alg=").unwrap_or_else(|| "hmac-sha512".to_string());
        let key_id = extract_str(&req.path, "key=").unwrap_or_else(|| "auth_hmac".to_string());
        let ts = extract_u64(&req.path, "ts=").unwrap_or(300_000);
        let required = extract_u8(&req.path, "required=").unwrap_or(1) != 0;
        let anti = extract_u8(&req.path, "replay=").unwrap_or(1) != 0;
        crate::webhook::guards::set_guard(crate::webhook::guards::GuardConfig {
            path,
            alg,
            key_id,
            required,
            ts_window_ms: ts,
            anti_replay_on: anti,
        });
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/webhook/guard/disable?") {
        if let Some(p) = extract_str(&req.path, "path=") {
            crate::webhook::guards::disable_guard(&p);
            return Some(Response::json(200, "{\"ok\":true}"));
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"path missing\"}",
        ));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/webhook/guard/list" {
        let body = crate::webhook::guards::list_guards()
            .into_iter()
            .map(|g| format!("{{\"path\":\"{}\",\"alg\":\"{}\",\"key_id\":\"{}\",\"required\":{},\"ts_window_ms\":{},\"anti_replay_on\":{}}}", g.path, g.alg, g.key_id, if g.required {1}else{0}, g.ts_window_ms, if g.anti_replay_on {1}else{0}))
            .collect::<Vec<_>>()
            .join(",");
        return Some(Response::json(200, &format!("[{}]", body)));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/webhook/guard/stats" {
        let body = crate::telemetry::sig_paths_json();
        return Some(Response::json(200, &body));
    }
    None
}
