// Arabic: معالجات الذاكرة (تهيئة/تفريغ/حالة)
// English: Memory handlers (config/purge/status)

use crate::api::std_http::utils::{extract_u64, extract_u8};
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/memory/config?") {
        let limit = extract_u64(&req.path, "limit=").unwrap_or(0);
        let auto = extract_u8(&req.path, "auto=").unwrap_or(0) != 0;
        crate::telemetry::set_memory_limit(limit, auto);
        crate::telemetry::record_event("mem_cfg", &format!("limit={} auto={}", limit, auto as u8));
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/memory/purge" {
        let done = crate::telemetry::try_memory_purge(true);
        return Some(Response::json(
            200,
            &format!("{{\"ok\":true,\"purged\":{}}}", if done { 1 } else { 0 }),
        ));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/memory/status" {
        let (limit, auto, used_ev) = crate::telemetry::memory_status();
        let body = format!(
            "{{\"limit\":{},\"auto\":{},\"used_events\":{}}}",
            limit,
            if auto { 1 } else { 0 },
            used_ev
        );
        return Some(Response::json(200, &body));
    }
    None
}
