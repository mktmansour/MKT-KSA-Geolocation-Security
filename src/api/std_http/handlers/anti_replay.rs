// Arabic: إدارة تنظيف منع الإعادة (anti-replay purge)
// English: Anti-replay purge management

use crate::api::std_http::utils::{extract_str, extract_u64, extract_u8};
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/anti_replay/purge/config?")
    {
        let mode = extract_str(&req.path, "mode=").unwrap_or_else(|| "weekly".to_string());
        let sens = extract_u8(&req.path, "sensitivity=").unwrap_or(60);
        let window = extract_u64(&req.path, "window=").unwrap_or(300_000);
        let cap = extract_u64(&req.path, "capacity=").unwrap_or(1024) as usize;
        crate::crypto::key_rotation::configure_anti_replay_purge(&mode, sens, window, cap);
        crate::telemetry::record_event("ar_purge_cfg", &mode);
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/anti_replay/purge/disable" {
        crate::crypto::key_rotation::disable_anti_replay_purge();
        crate::telemetry::record_event("ar_purge_disable", "by operator");
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/anti_replay/purge/run" {
        crate::crypto::key_rotation::run_anti_replay_purge_now();
        crate::telemetry::record_event("ar_purge_run", "manual run");
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/anti_replay/purge/status" {
        let (en, mode, iv_ms, next_ms, sens, base_w, base_c) =
            crate::crypto::key_rotation::anti_replay_purge_status();
        let body = format!(
            "{{\"enabled\":{},\"mode\":\"{}\",\"interval_ms\":{},\"next_ms\":{},\"sensitivity\":{},\"base_window_ms\":{},\"base_capacity\":{}}}",
            if en {1}else{0}, mode, iv_ms, next_ms, sens, base_w, base_c
        );
        return Some(Response::json(200, &body));
    }
    None
}
