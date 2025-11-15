// Arabic: إعداد التنبيهات
// English: Alerts configuration

use crate::api::std_http::utils::{extract_str, extract_u64, extract_u8};
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/alerts/set?") {
        let risk = extract_u8(&req.path, "risk=").unwrap_or(80);
        let cooldown = extract_u64(&req.path, "cooldown=").unwrap_or(300);
        let email = extract_str(&req.path, "email=");
        let url = extract_str(&req.path, "url=");
        crate::telemetry::set_alert_config(risk, email, url, cooldown);
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/alerts/disable" {
        crate::telemetry::disable_alerts();
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    None
}
