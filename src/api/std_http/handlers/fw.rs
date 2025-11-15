// Arabic: معالجات جدار الحماية (fw): فتح/إغلاق وإظهار المقاييس
// English: Firewall handlers: /fw/metrics, /fw/open, /fw/close

use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/fw/metrics" {
        let body = crate::telemetry::metrics_json();
        return Some(Response::json(200, &body));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/fw/open" {
        crate::telemetry::set_risk(95);
        crate::telemetry::record_event("fw_open", "manual open by operator");
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/fw/close" {
        crate::telemetry::set_risk(0);
        crate::telemetry::record_event("fw_close", "manual close by operator");
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    None
}
