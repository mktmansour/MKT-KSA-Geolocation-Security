// Arabic: معالجات القياس وتيار الأحداث
// English: Telemetry handlers: /metrics and /events.ndjson

use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/metrics" {
        return Some(Response::json(200, &crate::telemetry::metrics_json()));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/events.ndjson" {
        return Some(Response {
            status: 200,
            content_type: "application/x-ndjson",
            body: crate::telemetry::events_ndjson().into_bytes(),
            fingerprint_hex: None,
            headers: Vec::new(),
        });
    }
    None
}
