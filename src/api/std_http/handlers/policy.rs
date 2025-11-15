// Arabic: سياسة التفتيش (جلب/تعيين JSON/تعيين DSL)
// English: Inspection policy (get/set JSON/set DSL)

use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/policy/get" {
        let body = crate::security::inspection_policy::current_policy_json();
        return Some(Response::json(200, &body));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/policy/set?") {
        if let Ok(txt) = core::str::from_utf8(&req.body) {
            if let Some(_newp) = crate::security::inspection_policy::InboundPolicy::from_json(txt) {
                crate::security::inspection_policy::set_current_policy(_newp);
                crate::telemetry::record_event("policy_set", "runtime policy updated");
                return Some(Response::json(200, "{\"ok\":true}"));
            }
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"invalid policy json\"}",
        ));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/policy/set_dsl" {
        if let Ok(txt) = core::str::from_utf8(&req.body) {
            if let Some(_newp) = crate::security::inspection_policy::InboundPolicy::from_dsl(txt) {
                crate::security::inspection_policy::set_current_policy(_newp);
                crate::telemetry::record_event("policy_set_dsl", "runtime policy updated via dsl");
                return Some(Response::json(200, "{\"ok\":true}"));
            }
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"invalid policy dsl\"}",
        ));
    }
    None
}
