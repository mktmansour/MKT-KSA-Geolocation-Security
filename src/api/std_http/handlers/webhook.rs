// Arabic: معالج الويب‑هوك الافتراضي /webhook/in
// English: Default webhook ingress handler /webhook/in

use crate::api::std_http::router;
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/webhook/in" {
        if let Some(ep) = router::webhook_endpoint() {
            let body_str = String::from_utf8_lossy(&req.body);
            match ep.receive(&body_str) {
                Ok(()) => {
                    crate::telemetry::inc_webhook_in_ok();
                    return Some(Response::json(200, "{\"ok\":true}"));
                }
                Err(e) => {
                    crate::telemetry::inc_webhook_in_err();
                    return Some(Response::json(
                        400,
                        &format!("{{\"ok\":false,\"err\":\"{}\"}}", e),
                    ));
                }
            }
        }
        return Some(Response::json(
            404,
            "{\"error\":\"webhook endpoint not set\"}",
        ));
    }
    None
}
