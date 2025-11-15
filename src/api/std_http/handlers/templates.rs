// Arabic: إدارة القوالب (templates)
// English: Templates handlers

use crate::api::std_http::utils::extract_str;
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/templates/set?") {
        let lang = extract_str(&req.path, "lang=").unwrap_or_else(|| "en".to_string());
        let subject = extract_str(&req.path, "subject=").unwrap_or_default();
        let body = extract_str(&req.path, "body=").unwrap_or_default();
        crate::telemetry::set_template(&lang, subject, body);
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/templates/default?") {
        let lang = extract_str(&req.path, "lang=").unwrap_or_else(|| "en".to_string());
        crate::telemetry::set_default_lang(&lang);
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    None
}
