// Arabic: ميزات المطور وتفضيلات اللغة والضغط
// English: Features toggles, language preference, compression toggle

use crate::api::std_http::{Request, Response};
use crate::api::std_http::utils::extract_str;

pub fn try_handle(req: &Request) -> Option<Response> {
    // /toggle?compression=on|off
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/toggle") {
        let on = req.path.contains("compression=on");
        let off = req.path.contains("compression=off");
        if on {
            crate::telemetry::set_compression_enabled(true);
        }
        if off {
            crate::telemetry::set_compression_enabled(false);
        }
        return Some(Response::json(200, &crate::telemetry::metrics_json()));
    }
    // /features/enable?name=...
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/features/enable?") {
        if let Some(name) = extract_str(&req.path, "name=") {
            match name.as_str() {
                "ai_insights" => crate::telemetry::set_ai_insights_enabled(true),
                "cloud" => crate::telemetry::set_cloud_enabled(true),
                "csv_export" => crate::telemetry::set_csv_export_enabled(true),
                _ => {}
            }
            return Some(Response::json(200, "{\"ok\":true}"));
        }
        return Some(Response::json(400, "{\"ok\":false,\"err\":\"name missing\"}"));
    }
    // /features/disable?name=...
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/features/disable?") {
        if let Some(name) = extract_str(&req.path, "name=") {
            match name.as_str() {
                "ai_insights" => crate::telemetry::set_ai_insights_enabled(false),
                "cloud" => crate::telemetry::set_cloud_enabled(false),
                "csv_export" => crate::telemetry::set_csv_export_enabled(false),
                _ => {}
            }
            return Some(Response::json(200, "{\"ok\":true}"));
        }
        return Some(Response::json(400, "{\"ok\":false,\"err\":\"name missing\"}"));
    }
    // /lang/set?lang=...
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/lang/set?") {
        let lang = extract_str(&req.path, "lang=").unwrap_or_else(|| "en".to_string());
        crate::telemetry::set_default_lang(&lang);
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    None
}


