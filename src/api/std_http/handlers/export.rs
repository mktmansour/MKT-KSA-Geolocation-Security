// Arabic: معالجات التصدير (CSV)
// English: Export handlers (CSV)

use crate::api::std_http::utils::extract_str;
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/export/csv?") {
        if !crate::telemetry::csv_export_enabled() {
            return Some(Response::json(
                403,
                "{\"ok\":false,\"err\":\"csv disabled\"}",
            ));
        }
        let typ = extract_str(&req.path, "type=").unwrap_or_else(|| "metrics".to_string());
        if typ == "metrics" {
            let m = crate::telemetry::metrics_json();
            let body = format!(
                "type,value\nmetrics,{}\n",
                m.replace('\n', " ").replace('\"', "'")
            );
            return Some(Response {
                status: 200,
                content_type: "text/csv",
                body: body.into_bytes(),
                fingerprint_hex: None,
                headers: Vec::new(),
            });
        } else {
            let ev = crate::telemetry::events_ndjson();
            let body = format!("line\n{}", ev);
            return Some(Response {
                status: 200,
                content_type: "text/csv",
                body: body.into_bytes(),
                fingerprint_hex: None,
                headers: Vec::new(),
            });
        }
    }
    None
}
