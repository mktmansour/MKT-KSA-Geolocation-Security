// Arabic: معالج دفع سحابي اختياري
// English: Optional cloud push handler

use crate::api::std_http::utils::extract_str;
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/cloud/push?") {
        if !crate::telemetry::cloud_enabled() {
            return Some(Response::json(
                403,
                "{\"ok\":false,\"err\":\"cloud disabled\"}",
            ));
        }
        if let Some(_url) = extract_str(&req.path, "url=") {
            #[cfg(all(feature = "egress", feature = "egress_http_std"))]
            {
                use std::io::Write;
                use std::net::TcpStream;
                let payload = crate::telemetry::metrics_json();
                if let Ok((host, port, path)) = super::super::super::webhook::parse_http_url(&_url)
                {
                    if let Ok(mut s) = TcpStream::connect((host.as_str(), port)) {
                        let req_line = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, host, payload.len());
                        let _ = s.write_all(req_line.as_bytes());
                        let _ = s.write_all(payload.as_bytes());
                        return Some(Response::json(200, "{\"ok\":true}"));
                    }
                }
            }
            return Some(Response::json(
                400,
                "{\"ok\":false,\"err\":\"push failed or egress disabled\"}",
            ));
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"url missing\"}",
        ));
    }
    None
}
