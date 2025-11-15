// Arabic: معالجات النسخ الاحتياطي (تحميل/إرسال/موافقة/جدولة/تعطيل/بريد)
// English: Backup handlers: download/send/consent/schedule/disable/email

use crate::api::std_http::utils::{extract_str, extract_u64, extract_u8};
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
    // /backup/download
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/backup/download" {
        let data = crate::telemetry::export_events_ndjson();
        return Some(Response {
            status: 200,
            content_type: "application/x-ndjson",
            body: data,
            fingerprint_hex: None,
            headers: Vec::new(),
        });
    }
    // /backup/send?url=...&consent=...
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/send?") {
        if let Some(pos) = req.path.find("url=") {
            let _url = &req.path[pos + 4..];
            // optional consent
            if let Some(cpos) = req.path.find("consent=") {
                let token = &req.path[cpos + 8..];
                if !crate::telemetry::has_consent(token) {
                    return Some(Response::json(
                        403,
                        "{\"ok\":false,\"err\":\"consent required\"}",
                    ));
                }
            }
            #[cfg(all(feature = "egress", feature = "egress_http_std"))]
            {
                let data = crate::telemetry::export_events_ndjson();
                use std::io::Write;
                use std::net::TcpStream;
                if let Ok((host, port, path)) = super::super::super::webhook::parse_http_url(_url) {
                    if let Ok(mut s) = TcpStream::connect((host.as_str(), port)) {
                        let req_line = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, host, data.len());
                        let _ = s.write_all(req_line.as_bytes());
                        let _ = s.write_all(&data);
                        return Some(Response::json(200, "{\"ok\":true}"));
                    }
                }
            }
            return Some(Response::json(
                400,
                "{\"ok\":false,\"err\":\"send failed or feature disabled\"}",
            ));
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"url missing\"}",
        ));
    }
    // /backup/consent?token=...
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/consent?") {
        if let Some(pos) = req.path.find("token=") {
            let token = &req.path[pos + 6..];
            crate::telemetry::set_backup_consent(token.to_string());
            return Some(Response::json(200, "{\"ok\":true}"));
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"token missing\"}",
        ));
    }
    // /backup/schedule?interval=...&risk=...&url=...&email=...
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/schedule?") {
        let interval = extract_u64(&req.path, "interval=").unwrap_or(3600);
        let risk = extract_u8(&req.path, "risk=").unwrap_or(50);
        let dest_url = extract_str(&req.path, "url=");
        let dest_email = extract_str(&req.path, "email=");
        crate::telemetry::configure_backup(interval, dest_url, dest_email, risk);
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/backup/schedule/disable" {
        crate::telemetry::disable_backup();
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    // /backup/email?to=...
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/email?") {
        #[cfg(feature = "smtp_std")]
        {
            if let Some(pos) = req.path.find("to=") {
                let to = &req.path[pos + 3..];
                let data = crate::telemetry::events_ndjson();
                let (subj, body) = crate::telemetry::compose_backup_email(None, &data);
                if super::super::email::smtp_send_simple(to, &subj, &body).is_ok() {
                    return Some(Response::json(200, "{\"ok\":true}"));
                }
            }
            return Some(Response::json(
                400,
                "{\"ok\":false,\"err\":\"invalid email params\"}",
            ));
        }
        #[cfg(not(feature = "smtp_std"))]
        {
            return Some(Response::json(
                400,
                "{\"ok\":false,\"err\":\"smtp disabled\"}",
            ));
        }
    }
    None
}
