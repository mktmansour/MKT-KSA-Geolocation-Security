// Arabic: راوتر std_http وتسجيل نقطة الويب‑هوك
// English: std_http router and webhook endpoint registry

use super::{utils::*, Handler, Request, Response};
use std::sync::Arc;

mod handlers {
    pub mod alerts;
    pub mod anti_replay;
    pub mod backup;
    pub mod cloud;
    pub mod export;
    pub mod fw;
    pub mod keys;
    pub mod memory;
    pub mod policy;
    pub mod telemetry;
    pub mod templates;
    pub mod webhook;
    pub mod webhook_guard;
}

static WEBHOOK_ENDPOINT: std::sync::OnceLock<Arc<dyn crate::webhook::WebhookEndpoint>> =
    std::sync::OnceLock::new();

pub fn set_webhook_endpoint(ep: Arc<dyn crate::webhook::WebhookEndpoint>) {
    let _ = WEBHOOK_ENDPOINT.set(ep);
}

pub(crate) fn webhook_endpoint() -> Option<&'static Arc<dyn crate::webhook::WebhookEndpoint>> {
    WEBHOOK_ENDPOINT.get()
}

pub(crate) fn router_dispatch(handler: Handler, req: &Request) -> Response {
    // OAuth2 Endpoints
    if req.path.starts_with("/oauth/") {
        return super::oauth::handle_oauth2_request(req);
    }

    if let Some(r) = handlers::telemetry::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::fw::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::webhook::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::backup::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::export::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::cloud::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::webhook_guard::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::memory::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::anti_replay::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::keys::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::policy::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::alerts::try_handle(req) {
        return r;
    }
    if let Some(r) = handlers::templates::try_handle(req) {
        return r;
    }

    // Default webhook ingress
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/webhook/in" {
        if let Some(ep) = WEBHOOK_ENDPOINT.get() {
            let body_str = String::from_utf8_lossy(&req.body);
            match ep.receive(&body_str) {
                Ok(()) => {
                    crate::telemetry::inc_webhook_in_ok();
                    return Response::json(200, "{\"ok\":true}");
                }
                Err(e) => {
                    crate::telemetry::inc_webhook_in_err();
                    return Response::json(400, &format!("{{\"ok\":false,\"err\":\"{}\"}}", e));
                }
            }
        }
        return Response::json(404, "{\"error\":\"webhook endpoint not set\"}");
    }

    if req.method.eq_ignore_ascii_case("GET") && req.path == "/backup/download" {
        let data = crate::telemetry::export_events_ndjson();
        return Response {
            status: 200,
            content_type: "application/x-ndjson",
            body: data,
            fingerprint_hex: None,
            headers: Vec::new(),
        };
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/send?") {
        if let Some(pos) = req.path.find("url=") {
            let _url = &req.path[pos + 4..];
            if let Some(cpos) = req.path.find("consent=") {
                let token = &req.path[cpos + 8..];
                if !crate::telemetry::has_consent(token) {
                    return Response::json(403, "{\"ok\":false,\"err\":\"consent required\"}");
                }
            }
            #[cfg(all(feature = "egress", feature = "egress_http_std"))]
            {
                let _client = crate::security::egress_guard::http_client::std_impl::StdClient;
                let _policy = crate::security::egress_guard::policy::EgressPolicy::default();
                let data = crate::telemetry::export_events_ndjson();
                use std::io::Write;
                use std::net::TcpStream;
                if let Ok((host, port, path)) = super::super::webhook::parse_http_url(_url) {
                    if let Ok(mut s) = TcpStream::connect((host.as_str(), port)) {
                        let req_line = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, host, data.len());
                        let _ = s.write_all(req_line.as_bytes());
                        let _ = s.write_all(&data);
                        return Response::json(200, "{\"ok\":true}");
                    }
                }
            }
            return Response::json(
                400,
                "{\"ok\":false,\"err\":\"send failed or feature disabled\"}",
            );
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"url missing\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/consent?") {
        if let Some(pos) = req.path.find("token=") {
            let token = &req.path[pos + 6..];
            crate::telemetry::set_backup_consent(token.to_string());
            return Response::json(200, "{\"ok\":true}");
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"token missing\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/schedule?") {
        let interval = extract_u64(&req.path, "interval=").unwrap_or(3600);
        let risk = extract_u8(&req.path, "risk=").unwrap_or(50);
        let dest_url = extract_str(&req.path, "url=");
        let dest_email = extract_str(&req.path, "email=");
        crate::telemetry::configure_backup(interval, dest_url, dest_email, risk);
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/backup/schedule/disable" {
        crate::telemetry::disable_backup();
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/backup/email?") {
        #[cfg(feature = "smtp_std")]
        {
            if let Some(pos) = req.path.find("to=") {
                let to = &req.path[pos + 3..];
                let data = crate::telemetry::events_ndjson();
                let (subj, body) = crate::telemetry::compose_backup_email(None, &data);
                if super::email::smtp_send_simple(to, &subj, &body).is_ok() {
                    return Response::json(200, "{\"ok\":true}");
                }
            }
            return Response::json(400, "{\"ok\":false,\"err\":\"invalid email params\"}");
        }
        #[cfg(not(feature = "smtp_std"))]
        {
            return Response::json(400, "{\"ok\":false,\"err\":\"smtp disabled\"}");
        }
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/templates/set?") {
        let lang = extract_str(&req.path, "lang=").unwrap_or_else(|| "en".to_string());
        let subject = extract_str(&req.path, "subject=").unwrap_or_default();
        let body = extract_str(&req.path, "body=").unwrap_or_default();
        crate::telemetry::set_template(&lang, subject, body);
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/templates/default?") {
        let lang = extract_str(&req.path, "lang=").unwrap_or_else(|| "en".to_string());
        crate::telemetry::set_default_lang(&lang);
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/toggle") {
        let on = req.path.contains("compression=on");
        let off = req.path.contains("compression=off");
        if on {
            crate::telemetry::set_compression_enabled(true);
        }
        if off {
            crate::telemetry::set_compression_enabled(false);
        }
        return Response::json(200, &crate::telemetry::metrics_json());
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/features/enable?") {
        if let Some(name) = extract_str(&req.path, "name=") {
            match name.as_str() {
                "ai_insights" => crate::telemetry::set_ai_insights_enabled(true),
                "cloud" => crate::telemetry::set_cloud_enabled(true),
                "csv_export" => crate::telemetry::set_csv_export_enabled(true),
                _ => {}
            }
            return Response::json(200, "{\"ok\":true}");
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"name missing\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/features/disable?") {
        if let Some(name) = extract_str(&req.path, "name=") {
            match name.as_str() {
                "ai_insights" => crate::telemetry::set_ai_insights_enabled(false),
                "cloud" => crate::telemetry::set_cloud_enabled(false),
                "csv_export" => crate::telemetry::set_csv_export_enabled(false),
                _ => {}
            }
            return Response::json(200, "{\"ok\":true}");
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"name missing\"}");
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/export/csv?") {
        if !crate::telemetry::csv_export_enabled() {
            return Response::json(403, "{\"ok\":false,\"err\":\"csv disabled\"}");
        }
        let typ = extract_str(&req.path, "type=").unwrap_or_else(|| "metrics".to_string());
        if typ == "metrics" {
            let m = crate::telemetry::metrics_json();
            let body = format!(
                "type,value\nmetrics,{}\n",
                m.replace('\n', " ").replace('\"', "'")
            );
            return Response {
                status: 200,
                content_type: "text/csv",
                body: body.into_bytes(),
                fingerprint_hex: None,
                headers: Vec::new(),
            };
        } else {
            let ev = crate::telemetry::events_ndjson();
            let body = format!("line\n{}", ev);
            return Response {
                status: 200,
                content_type: "text/csv",
                body: body.into_bytes(),
                fingerprint_hex: None,
                headers: Vec::new(),
            };
        }
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/cloud/push?") {
        if !crate::telemetry::cloud_enabled() {
            return Response::json(403, "{\"ok\":false,\"err\":\"cloud disabled\"}");
        }
        if let Some(_url) = extract_str(&req.path, "url=") {
            #[cfg(all(feature = "egress", feature = "egress_http_std"))]
            {
                use std::io::Write;
                use std::net::TcpStream;
                let payload = crate::telemetry::metrics_json();
                if let Ok((host, port, path)) = super::super::webhook::parse_http_url(&_url) {
                    if let Ok(mut s) = TcpStream::connect((host.as_str(), port)) {
                        let req_line = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, host, payload.len());
                        let _ = s.write_all(req_line.as_bytes());
                        let _ = s.write_all(payload.as_bytes());
                        return Response::json(200, "{\"ok\":true}");
                    }
                }
            }
            return Response::json(
                400,
                "{\"ok\":false,\"err\":\"push failed or egress disabled\"}",
            );
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"url missing\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/webhook/guard/set?") {
        let path = extract_str(&req.path, "path=").unwrap_or_else(|| "/webhook/in".to_string());
        let alg = extract_str(&req.path, "alg=").unwrap_or_else(|| "hmac-sha512".to_string());
        let key_id = extract_str(&req.path, "key=").unwrap_or_else(|| "auth_hmac".to_string());
        let ts = extract_u64(&req.path, "ts=").unwrap_or(300_000);
        let required = extract_u8(&req.path, "required=").unwrap_or(1) != 0;
        let anti = extract_u8(&req.path, "replay=").unwrap_or(1) != 0;
        crate::webhook::guards::set_guard(crate::webhook::guards::GuardConfig {
            path,
            alg,
            key_id,
            required,
            ts_window_ms: ts,
            anti_replay_on: anti,
        });
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/webhook/guard/disable?") {
        if let Some(p) = extract_str(&req.path, "path=") {
            crate::webhook::guards::disable_guard(&p);
            return Response::json(200, "{\"ok\":true}");
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"path missing\"}");
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/webhook/guard/list" {
        let body = crate::webhook::guards::list_guards()
            .into_iter()
            .map(|g| format!("{{\"path\":\"{}\",\"alg\":\"{}\",\"key_id\":\"{}\",\"required\":{},\"ts_window_ms\":{},\"anti_replay_on\":{}}}", g.path, g.alg, g.key_id, if g.required {1}else{0}, g.ts_window_ms, if g.anti_replay_on {1}else{0}))
            .collect::<Vec<_>>()
            .join(",");
        return Response::json(200, &format!("[{}]", body));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/webhook/guard/stats" {
        let body = crate::telemetry::sig_paths_json();
        return Response::json(200, &body);
    }
    if req.method.eq_ignore_ascii_case("GET")
        && (req.path.starts_with("/cloud-management")
            || req.path.starts_with("/weather-upload")
            || req.path.starts_with("/client-upload")
            || req.path.starts_with("/full-upload")
            || req.path.starts_with("/performance-alerts")
            || req.path.starts_with("/performance-metrics")
            || req.path.starts_with("/memory-config")
            || req.path.starts_with("/memory-purge")
            || req.path.starts_with("/key-rotation")
            || req.path.starts_with("/anti-replay-config")
            || req.path.starts_with("/backup-schedule")
            || req.path.starts_with("/cloud-backup")
            || req.path.starts_with("/recovery-test")
            || req.path.starts_with("/crash-report")
            || req.path.starts_with("/logs")
            || req.path.starts_with("/export-pdf")
            || req.path.starts_with("/add-guard")
            || req.path.starts_with("/configure-guards")
            || req.path.starts_with("/oauth-clients")
            || req.path.starts_with("/performance-monitor")
            || req.path.starts_with("/crash-protection")
            || req.path.starts_with("/token-generator"))
    {
        return Response::json(404, "{\"ok\":false,\"err\":\"ui_removed\"}");
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/dashboard-new") {
        return Response::json(404, "{\"ok\":false,\"err\":\"dashboard_removed\"}");
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/dashboard") {
        return Response::json(404, "{\"ok\":false,\"err\":\"dashboard_removed\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/lang/set?") {
        let lang = extract_str(&req.path, "lang=").unwrap_or_else(|| "en".to_string());
        crate::telemetry::set_default_lang(&lang);
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/memory/config?") {
        let limit = extract_u64(&req.path, "limit=").unwrap_or(0);
        let auto = extract_u8(&req.path, "auto=").unwrap_or(0) != 0;
        crate::telemetry::set_memory_limit(limit, auto);
        crate::telemetry::record_event("mem_cfg", &format!("limit={} auto={}", limit, auto as u8));
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/memory/purge" {
        let done = crate::telemetry::try_memory_purge(true);
        return Response::json(
            200,
            &format!("{{\"ok\":true,\"purged\":{}}}", if done { 1 } else { 0 }),
        );
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/memory/status" {
        let (limit, auto, used_ev) = crate::telemetry::memory_status();
        let body = format!(
            "{{\"limit\":{},\"auto\":{},\"used_events\":{}}}",
            limit,
            if auto { 1 } else { 0 },
            used_ev
        );
        return Response::json(200, &body);
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/anti_replay/purge/config?")
    {
        let mode = extract_str(&req.path, "mode=").unwrap_or_else(|| "weekly".to_string());
        let sens = extract_u8(&req.path, "sensitivity=").unwrap_or(60);
        let window = extract_u64(&req.path, "window=").unwrap_or(300_000);
        let cap = extract_u64(&req.path, "capacity=").unwrap_or(1024) as usize;
        crate::crypto::key_rotation::configure_anti_replay_purge(&mode, sens, window, cap);
        crate::telemetry::record_event("ar_purge_cfg", &mode);
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/anti_replay/purge/disable" {
        crate::crypto::key_rotation::disable_anti_replay_purge();
        crate::telemetry::record_event("ar_purge_disable", "by operator");
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/anti_replay/purge/run" {
        crate::crypto::key_rotation::run_anti_replay_purge_now();
        crate::telemetry::record_event("ar_purge_run", "manual run");
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/anti_replay/purge/status" {
        let (en, mode, iv_ms, next_ms, sens, base_w, base_c) =
            crate::crypto::key_rotation::anti_replay_purge_status();
        let body = format!(
            "{{\"enabled\":{},\"mode\":\"{}\",\"interval_ms\":{},\"next_ms\":{},\"sensitivity\":{},\"base_window_ms\":{},\"base_capacity\":{}}}",
            if en {1}else{0}, mode, iv_ms, next_ms, sens, base_w, base_c
        );
        return Response::json(200, &body);
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/keys/auto/config?") {
        let th = extract_u8(&req.path, "threshold=").unwrap_or(85);
        let it = extract_u64(&req.path, "interval=").unwrap_or(300);
        let len = extract_u64(&req.path, "len=")
            .map(|v| v as usize)
            .unwrap_or(32);
        let ids = extract_str(&req.path, "ids=").unwrap_or_default();
        let list: Vec<String> = ids
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        crate::crypto::key_rotation::configure_auto_rotation(th, it, list, len);
        crate::telemetry::record_event("key_auto_cfg", "applied");
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/keys/auto/disable" {
        crate::crypto::key_rotation::disable_auto_rotation();
        crate::telemetry::record_event("key_auto_disable", "by operator");
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/keys/create?") {
        let id = extract_str(&req.path, "id=");
        let ver = extract_u64(&req.path, "ver=")
            .map(|v| v as u32)
            .unwrap_or(1);
        let len = extract_u64(&req.path, "len=")
            .map(|v| v as usize)
            .unwrap_or(32);
        let ts = extract_u64(&req.path, "ts=").unwrap_or(0);
        let fp = extract_str(&req.path, "fp=");
        if let Some(id) = id {
            let mgr = crate::crypto::key_rotation::key_manager();
            let res = mgr.create_key(&id, ver, len, fp, ts);
            if res.is_ok() {
                crate::telemetry::record_event("key_create", &id);
                return Response::json(200, "{\"ok\":true}");
            }
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"invalid params\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/keys/rotate?") {
        let id = extract_str(&req.path, "id=");
        let ver = extract_u64(&req.path, "ver=")
            .map(|v| v as u32)
            .unwrap_or(2);
        let len = extract_u64(&req.path, "len=")
            .map(|v| v as usize)
            .unwrap_or(32);
        let ts = extract_u64(&req.path, "ts=").unwrap_or(0);
        if let Some(id) = id {
            let mgr = crate::crypto::key_rotation::key_manager();
            if mgr.rotate_key(&id, ver, len, ts).is_ok() {
                crate::telemetry::record_event("key_rotate", &id);
                if let Some(ep) = WEBHOOK_ENDPOINT.get() {
                    let payload = format!(
                        "{{\"event\":\"key_rotated\",\"id\":\"{}\",\"ver\":{}}}",
                        id, ver
                    );
                    let _ = ep.receive(&payload);
                }
                return Response::json(200, "{\"ok\":true}");
            }
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"rotation failed\"}");
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/keys/meta?") {
        let ids = extract_str(&req.path, "id=").unwrap_or_default();
        let list: Vec<String> = ids
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let mgr = crate::crypto::key_rotation::key_manager();
        let metas = mgr.export_metadata_for(&list);
        let body = metas
            .into_iter()
            .map(|m| {
                format!(
                    "{{\"id\":\"{}\",\"ver\":{},\"created_ms\":{},\"status\":\"{:?}\"}}",
                    m.key_id.0, m.version, m.created_ms, m.status
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        return Response::json(200, &format!("[{}]", body));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/keys/export_hex?") {
        let ids = extract_str(&req.path, "id=").unwrap_or_default();
        let token = extract_str(&req.path, "consent=").unwrap_or_default();
        if token.is_empty() || !crate::telemetry::has_consent(&token) {
            return Response::json(403, "{\"ok\":false,\"err\":\"consent required\"}");
        }
        let list: Vec<String> = ids
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let mgr = crate::crypto::key_rotation::key_manager();
        let pairs = mgr.export_material_hex_for(&list);
        let body = pairs
            .into_iter()
            .map(|(m, hex)| {
                format!(
                    "{{\"id\":\"{}\",\"ver\":{},\"key_hex\":\"{}\"}}",
                    m.key_id.0, m.version, hex
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        return Response::json(200, &format!("[{}]", body));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path == "/policy/get" {
        let body = crate::security::inspection_policy::current_policy_json();
        return Response::json(200, &body);
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/policy/set?") {
        if let Ok(txt) = core::str::from_utf8(&req.body) {
            if let Some(_newp) = crate::security::inspection_policy::InboundPolicy::from_json(txt) {
                crate::security::inspection_policy::set_current_policy(_newp);
                crate::telemetry::record_event("policy_set", "runtime policy updated");
                return Response::json(200, "{\"ok\":true}");
            }
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"invalid policy json\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/policy/set_dsl" {
        if let Ok(txt) = core::str::from_utf8(&req.body) {
            if let Some(_newp) = crate::security::inspection_policy::InboundPolicy::from_dsl(txt) {
                crate::security::inspection_policy::set_current_policy(_newp);
                crate::telemetry::record_event("policy_set_dsl", "runtime policy updated via dsl");
                return Response::json(200, "{\"ok\":true}");
            }
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"invalid policy dsl\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/risk" {
        if let Ok(txt) = core::str::from_utf8(&req.body) {
            if let Some(pos) = txt.find("\"risk\":") {
                let num = txt[pos + 7..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>();
                if let Ok(v) = num.parse::<u8>() {
                    crate::telemetry::set_risk(v);
                    return Response::json(200, "{\"ok\":true}");
                }
            }
        }
        return Response::json(400, "{\"ok\":false,\"err\":\"invalid risk payload\"}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path.starts_with("/alerts/set?") {
        let risk = extract_u8(&req.path, "risk=").unwrap_or(80);
        let cooldown = extract_u64(&req.path, "cooldown=").unwrap_or(300);
        let email = extract_str(&req.path, "email=");
        let url = extract_str(&req.path, "url=");
        crate::telemetry::set_alert_config(risk, email, url, cooldown);
        return Response::json(200, "{\"ok\":true}");
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/alerts/disable" {
        crate::telemetry::disable_alerts();
        return Response::json(200, "{\"ok\":true}");
    }

    // Fallback to user handler
    handler(req)
}
