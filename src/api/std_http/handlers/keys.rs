// Arabic: إدارة المفاتيح (تكوين تلقائي/تعطيل/إنشاء/تدوير/تعريف/تصدير)
// English: Keys management (auto-config/disable/create/rotate/meta/export_hex)

use crate::api::std_http::utils::{extract_str, extract_u64, extract_u8};
use crate::api::std_http::{Request, Response};

pub fn try_handle(req: &Request) -> Option<Response> {
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
        return Some(Response::json(200, "{\"ok\":true}"));
    }
    if req.method.eq_ignore_ascii_case("POST") && req.path == "/keys/auto/disable" {
        crate::crypto::key_rotation::disable_auto_rotation();
        crate::telemetry::record_event("key_auto_disable", "by operator");
        return Some(Response::json(200, "{\"ok\":true}"));
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
                return Some(Response::json(200, "{\"ok\":true}"));
            }
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"invalid params\"}",
        ));
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
                return Some(Response::json(200, "{\"ok\":true}"));
            }
        }
        return Some(Response::json(
            400,
            "{\"ok\":false,\"err\":\"rotation failed\"}",
        ));
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
        return Some(Response::json(200, &format!("[{}]", body)));
    }
    if req.method.eq_ignore_ascii_case("GET") && req.path.starts_with("/keys/export_hex?") {
        let ids = extract_str(&req.path, "id=").unwrap_or_default();
        let token = extract_str(&req.path, "consent=").unwrap_or_default();
        if token.is_empty() || !crate::telemetry::has_consent(&token) {
            return Some(Response::json(
                403,
                "{\"ok\":false,\"err\":\"consent required\"}",
            ));
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
        return Some(Response::json(200, &format!("[{}]", body)));
    }
    None
}
