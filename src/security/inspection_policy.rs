/*!
سياسات تفتيش الوارد (صفر تبعية): طرق مسموحة، مسارات مسموحة، وحدود أحجام.
Inbound inspection policies (zero‑deps): allowed methods, path prefixes, and size limits.
*/

use crate::core::digest::CoreDigest;
use crate::security::inspection::{inspect_and_fingerprint, InspectionResult, Limits};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone)]
pub struct InboundPolicy {
    pub allowed_methods: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    pub denied_path_prefixes: Vec<String>,
    pub allowed_content_types: Vec<String>,
    pub limits: Limits,
}

impl Default for InboundPolicy {
    fn default() -> Self {
        Self {
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_path_prefixes: vec!["/".into()],
            denied_path_prefixes: vec!["/internal".into(), "/admin".into()],
            allowed_content_types: vec![
                "application/json".into(),
                "text/plain".into(),
                "application/x-www-form-urlencoded".into(),
            ],
            limits: Limits::default(),
        }
    }
}

impl InboundPolicy {
    pub fn evaluate_request(
        &self,
        method: &str,
        path: &str,
        headers_raw: &[u8],
        body_raw: &[u8],
    ) -> InspectionResult {
        if !self
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            return InspectionResult {
                ok: false,
                reason: Some("method not allowed".into()),
                fingerprint_hex: fingerprint(headers_raw, body_raw),
            };
        }
        if !self
            .allowed_path_prefixes
            .iter()
            .any(|p| path.starts_with(p))
        {
            return InspectionResult {
                ok: false,
                reason: Some("path not allowed".into()),
                fingerprint_hex: fingerprint(headers_raw, body_raw),
            };
        }
        if self
            .denied_path_prefixes
            .iter()
            .any(|p| path.starts_with(p))
        {
            return InspectionResult {
                ok: false,
                reason: Some("path denied".into()),
                fingerprint_hex: fingerprint(headers_raw, body_raw),
            };
        }
        // Content-Type allowlist (basic parse from headers_raw)
        if let Some(ct) = find_header_value(headers_raw, b"content-type") {
            let ct_l = ct.to_ascii_lowercase();
            if !self
                .allowed_content_types
                .iter()
                .any(|v| ct_l.starts_with(v))
            {
                return InspectionResult {
                    ok: false,
                    reason: Some("content-type not allowed".into()),
                    fingerprint_hex: fingerprint(headers_raw, body_raw),
                };
            }
        }
        // تكييف الحدود مع المخاطر الحالية
        let limits = adapt_limits(self.limits);
        // تفتيش المحتوى وحساب البصمة
        let mut d = crate::core::digest::StdHasherDigest::default();
        inspect_and_fingerprint(&mut d, limits, headers_raw, body_raw)
    }

    /// Arabic: تحميل سياسة من JSON بسيط (سلاسل)، صفر تبعية
    /// English: Load policy from simple JSON (strings), zero‑deps
    pub fn from_json(json: &str) -> Option<Self> {
        let mut p = Self::default();
        if let Some(idx) = json.find("\"allowed_methods\"") {
            if let Some(arr) = extract_array_strings(&json[idx..]) {
                p.allowed_methods = arr;
            }
        }
        if let Some(idx) = json.find("\"allowed_path_prefixes\"") {
            if let Some(arr) = extract_array_strings(&json[idx..]) {
                p.allowed_path_prefixes = arr;
            }
        }
        if let Some(idx) = json.find("\"denied_path_prefixes\"") {
            if let Some(arr) = extract_array_strings(&json[idx..]) {
                p.denied_path_prefixes = arr;
            }
        }
        if let Some(idx) = json.find("\"allowed_content_types\"") {
            if let Some(arr) = extract_array_strings(&json[idx..]) {
                p.allowed_content_types = arr;
            }
        }
        if let Some(idx) = json.find("\"limits\"") {
            if let Some(obj) = extract_object(&json[idx..]) {
                if let Some(l) = parse_limits(&obj) {
                    p.limits = l;
                }
            }
        }
        Some(p)
    }

    /// Arabic: DSL نصّي مبسّط لضبط السياسة بدون تبعيات
    /// English: Minimal textual DSL to set policy without deps
    pub fn from_dsl(dsl: &str) -> Option<Self> {
        let mut p = Self::default();
        for raw in dsl.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let (k, v) = if let Some(pos) = line.find('=') {
                (&line[..pos].trim(), line[pos + 1..].trim())
            } else if let Some(pos) = line.find(':') {
                (&line[..pos].trim(), line[pos + 1..].trim())
            } else {
                continue;
            };
            let key = k.to_ascii_lowercase();
            // list helpers
            let list = |s: &str| -> Vec<String> {
                s.split(',')
                    .map(|x| x.trim())
                    .filter(|x| !x.is_empty())
                    .map(|x| x.to_string())
                    .collect()
            };
            if key == "allowed_methods" {
                p.allowed_methods = list(v);
                continue;
            }
            if key == "allowed_path_prefixes" {
                p.allowed_path_prefixes = list(v);
                continue;
            }
            if key == "denied_path_prefixes" {
                p.denied_path_prefixes = list(v);
                continue;
            }
            if key == "allowed_content_types" {
                p.allowed_content_types = list(v);
                continue;
            }
            if key == "limits.max_headers_bytes" {
                if let Ok(n) = v.parse::<usize>() {
                    p.limits.max_headers_bytes = n;
                }
                continue;
            }
            if key == "limits.max_body_bytes" {
                if let Ok(n) = v.parse::<usize>() {
                    p.limits.max_body_bytes = n;
                }
                continue;
            }
        }
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_disallowed_content_type() {
        let p = InboundPolicy::default();
        let headers = b"Content-Type: application/xml\r\n\r\n";
        let res = p.evaluate_request("POST", "/webhook/in", headers, b"<x/>");
        assert!(!res.ok);
        assert_eq!(res.reason.as_deref(), Some("content-type not allowed"));
    }
    #[test]
    fn allows_x_www_form_urlencoded() {
        let p = InboundPolicy::default();
        let headers = b"Content-Type: application/x-www-form-urlencoded\r\n\r\n";
        let res = p.evaluate_request(
            "POST",
            "/oauth/token",
            headers,
            b"grant_type=client_credentials",
        );
        assert!(res.ok);
    }
    #[test]
    fn denies_disallowed_method() {
        let p = InboundPolicy::default();
        let headers = b"Content-Type: application/json\r\n\r\n";
        let res = p.evaluate_request("PUT", "/any", headers, b"{}");
        assert!(!res.ok);
        assert_eq!(res.reason.as_deref(), Some("method not allowed"));
    }
}
// ---------- Runtime policy (zero-deps) ----------
static RUNTIME: OnceLock<Mutex<InboundPolicy>> = OnceLock::new();

pub fn set_current_policy(p: InboundPolicy) {
    *RUNTIME
        .get_or_init(|| Mutex::new(InboundPolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = p;
}

pub fn current_policy() -> Option<InboundPolicy> {
    let g = RUNTIME
        .get_or_init(|| Mutex::new(InboundPolicy::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Some(g)
}

pub fn current_policy_json() -> String {
    let p = current_policy().unwrap_or_default();
    format!(
        "{{\"allowed_methods\":{:?},\"allowed_path_prefixes\":{:?},\"denied_path_prefixes\":{:?},\"allowed_content_types\":{:?},\"limits\":{{\"max_headers_bytes\":{},\"max_body_bytes\":{}}}}}",
        p.allowed_methods,
        p.allowed_path_prefixes,
        p.denied_path_prefixes,
        p.allowed_content_types,
        p.limits.max_headers_bytes,
        p.limits.max_body_bytes
    )
}

fn fingerprint(headers: &[u8], body: &[u8]) -> String {
    let mut d = crate::core::digest::StdHasherDigest::default();
    d.hash_bytes(headers);
    d.hash_bytes(b"\n\n");
    d.hash_bytes(body);
    d.finalize_hex()
}

fn find_header_value(headers_raw: &[u8], key_lc: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(headers_raw);
    for line in text.split("\r\n") {
        if let Some(colon) = line.find(':') {
            let (k, v) = line.split_at(colon);
            if k.trim()
                .eq_ignore_ascii_case(&String::from_utf8_lossy(key_lc))
            {
                return Some(v[1..].trim().to_string());
            }
        }
    }
    None
}

fn adapt_limits(base: Limits) -> Limits {
    // Arabic: تنزيل الحدود عند ارتفاع المخاطر (من Telemetry) — صفر تبعية
    // English: Tighten limits when risk is high
    let risk = crate::telemetry::current_risk();
    if risk >= 80 {
        Limits {
            max_headers_bytes: base.max_headers_bytes / 2,
            max_body_bytes: base.max_body_bytes / 2,
        }
    } else if risk >= 50 {
        Limits {
            max_headers_bytes: base.max_headers_bytes * 3 / 4,
            max_body_bytes: base.max_body_bytes * 3 / 4,
        }
    } else {
        base
    }
}

fn extract_array_strings(s: &str) -> Option<Vec<String>> {
    let start = s.find('[')?;
    let rest = &s[start + 1..];
    let end = rest.find(']')?;
    let inner = &rest[..end];
    let mut out = Vec::new();
    for part in inner.split(',') {
        let t = part.trim();
        if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
            out.push(t[1..t.len() - 1].to_string());
        }
    }
    Some(out)
}

fn extract_object(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let mut depth = 0usize;
    let bytes = s.as_bytes();
    for i in start..bytes.len() {
        if bytes[i] == b'{' {
            depth += 1;
        }
        if bytes[i] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(s[start..=i].to_string());
            }
        }
    }
    None
}

fn parse_limits(obj: &str) -> Option<Limits> {
    fn num(s: &str, key: &str) -> Option<usize> {
        let k = format!("\"{}\"", key);
        let idx = s.find(&k)?;
        let rest = &s[idx + k.len()..];
        let pos = rest.find(|c: char| c.is_ascii_digit())?;
        let digits: String = rest[pos..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }
    Some(Limits {
        max_headers_bytes: num(obj, "max_headers_bytes")?,
        max_body_bytes: num(obj, "max_body_bytes")?,
    })
}
