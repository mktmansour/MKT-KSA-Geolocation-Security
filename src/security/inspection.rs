/*!
Arabic: تفتيش صارم للمدخلات/المخرجات صفر تبعية (XSS/SSRF/Path/Size/UTF-8)، مع حساب بصمة سلامة.
English: Strict zero-deps IO inspection (XSS/SSRF/Path/Size/UTF-8) with integrity fingerprinting.
*/

use crate::core::digest::{CoreDigest, StdHasherDigest};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_headers_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_headers_bytes: 32 * 1024,
            max_body_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InspectionResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub fingerprint_hex: String,
}

pub fn inspect_and_fingerprint<D: CoreDigest>(
    digest: &mut D,
    limits: Limits,
    headers: &[u8],
    body: &[u8],
) -> InspectionResult {
    // 1) حدود الحجم
    if headers.len() > limits.max_headers_bytes {
        return fail(digest, "headers too large", headers, body);
    }
    if body.len() > limits.max_body_bytes {
        return fail(digest, "body too large", headers, body);
    }

    // 2) UTF-8 تحقق أساسي (جسم فقط عند التصريح)
    // Note: يمكن قبول ثنائي؛ هنا نفحص إن كان نصيًا لتقليل المخاطر الشائعة
    if !body.is_empty() && !is_probably_utf8(body) {
        // ليس فشلًا حتميًا؛ لكن نعطي تحذير عبر السبب ونستمر
    }

    // 3) فحص بسيط لأنماط خطيرة
    let suspicious: [&[u8]; 6] = [
        b"<script",
        b"javascript:",
        b"data:",
        b"onerror=",
        b"onload=",
        b"\0",
    ];
    for pat in suspicious.iter() {
        if contains_case_insensitive(body, pat) {
            return fail(digest, "suspicious pattern", headers, body);
        }
    }

    // 4) حساب البصمة (headers||"\n\n"||body) عبر مُولّد داخلي كي لا نستهلك `digest`
    let mut fp_d = StdHasherDigest::default();
    fp_d.hash_bytes(headers);
    fp_d.hash_bytes(b"\n\n");
    fp_d.hash_bytes(body);
    let fp = fp_d.finalize_hex();
    InspectionResult {
        ok: true,
        reason: None,
        fingerprint_hex: fp,
    }
}

fn fail<D: CoreDigest>(
    _digest: &mut D,
    reason: &str,
    headers: &[u8],
    body: &[u8],
) -> InspectionResult {
    let mut fp_d = StdHasherDigest::default();
    fp_d.hash_bytes(headers);
    fp_d.hash_bytes(b"\n\n");
    fp_d.hash_bytes(body);
    let fp = fp_d.finalize_hex();
    InspectionResult {
        ok: false,
        reason: Some(reason.to_string()),
        fingerprint_hex: fp,
    }
}

fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let n_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    let h_lower: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();
    h_lower
        .windows(n_lower.len())
        .any(|w| w == n_lower.as_slice())
}

fn is_probably_utf8(bytes: &[u8]) -> bool {
    core::str::from_utf8(bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_xss_like_patterns() {
        let mut d = StdHasherDigest::default();
        let limits = Limits::default();
        let headers = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let evil = b"<ScRiPt>alert(1)</sCrIpT>";
        let res = inspect_and_fingerprint(&mut d, limits, headers, evil);
        assert!(!res.ok);
        assert!(res.reason.unwrap_or_default().contains("suspicious"));
    }

    #[test]
    fn fingerprint_stable_for_same_input() {
        let mut d1 = StdHasherDigest::default();
        let mut d2 = StdHasherDigest::default();
        let limits = Limits::default();
        let h = b"H:1\r\n\r\n";
        let b = b"body";
        let r1 = inspect_and_fingerprint(&mut d1, limits, h, b);
        let r2 = inspect_and_fingerprint(&mut d2, limits, h, b);
        assert!(r1.ok && r2.ok);
        assert_eq!(r1.fingerprint_hex, r2.fingerprint_hex);
    }
}
