// Arabic: وظائف الأمن والتوقيع والتحقق (جزء std_http)
// English: Security, signing, and verification helpers (std_http part)

use super::Request;

#[allow(dead_code)]
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[allow(clippy::manual_is_multiple_of)]
pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)? as u8;
        let lo = (bytes[i + 1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

pub(crate) fn find_header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

#[cfg(feature = "sign_hmac")]
fn sha512_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let out = hasher.finalize();
    to_hex(&out)
}

pub(crate) fn canonical_string(
    method: &str,
    path: &str,
    content_type: &str,
    ts: &str,
    nonce: &str,
    body: &[u8],
    #[allow(unused_variables)] host: &str,
) -> String {
    #[cfg(feature = "sign_hmac")]
    let body_hash = sha512_hex(body);
    #[cfg(not(feature = "sign_hmac"))]
    let body_hash = body.len().to_string();
    #[cfg(feature = "sign_host")]
    {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            method, path, content_type, ts, nonce, body_hash, host
        )
    }
    #[cfg(not(feature = "sign_host"))]
    {
        format!(
            "{}|{}|{}|{}|{}|{}",
            method, path, content_type, ts, nonce, body_hash
        )
    }
}

pub(crate) fn verify_oauth2_request(req: &Request) -> Result<(), ()> {
    let oauth2_guards = crate::oauth2::guards_oauth2::create_oauth2_guards();
    let guard = oauth2_guards
        .iter()
        .find(|g| req.path.starts_with(&g.path))
        .cloned()
        .unwrap_or_else(|| crate::webhook::guards::GuardConfig {
            path: req.path.clone(),
            alg: "oauth2".to_string(),
            key_id: "oauth2_default".to_string(),
            required: true,
            ts_window_ms: 300_000,
            anti_replay_on: true,
        });
    if let Some(auth_header) = find_header(&req.headers, "authorization") {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            if crate::oauth2::guards_oauth2::validate_oauth2_token(token).is_ok() {
                return Ok(());
            }
        }
    }
    if req.method == "POST" && req.path == "/oauth/token" {
        if let Ok(body_str) = std::str::from_utf8(&req.body) {
            if body_str.contains("client_id") {
                return Ok(());
            }
        }
    }
    if guard.required {
        Err(())
    } else {
        Ok(())
    }
}

pub(crate) fn verify_request_signature(req: &Request) -> Result<(), ()> {
    // Check if this is an OAuth2 endpoint
    if req.path.starts_with("/oauth/") {
        return verify_oauth2_request(req);
    }

    // Enforce only for HMAC-SHA512 at the moment
    let guard = crate::webhook::guards::get_guard_for(&req.path).unwrap_or_else(|| {
        crate::webhook::guards::GuardConfig {
            path: req.path.clone(),
            ..crate::webhook::guards::GuardConfig::default()
        }
    });
    if guard.alg != "hmac-sha512" {
        return if guard.required { Err(()) } else { Ok(()) };
    }
    let key_id = match find_header(&req.headers, "x-mkt-keyid").or(Some(guard.key_id.as_str())) {
        Some(v) => v,
        None => {
            return if guard.required { Err(()) } else { Ok(()) };
        }
    };
    let ts = match find_header(&req.headers, "x-mkt-timestamp") {
        Some(v) => v,
        None => return if guard.required { Err(()) } else { Ok(()) },
    };
    let nonce = match find_header(&req.headers, "x-mkt-nonce") {
        Some(v) => v,
        None => return if guard.required { Err(()) } else { Ok(()) },
    };
    let sig_hex = match find_header(&req.headers, "x-mkt-signature") {
        Some(v) => v,
        None => return if guard.required { Err(()) } else { Ok(()) },
    };
    let sig = match from_hex(sig_hex) {
        Some(v) => v,
        None => return if guard.required { Err(()) } else { Ok(()) },
    };
    let ctype = find_header(&req.headers, "content-type").unwrap_or("");
    let host = find_header(&req.headers, "host").unwrap_or("");
    let canon = canonical_string(&req.method, &req.path, ctype, ts, nonce, &req.body, host);
    // Reject stale timestamps (5 minutes window)
    if let Ok(ts_num) = ts.parse::<u128>() {
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => 0,
        };
        if now.saturating_sub(ts_num) > guard.ts_window_ms as u128 {
            return if guard.required { Err(()) } else { Ok(()) };
        }
    }
    // Anti-replay per key using nonce
    let mgr = crate::crypto::key_rotation::key_manager();
    if guard.anti_replay_on
        && mgr
            .check_and_mark_nonce(key_id, nonce.as_bytes(), {
                match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                    Ok(d) => d.as_millis() as u64,
                    Err(_) => 0,
                }
            })
            .is_err()
    {
        return if guard.required { Err(()) } else { Ok(()) };
    }
    // Verify HMAC when feature available; otherwise treat as disabled
    #[cfg(feature = "sign_hmac")]
    {
        if let Ok((_, key)) = mgr.get(key_id) {
            let ok = crate::security::signing::verify_hmac_sha512(canon.as_bytes(), &sig, &key);
            if ok {
                Ok(())
            } else if guard.required {
                Err(())
            } else {
                Ok(())
            }
        } else if guard.required {
            Err(())
        } else {
            Ok(())
        }
    }
    #[cfg(not(feature = "sign_hmac"))]
    {
        let _ = (canon, sig);
        // Fail-closed for required HMAC paths when signing feature is disabled
        if guard.required {
            return Err(());
        }
        Ok(())
    }
}
