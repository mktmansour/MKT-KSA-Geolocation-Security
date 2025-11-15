/*!
خادم HTTP داخلي بسيط (صفر تبعية) لدعم نقاط إدخال الويب هوك وغيرها.
Simple zero-deps HTTP server to support webhook ingress and basic endpoints.
*/

// std_http module root (types/routers/io/security split into submodules)

// Dashboard UI removed: no UI rendering in library builds

// ------ Submodules (extracted) ------
// NOTE: These are internal and used to reduce file size while keeping logic intact
#![allow(unexpected_cfgs)]

#[path = "std_http/types.rs"]
mod types;
pub use types::{Handler, Request, Response};
#[path = "std_http/parser.rs"]
mod parser;
#[cfg(test)]
pub(crate) use parser::{parse_form_params, url_decode};

#[path = "std_http/oauth.rs"]
mod oauth;

// ------ Extracted internal modules ------
#[path = "std_http/security.rs"]
mod security;
pub(crate) use security::find_header;

#[path = "std_http/io.rs"]
mod io;
pub use io::{run, run_once, run_with_policy};

#[path = "std_http/http.rs"]
mod http;
pub(crate) use http::reason_phrase;

#[path = "std_http/utils.rs"]
mod utils;
// helpers used internally by router/handlers; no re-export needed here

#[path = "std_http/router.rs"]
mod router;
pub use router::set_webhook_endpoint;

#[path = "std_http/email.rs"]
mod email;

// ---- Minimal signature guard (optional via features) ----
#[cfg(feature = "sign_hmac")]
#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_sha512_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let out = hasher.finalize();
    to_hex(&out)
}

#[allow(dead_code)]
#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[allow(clippy::manual_is_multiple_of)]
#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_from_hex(s: &str) -> Option<Vec<u8>> {
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

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_find_header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_canonical_string(
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

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_verify_oauth2_request(req: &Request) -> Result<(), ()> {
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

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_verify_request_signature(req: &Request) -> Result<(), ()> {
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

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_run(addr: &str, handler: Handler) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let handler = handler.clone();
        if let Ok(mut s) = stream {
            thread::spawn(move || {
                let _ = handle_conn(&mut s, handler);
            });
        }
    }
    Ok(())
}

/// Arabic: خادم لطلبٍ واحد فقط (مفيد للاختبارات والتكامل).
/// English: Single-request server (useful for tests/integration).
#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_run_once(addr: &str, handler: Handler) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    if let Some(Ok(mut s)) = listener.incoming().next() {
        let _ = handle_conn(&mut s, handler);
    }
    Ok(())
}

/// تشغيل الخادم بسياسة تفتيش داخلية قبل استدعاء المعالج.
/// Run server with inbound inspection policy before invoking handler.
#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_run_with_policy(
    addr: &str,
    policy: crate::security::inspection_policy::InboundPolicy,
    handler: Handler,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let handler = handler.clone();
        let policy = policy.clone();
        if let Ok(mut s) = stream {
            thread::spawn(move || {
                let _ = handle_conn_with_policy(&mut s, policy, handler);
            });
        }
    }
    Ok(())
}

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_handle_conn(stream: &mut TcpStream, handler: Handler) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);

    // Split headers/body for inspection
    let (headers_raw, body_raw) = if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        (&buf[..idx], &buf[idx + 4..])
    } else {
        (&buf[..], &buf[..0])
    };

    // Build request
    #[cfg(feature = "compress_rle")]
    let mut req = parse_request(&buf);
    #[cfg(not(feature = "compress_rle"))]
    let req = parse_request(&buf);

    // Inspect input using live policy and compute incoming fingerprint
    let mut digest = crate::core::digest::StdHasherDigest::default();
    let inspection = if let Some(pol) = crate::security::inspection_policy::current_policy() {
        pol.evaluate_request(&req.method, &req.path, headers_raw, body_raw)
    } else {
        crate::security::inspection::inspect_and_fingerprint(
            &mut digest,
            crate::security::inspection::Limits::default(),
            headers_raw,
            body_raw,
        )
    };

    crate::telemetry::inc_inspected();

    if crate::telemetry::circuit_is_open() && req.path != "/metrics" {
        crate::telemetry::fw_block();
        let header = format!(
            "HTTP/1.1 503 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reason_phrase(503),
            33
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(b"{\"error\":\"service_unavailable\"}")?;
        return Ok(());
    }
    let mut resp = if inspection.ok {
        let mut signed_ok = true;
        let must_check = crate::webhook::guards::get_guard_for(&req.path).is_some()
            || req.path.starts_with("/keys/")
            || req.path.starts_with("/backup/")
            || req.path.starts_with("/alerts/")
            || req.path.starts_with("/webhook/guard/")
            || req.path.starts_with("/anti_replay/purge");
        if must_check {
            match verify_request_signature(&req) {
                Ok(()) => {
                    crate::telemetry::inc_sig_ok();
                    crate::telemetry::record_sig_ok_path(&req.path);
                    crate::webhook::guards::relax_guard_if_safe(&req.path);
                }
                Err(()) => {
                    crate::telemetry::inc_sig_err();
                    crate::telemetry::record_sig_err_path(&req.path);
                    crate::telemetry::adaptive_guard_tighten_for(&req.path);
                    signed_ok = false;
                }
            }
        }
        // After signature verification, optionally decompress inbound body for handlers
        #[cfg(feature = "compress_rle")]
        {
            if signed_ok && header_eq(&req.headers, "content-encoding", "rle") {
                match crate::utils::rle::rle_decompress(&req.body) {
                    Ok(dec) => {
                        crate::telemetry::inc_comp_in();
                        req.body = dec;
                    }
                    Err(_) => {
                        crate::telemetry::inc_blocked();
                        return write_error(stream, 400, "invalid rle body");
                    }
                }
            }
        }

        if !signed_ok {
            Response::json(401, "{\"error\":\"invalid_signature\"}")
        } else {
            router_dispatch(handler, &req)
        }
    } else {
        crate::telemetry::inc_blocked();
        Response::json(
            400,
            &format!(
                "{{\"error\":\"blocked\",\"reason\":{:?},\"fp\":\"{}\"}}",
                inspection.reason, inspection.fingerprint_hex
            ),
        )
    };

    // Compute outgoing fingerprint over response body
    let mut out_digest = crate::core::digest::StdHasherDigest::default();
    let out_fp = crate::security::fingerprint::fingerprint_payload(
        &mut out_digest,
        b"content-type:json",
        &resp.body,
    );
    crate::telemetry::inc_fp_out();
    resp.fingerprint_hex = Some(out_fp);

    // Optional outbound RLE compress
    #[cfg(feature = "compress_rle")]
    let mut body_to_send: Vec<u8> = resp.body.clone();
    #[cfg(not(feature = "compress_rle"))]
    let body_to_send: Vec<u8> = resp.body.clone();
    let mut extra_headers = String::new();
    #[cfg(feature = "compress_rle")]
    {
        if crate::telemetry::compression_enabled()
            && resp.content_type.contains("json")
            && body_to_send.len() > 512
        {
            body_to_send = crate::utils::rle::rle_compress(&body_to_send);
            crate::telemetry::inc_comp_out();
            extra_headers.push_str("Content-Encoding: rle\r\n");
        }
    }
    // Append custom response headers (e.g., Location)
    for (k, v) in &resp.headers {
        extra_headers.push_str(&format!("{}: {}\r\n", k, v));
    }

    // Send response with fingerprint header (custom)
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}Content-Length: {}\r\nX-Integrity-Fingerprint: {}\r\nConnection: close\r\n\r\n",
        resp.status, reason_phrase(resp.status), resp.content_type, extra_headers, body_to_send.len(), resp.fingerprint_hex.clone().unwrap_or_default()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body_to_send)?;
    // Adaptive telemetry observe
    let peer = stream.peer_addr().ok().map(|a| a.ip().to_string());
    crate::telemetry::observe_http(
        &req.method,
        &req.path,
        resp.status,
        headers_raw.len() + body_raw.len(),
        body_to_send.len(),
        peer.as_deref(),
    );
    // Memory auto-purge if configured and over limit
    if crate::telemetry::memory_status().1 {
        let _ = crate::telemetry::try_memory_purge(false);
    }
    if resp.status < 500 {
        crate::telemetry::fw_allow();
    } else {
        crate::telemetry::fw_block();
    }
    Ok(())
}

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_handle_conn_with_policy(
    stream: &mut TcpStream,
    policy: crate::security::inspection_policy::InboundPolicy,
    handler: Handler,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);

    // Split headers/body
    let (headers_raw, body_raw) = if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        (&buf[..idx], &buf[idx + 4..])
    } else {
        (&buf[..], &buf[..0])
    };

    #[cfg(feature = "compress_rle")]
    let mut req = parse_request(&buf);
    #[cfg(not(feature = "compress_rle"))]
    let req = parse_request(&buf);

    crate::telemetry::inc_inspected();
    let check = policy.evaluate_request(&req.method, &req.path, headers_raw, body_raw);

    let mut resp = if check.ok {
        let mut signed_ok = true;
        let must_check = crate::webhook::guards::get_guard_for(&req.path).is_some()
            || req.path.starts_with("/keys/")
            || req.path.starts_with("/backup/")
            || req.path.starts_with("/alerts/")
            || req.path.starts_with("/webhook/guard/")
            || req.path.starts_with("/anti_replay/purge");
        if must_check {
            match verify_request_signature(&req) {
                Ok(()) => {
                    crate::telemetry::inc_sig_ok();
                    crate::telemetry::record_sig_ok_path(&req.path);
                    crate::webhook::guards::relax_guard_if_safe(&req.path);
                }
                Err(()) => {
                    crate::telemetry::inc_sig_err();
                    crate::telemetry::record_sig_err_path(&req.path);
                    crate::telemetry::adaptive_guard_tighten_for(&req.path);
                    signed_ok = false;
                }
            }
        }
        // After signature verification, optionally decompress inbound body for handlers
        #[cfg(feature = "compress_rle")]
        {
            if signed_ok && header_eq(&req.headers, "content-encoding", "rle") {
                match crate::utils::rle::rle_decompress(&req.body) {
                    Ok(dec) => {
                        crate::telemetry::inc_comp_in();
                        req.body = dec;
                    }
                    Err(_) => {
                        crate::telemetry::inc_blocked();
                        return write_error(stream, 400, "invalid rle body");
                    }
                }
            }
        }

        if !signed_ok {
            Response::json(401, "{\"error\":\"invalid_signature\"}")
        } else {
            router_dispatch(handler, &req)
        }
    } else {
        crate::telemetry::inc_blocked();
        Response::json(
            400,
            &format!(
                "{{\"error\":\"blocked\",\"reason\":{:?},\"fp\":\"{}\"}}",
                check.reason, check.fingerprint_hex
            ),
        )
    };

    // Outgoing fingerprint header
    let mut out_digest = crate::core::digest::StdHasherDigest::default();
    let out_fp = crate::security::fingerprint::fingerprint_payload(
        &mut out_digest,
        b"content-type:json",
        &resp.body,
    );
    crate::telemetry::inc_fp_out();
    resp.fingerprint_hex = Some(out_fp);

    #[cfg(feature = "compress_rle")]
    let mut body_to_send: Vec<u8> = resp.body.clone();
    #[cfg(not(feature = "compress_rle"))]
    let body_to_send: Vec<u8> = resp.body.clone();
    let mut extra_headers = String::new();
    #[cfg(feature = "compress_rle")]
    {
        if crate::telemetry::compression_enabled()
            && resp.content_type.contains("json")
            && body_to_send.len() > 512
        {
            body_to_send = crate::utils::rle::rle_compress(&body_to_send);
            crate::telemetry::inc_comp_out();
            extra_headers.push_str("Content-Encoding: rle\r\n");
        }
    }
    // Append custom response headers (e.g., Location)
    for (k, v) in &resp.headers {
        extra_headers.push_str(&format!("{}: {}\r\n", k, v));
    }
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}Content-Length: {}\r\nX-Integrity-Fingerprint: {}\r\nConnection: close\r\n\r\n",
        resp.status, reason_phrase(resp.status), resp.content_type, extra_headers, body_to_send.len(), resp.fingerprint_hex.clone().unwrap_or_default()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body_to_send)?;
    let peer = stream.peer_addr().ok().map(|a| a.ip().to_string());
    crate::telemetry::observe_http(
        &req.method,
        &req.path,
        resp.status,
        headers_raw.len() + body_raw.len(),
        body_to_send.len(),
        peer.as_deref(),
    );
    if resp.status < 500 {
        crate::telemetry::fw_allow();
    } else {
        crate::telemetry::fw_block();
    }
    Ok(())
}

#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_parse_request(raw: &[u8]) -> Request {
    // Minimal parsing: METHOD PATH HTTP/1.1\r\n...\r\n\r\nBODY
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let (method, path) = if let Some(line1) = lines.next() {
        let mut parts = line1.split_whitespace();
        (
            parts.next().unwrap_or("").to_string(),
            parts.next().unwrap_or("/").to_string(),
        )
    } else {
        (String::new(), "/".to_string())
    };
    // collect headers
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let (k, v) = line.split_at(colon);
            headers.push((k.trim().to_ascii_lowercase(), v[1..].trim().to_string()));
        }
    }
    let body = if let Some(idx) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        raw[idx + 4..].to_vec()
    } else {
        Vec::new()
    };
    Request {
        method,
        path,
        headers,
        body,
    }
}

// Router moved to std_http/router.rs

// WEBHOOK_ENDPOINT moved to router.rs

#[cfg(feature = "compress_rle")]
#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_header_eq(headers: &[(String, String)], key: &str, val: &str) -> bool {
    headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case(key) && v.trim().eq_ignore_ascii_case(val))
}

#[cfg(feature = "compress_rle")]
#[cfg(FALSE)]
#[allow(dead_code)]
fn _deprecated_write_error(stream: &mut TcpStream, status: u16, msg: &str) -> std::io::Result<()> {
    let body = format!("{{\"error\":\"{}\"}}", msg);
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, reason_phrase(status), body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())
}

// smtp moved to email.rs

// extract helpers moved to utils.rs

/// Arabic: معالجة طلبات OAuth2 (للاختبارات فقط)
/// English: Handle OAuth2 requests (tests only)
#[cfg(test)]
fn handle_oauth2_request(req: &Request) -> Response {
    oauth::handle_oauth2_request(req)
}

#[cfg(test)]
mod tests;

// UI handlers fully removed in production library
