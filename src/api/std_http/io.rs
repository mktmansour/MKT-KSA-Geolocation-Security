// Arabic: طبقة الإدخال/الإخراج لخادم std_http (تشغيل واتصال وكتابة الاستجابة)
// English: std_http IO layer (run/connection/response writing)

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use super::Handler;
use super::{reason_phrase, security, Request, Response};

pub fn run(addr: &str, handler: Handler) -> std::io::Result<()> {
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

pub fn run_once(addr: &str, handler: Handler) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    if let Some(Ok(mut s)) = listener.incoming().next() {
        let _ = handle_conn(&mut s, handler);
    }
    Ok(())
}

pub fn run_with_policy(
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

fn handle_conn(stream: &mut TcpStream, handler: Handler) -> std::io::Result<()> {
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
            match security::verify_request_signature(&req) {
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
            super::router::router_dispatch(handler, &req)
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

fn handle_conn_with_policy(
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
            match security::verify_request_signature(&req) {
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
            super::router::router_dispatch(handler, &req)
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

pub(crate) fn parse_request(raw: &[u8]) -> Request {
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

#[cfg(feature = "compress_rle")]
fn header_eq(headers: &[(String, String)], key: &str, val: &str) -> bool {
    headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case(key) && v.trim().eq_ignore_ascii_case(val))
}

#[cfg(feature = "compress_rle")]
fn write_error(stream: &mut TcpStream, status: u16, msg: &str) -> std::io::Result<()> {
    let body = format!("{{\"error\":\"{}\"}}", msg);
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, reason_phrase(status), body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())
}
