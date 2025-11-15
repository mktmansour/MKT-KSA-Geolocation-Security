/*! Arabic: عميل HMAC بسيط لاختبار توقيع الطلبات إلى الخادم المحلي.
English: Simple HMAC client to test signed requests to the local server. */

#[cfg(feature = "sign_hmac")]
fn main() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    #[allow(clippy::manual_is_multiple_of)]
    fn from_hex(s: &str) -> Option<Vec<u8>> {
        let b = s.as_bytes();
        if b.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(b.len() / 2);
        let to_n = |c: u8| -> Option<u8> { (c as char).to_digit(16).map(|v| v as u8) };
        for i in (0..b.len()).step_by(2) {
            let hi = to_n(b[i])?;
            let lo = to_n(b[i + 1])?;
            out.push((hi << 4) | lo);
        }
        Some(out)
    }

    fn sha512_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(data);
        let out = h.finalize();
        to_hex(&out)
    }

    fn hmac_sha512_hex(key: &[u8], msg: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC key");
        mac.update(msg);
        let sig = mac.finalize().into_bytes();
        to_hex(&sig)
    }

    fn canonical(
        method: &str,
        path: &str,
        ctype: &str,
        ts: &str,
        nonce: &str,
        body: &[u8],
        host: &str,
    ) -> String {
        let body_hash = sha512_hex(body);
        #[cfg(feature = "sign_host")]
        {
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                method, path, ctype, ts, nonce, body_hash, host
            )
        }
        #[cfg(not(feature = "sign_host"))]
        {
            format!(
                "{}|{}|{}|{}|{}|{}",
                method, path, ctype, ts, nonce, body_hash
            )
        }
    }

    fn now_ms() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }

    let key_hex =
        std::env::var("MKT_AUTH_HMAC_HEX").expect("Set MKT_AUTH_HMAC_HEX to sign requests");
    let key = from_hex(&key_hex).expect("MKT_AUTH_HMAC_HEX must be valid hex");
    let key_id = "auth_hmac";

    // Test 1: GET /metrics
    {
        let method = "GET";
        let path = "/metrics";
        let ctype = "application/json";
        let body = b"";
        let ts = now_ms().to_string();
        let nonce = format!("nonce-{}", now_ms());
        let host = "127.0.0.1:8080";
        let canon = canonical(method, path, ctype, &ts, &nonce, body, host);
        let sig = hmac_sha512_hex(&key, canon.as_bytes());
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: 0\r\nConnection: close\r\nx-mkt-keyid: {}\r\nx-mkt-timestamp: {}\r\nx-mkt-nonce: {}\r\nx-mkt-signature: {}\r\n\r\n",
            path, host, ctype, key_id, ts, nonce, sig
        );
        let mut s = TcpStream::connect("127.0.0.1:8080").expect("connect");
        s.write_all(req.as_bytes()).expect("write");
        s.shutdown(std::net::Shutdown::Write).ok();
        let mut resp = String::new();
        s.read_to_string(&mut resp).ok();
        println!(
            "[metrics]\n{}",
            resp.lines().take(3).collect::<Vec<_>>().join("\n")
        );
    }

    // Test 2: POST /webhook/in
    {
        let method = "POST";
        let path = "/webhook/in";
        let ctype = "application/json";
        let body = format!("{{\"msg\":\"hello\",\"ts\":{}}}", now_ms());
        let ts = now_ms().to_string();
        let nonce = format!("nonce-{}", now_ms());
        let host = "127.0.0.1:8080";
        let canon = canonical(method, path, ctype, &ts, &nonce, body.as_bytes(), host);
        let sig = hmac_sha512_hex(&key, canon.as_bytes());
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nx-mkt-keyid: {}\r\nx-mkt-timestamp: {}\r\nx-mkt-nonce: {}\r\nx-mkt-signature: {}\r\n\r\n{}",
            path, host, ctype, body.len(), key_id, ts, nonce, sig, body
        );
        let mut s = TcpStream::connect("127.0.0.1:8080").expect("connect");
        s.write_all(req.as_bytes()).expect("write");
        s.shutdown(std::net::Shutdown::Write).ok();
        let mut resp = String::new();
        s.read_to_string(&mut resp).ok();
        println!(
            "[webhook/in]\n{}",
            resp.lines().take(3).collect::<Vec<_>>().join("\n")
        );
    }

    // Test 3: GET /metrics without signature -> expect 401
    {
        let req = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n";
        let mut s = TcpStream::connect("127.0.0.1:8080").expect("connect");
        s.write_all(req.as_bytes()).expect("write");
        s.shutdown(std::net::Shutdown::Write).ok();
        let mut resp = String::new();
        s.read_to_string(&mut resp).ok();
        println!(
            "[metrics-unsigned]\n{}",
            resp.lines().take(3).collect::<Vec<_>>().join("\n")
        );
    }
}

#[cfg(not(feature = "sign_hmac"))]
fn main() {
    println!("Enable feature sign_hmac to build this client.");
}
