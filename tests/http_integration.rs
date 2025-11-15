#![cfg(all(feature = "api_std_http"))]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

#[test]
fn std_http_basic_metrics() {
    // start server in background thread (single request)
    std::thread::spawn(|| {
        let handler: mkt_ksa_geo_sec::api::std_http::Handler =
            Arc::new(|_req| mkt_ksa_geo_sec::api::std_http::Response::json(200, "{\"ok\":true}"));
        let _ = mkt_ksa_geo_sec::api::std_http::run_once("127.0.0.1:8099", handler);
    });

    // Give it a moment to bind
    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut s = TcpStream::connect("127.0.0.1:8099").expect("connect");
    let req = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
    s.write_all(req).expect("write");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok();
    let txt = String::from_utf8_lossy(&buf);
    assert!(txt.contains("200 OK"));
    assert!(txt.contains("\"inspected\""));
}
