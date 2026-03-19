# 01. Quick Start

This page gets you from zero setup to a running secure service.

## 1. Prerequisites

- Rust toolchain compatible with project lockfile.
- Linux or containerized environment.
- Required environment variables for secure startup.

## 2. Clone and Build

```bash
git clone https://github.com/mktmansour/MKT-KSA-Geolocation-Security.git
cd MKT-KSA-Geolocation-Security
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## 3. Run the Service

```bash
API_KEY=change_me \
JWT_SECRET=replace_with_a_long_secret_32_chars_min \
DATABASE_URL=sqlite://data/app.db \
SECURITY_PROFILE=strict \
cargo run
```

## 4. First Validation Call

```bash
curl -sS http://127.0.0.1:8080/api/users/00000000-0000-0000-0000-000000000000 \
  -H "X-API-Key: change_me" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "X-Request-ID: quickstart-001"
```

Expected behavior:

- Returns structured JSON with trace-aware fields.
- Returns deterministic auth/security errors when input is invalid.
- Includes request correlation behavior via request id.

## 5. Quick Integration as Library

```rust
use mkt_ksa_geo_sec::core::device_fp::DeviceFingerprint;

fn main() {
    let fp = DeviceFingerprint::new();
    let out = fp.generate_adaptive_fingerprint("device123", "user1");
    println!("{}", out);
}
```

## 6. Next Step

Continue to [02. Architecture](02-Architecture.md) to understand the full control flow and trust decision model.

## Search Keywords

Rust quick start security API, Actix Web startup, geolocation engine setup, Rust security library integration.
