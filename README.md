# MKT-KSA-Geolocation-Security

A zero-dependency standard HTTP library (pure Rust) for secure Webhook/API ingestion. It ships with HMAC‑SHA512 request signing (Host binding optional), an RFC‑aware OAuth2 implementation (from scratch), adaptive security guards, and production‑grade CI/CD.

Production builds are UI‑free by design: the library exposes API/Webhook endpoints only. A small demo binary is included for local verification.




# MKT KSA Geolocation Security

<div align="center">

### Zero-Dependency Sovereign Security Library for Sensitive Applications

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-success.svg)](Cargo.toml)
[![Security](https://img.shields.io/badge/security-sovereign-critical.svg)](#security)

</div>

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Target Audience](#target-audience)
3. [Key Advantages](#key-advantages)
4. [Use Cases & Applications](#use-cases--applications)
5. [Architecture](#architecture)
6. [Core Features](#core-features)
7. [Installation](#installation)
8. [Quick Start](#quick-start)
9. [API Routes](#api-routes)
10. [Webhook Guards](#webhook-guards)
11. [Key Rotation](#key-rotation)
12. [Dashboard](#dashboard)
13. [Export & Cloud Integration](#export--cloud-integration)
14. [FFI Interface](#ffi-interface)
15. [Optional Features](#optional-features)
16. [Usage Examples](#usage-examples)
17. [Testing](#testing)
18. [Security](#security)
19. [License](#license)
20. [Contact](#contact)

---

## 🎯 Overview

**MKT KSA Geolocation Security** is a comprehensive sovereign security library developed in Rust, designed specifically for sensitive applications requiring **full digital sovereignty** and **zero external dependencies**.

The library provides a multi-layered security system including:
- Strict input/output inspection
- Digital integrity fingerprinting
- Automatic risk-based key rotation
- 50+ per-path webhook guards with HMAC-SHA512 signatures
- Smart Anti-Replay protection
- AI-driven adaptive telemetry
- Comprehensive dashboard with full EN/AR localization
- C-ABI FFI interface for multi-language integration

### 🏆 Why This Library?

✅ **Digital Sovereignty**: Zero external dependencies — no third-party libs, no supply-chain risks  
✅ **Multi-Layer Security**: Comprehensive protection from input to output  
✅ **Adaptive Intelligence**: Automatic tightening/relaxation based on risk level  
✅ **Full Transparency**: Monitor and export all metrics and events  
✅ **Flexibility & Scale**: 50+ ready API routes, runtime-updatable policies  
✅ **High Performance**: Lightweight and optimized core  

---

## 👥 Target Audience

### Government & Sovereign Application Developers
Those requiring zero-dependency security solutions to ensure full digital sovereignty and compliance with national standards.

### Cybersecurity Teams
Building advanced protection systems with strict inspection, integrity fingerprinting, and real-time intrusion detection.

### FinTech Developers
Needing automatic key rotation, strong digital signatures, and anti-replay protection for financial transactions.

### HealthTech Companies
Protecting sensitive patient data with precise telemetry and complete event tracking.

### IoT & Smart Device Platforms
Verifying device fingerprints, geolocation, and behavior to prevent spoofing and breaches.

### Embedded Systems Developers
Requiring lightweight zero-deps library with C-ABI FFI for integration with embedded systems.

### Security Researchers & Academics
Studying and implementing advanced security mechanisms (Anti-Replay, HMAC, key rotation, DSL policies).

### DevOps/SRE Teams
Monitoring security via centralized dashboard, metrics export, and cloud integration for SIEM systems.

---

## ⭐ Key Advantages

### 🛡️ Full Digital Sovereignty
- **Zero external dependencies by default** — no third-party libraries, no supply-chain risks
- All algorithms implemented internally without external imports
- Full source code control and auditable

### 🔐 Multi-Layer Security

#### Per-Path Webhook Guards
- 50+ independent guards with HMAC-SHA512 signatures
- Configurable timestamp windows per path
- Automatic tightening based on path sensitivity

#### Strong Anti-Replay Protection
- Nonce tracking to prevent request replay
- Adaptive purging (daily/weekly/monthly) based on load
- Configurable capacity and behavior

#### Strict Inspection
- XSS, SQL injection, and dangerous path detection
- Header and body size limits
- UTF-8 validation and safe content patterns

#### Egress Guard (SSRF Protection)
- Prevent SSRF and dangerous destinations
- Host/port allow/deny lists
- RFC1918 and private address detection

### 🤖 Adaptive AI Intelligence

#### Automatic Tightening/Relaxation
- Dynamic security adjustment based on risk level
- Timestamp window reduction on rising threats
- Safe relaxation when risks subside

#### Self-Rotating Keys
- Automatic rotation on exceeding risk threshold
- Multi-version support (N and N+1)
- Webhook notifications on rotation

#### Smart Anti-Replay Purge
- Adaptive scheduling (daily/weekly/monthly)
- Configurable sensitivity (0-100)
- Live statistics and status

### 📊 Full Transparency & Monitoring

#### Comprehensive Dashboard
- HTML/JSON with full EN/AR localization
- Live metrics for all counters
- Key rotation and anti-replay status
- Complete guards list with configurations

#### Multi-Format Export
- CSV compatible with Excel
- NDJSON for events and metrics
- Cloud push for data forwarding

#### Per-Path Statistics
- Successful/failed signature counters
- Precise event tracking
- Complete timeline logs

### 🔧 Flexibility & Extensibility

#### Live Policies
- Runtime JSON/DSL updates
- No server restart required
- Immediate policy application

#### 50+ Ready API Routes
- Complete key management
- Backup and scheduling
- Smart firewall
- Alerts and monitoring

#### C-ABI FFI Interface
- Integration with C/C++/Python/Java/.NET
- Auto-generated headers
- Stable ABI across versions

### ⚡ High Performance & Efficiency

#### Lightweight Core
- Low memory and CPU footprint
- Adaptive memory guard with auto-purge
- Tight resource management

#### Optional Compression
- RLE for large payloads (>512B)
- Inbound/outbound compression counters
- Dynamic enable/disable

#### Smart Firewall
- Circuit breaker for resource protection
- Detailed counters (allowed/blocked)
- Manual open/close for emergencies

### ✅ Guaranteed Quality

#### Comprehensive Testing
- Clippy with zero warnings
- Miri for zero-deps core
- Complete integration tests
- Fuzz-like for random inputs

#### Full Documentation
- Comprehensive docs.rs
- Detailed SBOM
- Practical examples

#### Open Source
- Apache-2.0 License
- Fully auditable code
- Contributions welcome

### 🔑 Sovereign Cryptography

#### Internal HMAC-SHA512
- Implemented without external dependencies
- Strong digital signatures
- Secure verification

#### Constant-Time Comparisons
- ct_eq to prevent timing channels
- Protection against timing attacks
- Proven security

#### Advanced Key Rotation
- Multi-version support
- Smooth transition (N → N+1)
- Gradual old key deprecation

---

## 🚀 Use Cases & Applications

### 1. 🏛️ E-Government Systems
- Sovereign government service portals
- Digital identity and biometric verification systems
- Secure electronic voting platforms
- Government document management systems

### 2. 💰 Financial Services & Banking
- Digital wallets and electronic payment applications
- Trading platforms and cryptocurrency exchanges
- Real-time money transfer systems
- Secure payment gateways with PCI DSS compliance

### 3. 🏥 Healthcare
- Electronic Medical Records (EMR/EHR) systems
- Telemedicine platforms
- Vaccine and epidemic tracking applications
- Electronic prescription systems

### 4. 📡 Internet of Things (IoT)
- Smart home systems with device fingerprint verification
- Vehicle and asset tracking devices
- Industrial sensor networks (IIoT)
- Smart city systems

### 5. 🛒 E-Commerce
- Online retail platforms
- Secure payment gateways
- Inventory and supply chain management systems
- Loyalty and rewards programs

### 6. 📚 Education & E-Learning
- Electronic examination platforms
- Secure Learning Management Systems (LMS)
- Digital certificate applications
- Secure virtual classrooms

### 7. 🚚 Transportation & Logistics
- Shipment tracking with geo-verification
- Fleet management systems
- Ride-sharing platforms
- Smart delivery solutions

### 8. ⚡ Energy & Utilities
- Smart Grid systems
- Critical infrastructure monitoring
- Renewable energy plant management
- Secure smart meters

### 9. 🛡️ Cybersecurity
- Intrusion Detection/Prevention Systems (IDS/IPS)
- SIEM platforms
- Behavior analysis and anomaly detection tools
- SOC (Security Operations Center) solutions

### 10. 📱 Telecommunications & Media
- Secure live streaming platforms
- Encrypted messaging applications
- Sensitive Content Management Systems (CMS)
- Secure VoIP services

### 11. 🏭 Industry & Manufacturing
- Industrial Control Systems (SCADA/ICS)
- Production line monitoring
- Digital quality management
- Smart predictive maintenance

### 12. 🔬 Scientific Research
- Sensitive research data exchange platforms
- Virtual laboratory systems
- DNA and bioinformatics databases
- Secure research collaboration networks

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│         Dashboard (HTML/JSON) + Exports (CSV)           │
│              EN/AR Localization Support                 │
├─────────────────────────────────────────────────────────┤
│           API Routes (50+ endpoints)                    │
│  /keys/* /backup/* /webhook/* /policy/* /memory/*      │
├─────────────────────────────────────────────────────────┤
│       Per-Path Webhook Guards (HMAC-SHA512)            │
│   Signature Verification + Anti-Replay + Timestamps    │
├─────────────────────────────────────────────────────────┤
│         Inspection Policy (JSON/DSL Runtime)            │
│    Method/Path/ContentType Allow/Deny + Limits         │
├─────────────────────────────────────────────────────────┤
│      Fingerprint (Integrity) + Telemetry (Events)      │
│         ct_eq comparisons + NDJSON logging             │
├─────────────────────────────────────────────────────────┤
│    Key Rotation + Anti-Replay Purge + Memory Guard     │
│      Adaptive AI-driven tightening/relaxation          │
├─────────────────────────────────────────────────────────┤
│   Egress Guard (SSRF Protection) + Smart Firewall      │
│    RFC1918 check + Circuit Breaker + Rate Limiting     │
├─────────────────────────────────────────────────────────┤
│         Core (Digest, Resolver, Analyzers)             │
│            Zero-Dependency Sovereign Core               │
└─────────────────────────────────────────────────────────┘
```

---

## 🎁 Core Features

✅ **Zero Dependencies by Default (and for signing)** — Core and HMAC/SHA‑512 are implemented internally with no external crates  
✅ **50+ Independent Webhook Guards** — Per-path configurable protection  
✅ **Automatic Key Rotation** — Risk-based self-rotation  
✅ **Adaptive Anti-Replay** — Smart periodic purging (daily/weekly/monthly)  
✅ **Intelligent Telemetry** — Automatic guard tightening/relaxation  
✅ **Comprehensive Dashboard** — HTML/JSON with EN/AR localization  
✅ **CSV/NDJSON Export** — Excel-compatible exports  
✅ **Optional Cloud Integration** — Push data to external systems  
✅ **Live Policies** — Runtime JSON/DSL updates  
✅ **Egress Guard** — SSRF protection  
✅ **Memory Guard** — Auto/manual event purging  
✅ **C-ABI FFI** — Multi-language integration  
✅ **Optional RLE Compression** — For large payloads  
✅ **Smart Firewall** — Circuit breaker protection  
✅ **HMAC-SHA512 Signing** — Internal implementation  

---

## 📦 Installation

### From Crates.io

```toml
[dependencies]
mkt_ksa_geo_sec = "2.0.0"
```

### From Source

```bash
git clone https://github.com/mktmansour/MKT-KSA-Geolocation-Security
cd MKT-KSA-Geolocation-Security
cargo build --release
```

### Build with Specific Features

```bash
# HTTP server only
cargo build --features api_std_http

# Server + HMAC
cargo build --features "api_std_http,sign_hmac"

# Server + HMAC + RLE + FFI
cargo build --features "api_std_http,sign_hmac,compress_rle,ffi_c"
```

---

## 🚀 Quick Start

### Basic Example

```rust
use mkt_ksa_geo_sec::api::std_http;
use mkt_ksa_geo_sec::security::inspection_policy::InboundPolicy;
use std::sync::Arc;

fn main() {
    // Initialize telemetry
    mkt_ksa_geo_sec::telemetry::init();
    
    // Default safe policy
    let policy = InboundPolicy::default();
    
    // Simple handler
    let handler = Arc::new(|req: &std_http::Request| {
        std_http::Response::json(200, r#"{"status":"ok","endpoints":["/dashboard","/metrics"]}"#)
    });
    
    // Run server
    println!("Server running on http://127.0.0.1:8080");
    std_http::run_with_policy("127.0.0.1:8080", policy, handler).unwrap();
}
```

### Example with Webhook

```rust
use mkt_ksa_geo_sec::{api::std_http, webhook, telemetry};
use std::sync::Arc;

struct MyWebhook;

impl webhook::WebhookEndpoint for MyWebhook {
    fn receive(&self, payload: &str) -> Result<(), webhook::WebhookError> {
        telemetry::record_event("webhook_received", payload);
        
        // Check for dangerous content
        if payload.contains("attack") {
            telemetry::set_risk(80);
            return Err(webhook::WebhookError::InvalidPayload);
        }
        
        Ok(())
    }
}

fn main() {
    telemetry::init();
    
    // Attach webhook
    std_http::set_webhook_endpoint(Arc::new(MyWebhook));
    
    // Run with policy
    let policy = InboundPolicy::default();
    let handler = Arc::new(|req| {
        std_http::Response::json(200, r#"{"ok":true}"#)
    });
    
    std_http::run_with_policy("127.0.0.1:8080", policy, handler).unwrap();
}
```

---

## 🔌 API Routes

### 📨 Webhooks — External Ingress

| Route | Method | Description | Guard |
|-------|--------|-------------|-------|
| `/ai/ingest` | POST | Receive AI data | required, auth_hmac |
| `/ai/model/update` | POST | Update AI model | required, auth_hmac |
| `/ai/feedback` | POST | Model feedback | required, auth_hmac |
| `/weather/hook` | POST | Weather data | required, weather_hmac |
| `/weather/alerts` | POST | Weather alerts | required, weather_hmac |
| `/alerts/in` | POST | Security alerts | required, auth_hmac |
| `/partner/events` | POST | Partner events | required, partner_hmac |
| `/partner/telemetry` | POST | Partner telemetry | required, partner_hmac |
| `/geo/satellite` | POST | Satellite data | required, auth_hmac |
| `/geo/maplayer` | POST | Map layers | required, auth_hmac |
| `/webhook/in` | POST | General ingress | required, auth_hmac |

### 🔑 Key Management

| Route | Method | Description |
|-------|--------|-------------|
| `/keys/create` | POST | Create new key |
| `/keys/rotate` | POST | Rotate existing key |
| `/keys/meta` | GET | Fetch key metadata |
| `/keys/export_hex` | GET | Export keys (requires consent) |
| `/keys/auto/config` | POST | Configure auto-rotation |
| `/keys/auto/disable` | POST | Disable auto-rotation |

### 💾 Backup

| Route | Method | Description |
|-------|--------|-------------|
| `/backup/download` | GET | Download NDJSON log |
| `/backup/send` | POST | Send to external destination |
| `/backup/consent` | POST | Set consent token |
| `/backup/schedule` | POST | Schedule periodic backup |
| `/backup/schedule/disable` | POST | Cancel scheduling |
| `/backup/email` | POST | Send via email (smtp_std) |

### 🧱 Firewall

| Route | Method | Description |
|-------|--------|-------------|
| `/fw/metrics` | GET | Firewall metrics |
| `/fw/open` | POST | Open circuit breaker (503) |
| `/fw/close` | POST | Close breaker (restore) |

### 📊 Dashboard & Export

| Route | Method | Description |
|-------|--------|-------------|
| `/dashboard` | GET | HTML/JSON dashboard (lang=en\|ar) |
| `/metrics` | GET | Live JSON metrics |
| `/events.ndjson` | GET | Stream events NDJSON |
| `/export/csv` | GET | Export CSV (type=metrics\|events) |
| `/cloud/push` | POST | Push to cloud (url=...) |

### 🛡️ Webhook Guards

| Route | Method | Description |
|-------|--------|-------------|
| `/webhook/guard/list` | GET | List guards |
| `/webhook/guard/set` | POST | Set path guard |
| `/webhook/guard/disable` | POST | Disable guard |
| `/webhook/guard/stats` | GET | Signature statistics |

### 📜 Policies

| Route | Method | Description |
|-------|--------|-------------|
| `/policy/get` | GET | Get live policy |
| `/policy/set` | POST | Apply JSON runtime |
| `/policy/set_dsl` | POST | Apply DSL text |

### 🔄 Anti-Replay Purge

| Route | Method | Description |
|-------|--------|-------------|
| `/anti_replay/purge/config` | POST | Configure purge |
| `/anti_replay/purge/disable` | POST | Disable purge |
| `/anti_replay/purge/run` | POST | Run immediately |
| `/anti_replay/purge/status` | GET | Purge status |

### 🧠 Memory Guard

| Route | Method | Description |
|-------|--------|-------------|
| `/memory/config` | POST | Set limit & auto |
| `/memory/purge` | POST | Purge now |
| `/memory/status` | GET | Memory status |

### 🚨 Alerts

| Route | Method | Description |
|-------|--------|-------------|
| `/alerts/set` | POST | Set risk alert |
| `/alerts/disable` | POST | Disable alerts |

### 🎨 Others

| Route | Method | Description |
|-------|--------|-------------|
| `/templates/set` | POST | Set email templates |
| `/templates/default` | POST | Set default template |
| `/toggle` | GET | Toggle compression |
| `/features/enable` | POST | Enable feature |
| `/features/disable` | POST | Disable feature |
| `/lang/set` | POST | Set language |

---

## 🛡️ Webhook Guards

### What are Guards?

Guards are per-path security mechanisms providing:
- **HMAC-SHA512 signatures** for source integrity
- **Anti-Replay** to prevent request duplication
- **Timestamp windows** for limited acceptance
- **Adaptive tightening/relaxation** based on risk

### Guard Configuration

```rust
pub struct GuardConfig {
    pub path: String,           // Path
    pub alg: String,            // "hmac-sha512" or "none"
    pub key_id: String,         // Key identifier
    pub required: bool,         // Require signature?
    pub ts_window_ms: u64,      // Timestamp window (ms)
    pub anti_replay_on: bool,   // Enable anti-replay?
}
```

### Example: Configure Guard

```bash
# Set guard for /ai/ingest
curl -X POST "http://127.0.0.1:8080/webhook/guard/set?path=/ai/ingest&alg=hmac-sha512&key=auth_hmac&ts=300000&required=1&replay=1"

# List all guards
curl http://127.0.0.1:8080/webhook/guard/list

# Signature statistics
curl http://127.0.0.1:8080/webhook/guard/stats
```

### Example: Send Signed Request

```python
import hmac
import hashlib
import time
import requests

def sign_request(method, path, body, key):
    ts = str(int(time.time() * 1000))
    nonce = hashlib.sha256(ts.encode()).hexdigest()[:16]
    
    # Canonical: method|path|content-type|timestamp|nonce|sha512(body)
    body_hash = hashlib.sha512(body.encode()).hexdigest()
    canonical = f"{method}|{path}|application/json|{ts}|{nonce}|{body_hash}"
    
    # Compute HMAC-SHA512
    sig = hmac.new(key.encode(), canonical.encode(), hashlib.sha512).hexdigest()
    
    return {
        'X-MKT-Alg': 'hmac-sha512',
        'X-MKT-KeyId': 'auth_hmac',
        'X-MKT-Timestamp': ts,
        'X-MKT-Nonce': nonce,
        'X-MKT-Signature': sig
    }

# Send signed request
headers = sign_request('POST', '/ai/ingest', '{"data":"test"}', 'your-secret-key')
headers['Content-Type'] = 'application/json'
r = requests.post('http://127.0.0.1:8080/ai/ingest', 
                  json={"data":"test"}, 
                  headers=headers)
print(r.json())
```

### Automatic Tightening

When signature errors or risks rise, guards automatically tighten:
- Reduce `ts_window_ms`
- Enforce `required=true`
- Enable `anti_replay_on=true`

### Safe Relaxation

When risks drop and errors are rare, guards relax toward baseline settings.

---

## 🔑 Key Rotation

### Manual Rotation

```bash
# Create key
curl -X POST "http://127.0.0.1:8080/keys/create?id=auth_hmac&ver=1&len=32"

# Rotate key
curl -X POST "http://127.0.0.1:8080/keys/rotate?id=auth_hmac&ver=2&len=32"

# Fetch metadata
curl "http://127.0.0.1:8080/keys/meta?id=auth_hmac"
```

### Auto-Rotation

```bash
# Configure auto-rotation
# threshold: risk level for rotation (0-100)
# interval: check period in seconds
# ids: comma-separated key IDs
# len: key length in bytes
curl -X POST "http://127.0.0.1:8080/keys/auto/config?threshold=85&interval=300&ids=auth_hmac,backup_key&len=32"

# Disable auto-rotation
curl -X POST "http://127.0.0.1:8080/keys/auto/disable"
```

### Multi-Version Support

The system supports accepting two key versions simultaneously (N and N+1) for smooth transitions without service interruption:

```
Before rotation:  v1 (active)
During rotation:  v1 (active)  +  v2 (active)
After rotation:   v2 (active),  v1 (gradual deprecation)
```

---

## 📊 Dashboard

### Access

```bash
# HTML Arabic
http://127.0.0.1:8080/dashboard?fmt=html&lang=ar

# HTML English
http://127.0.0.1:8080/dashboard?fmt=html&lang=en

# JSON
http://127.0.0.1:8080/dashboard
```

### Dashboard Contents

#### 📈 Live Metrics
- Inspected/blocked requests
- Signature success/failure
- Inbound/outbound compression
- Computed fingerprints
- Inbound/outbound webhooks

#### 🔑 Key Rotation Status
- Enabled/disabled
- Risk threshold
- Check interval
- Last rotation
- Tracked keys count

#### 🔄 Anti-Replay Purge Status
- Enabled/disabled
- Mode (daily/weekly/monthly)
- Purge interval
- Next purge
- Sensitivity (0-100)

#### 🧠 Memory Status
- Set limit
- Auto-purge enabled?
- Events used
- Overflow warnings

#### 🎛️ Enabled Features
- AI Insights
- Cloud Integration
- CSV Export

#### 🛡️ Guards List
- Path
- Algorithm
- Key ID
- Required?
- Timestamp window
- Anti-replay on?

#### 📊 Signature Statistics
- Per-path: success/failure
- Total signatures
- Success rate

---

## 📤 Export & Cloud Integration

### CSV Export

```bash
# Export metrics
curl "http://127.0.0.1:8080/export/csv?type=metrics" -o metrics.csv

# Export events
curl "http://127.0.0.1:8080/export/csv?type=events" -o events.csv
```

### NDJSON Export

```bash
# Download event log
curl "http://127.0.0.1:8080/backup/download" -o events.ndjson

# Stream events live
curl "http://127.0.0.1:8080/events.ndjson"
```

### Cloud Push

```bash
# Enable cloud feature first
curl -X POST "http://127.0.0.1:8080/features/enable?name=cloud"

# Push metrics
curl -X POST "http://127.0.0.1:8080/cloud/push?url=https://api.example.com/receive"
```

---

## 🔗 FFI Interface

### Build with FFI

```bash
cargo build --release --features ffi_c

# Header auto-generated at: include/mkt_ksa_geo_sec.h
```

### Generated Header

```c
// include/mkt_ksa_geo_sec.h

// ABI version (stable)
uint32_t mkt_abi_version(void);

// SemVer string (NUL-terminated)
const char* mkt_semver_string(void);

// HMAC-SHA512
int32_t mkt_hmac_sha512(
    const uint8_t* data_ptr,
    size_t data_len,
    const uint8_t* key_ptr,
    size_t key_len,
    uint8_t* out_ptr,
    size_t out_len
);
```

### C Example

```c
#include "mkt_ksa_geo_sec.h"
#include <stdio.h>

int main() {
    // Display version
    printf("ABI: %u\n", mkt_abi_version());
    printf("Version: %s\n", mkt_semver_string());
    
    // Compute HMAC
    const uint8_t data[] = "Hello, World!";
    const uint8_t key[] = "secret-key";
    uint8_t out[64];
    
    int ret = mkt_hmac_sha512(data, 13, key, 10, out, 64);
    if (ret == 0) {
        printf("HMAC: ");
        for (int i = 0; i < 64; i++) {
            printf("%02x", out[i]);
        }
        printf("\n");
    }
    
    return 0;
}
```

### Linking

```bash
# Linux/macOS
gcc -o example example.c -L./target/release -lmkt_ksa_geo_sec

# Windows
cl.exe example.c mkt_ksa_geo_sec.lib
```

---

## 🎛️ Optional Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `api_std_http` | Internal zero-deps HTTP/1.1 server | ✅ Zero |
| `sign_hmac` | Internal HMAC-SHA512 signing | ✅ Zero |
| `compress_rle` | RLE compression/decompression | ✅ Zero |
| `egress` | Egress guard layer | ✅ Zero |
| `egress_http_std` | Simple HTTP egress client | ✅ Zero |
| `smtp_std` | Simple email sending (TCP) | ✅ Zero |
| `ffi_c` | C-ABI interface + header | ✅ Zero |
| `ledger_blake3` | BLAKE3 event ledger | ✅ Zero |
| `core_utils` | Core utility helpers | ✅ Zero |
| `input_validation` | Additional input validation | ✅ Zero |

**Note**: All features are zero-dependency — no external crates added.

---

## 💡 Usage Examples

### Run Demo Dashboard

```bash
# Set environment variables (Windows)
$env:CARGO_HOME="C:\rust\cargo"
$env:RUSTUP_HOME="C:\rust\rustup"

# Run
cargo run --bin std_dashboard_demo --features api_std_http

# Access
# http://127.0.0.1:8080/dashboard?fmt=html&lang=en
```

### Enable AI Feature

```bash
curl -X POST "http://127.0.0.1:8080/features/enable?name=ai_insights"
```

### Set Memory Limit

```bash
# 1MB limit with auto-purge
curl -X POST "http://127.0.0.1:8080/memory/config?limit=1048576&auto=1"

# Immediate purge
curl -X POST "http://127.0.0.1:8080/memory/purge"

# Status
curl "http://127.0.0.1:8080/memory/status"
```

### Configure Anti-Replay Purge

```bash
# Daily purge with sensitivity 70
curl -X POST "http://127.0.0.1:8080/anti_replay/purge/config?mode=daily&sensitivity=70&window=300000&capacity=2048"

# Run immediately
curl -X POST "http://127.0.0.1:8080/anti_replay/purge/run"

# Status
curl "http://127.0.0.1:8080/anti_replay/purge/status"
```

### Apply DSL Policy

```bash
# Create policy.dsl file
cat > policy.dsl << 'EOF'
# Security policy
allowed_methods=GET,POST
allowed_path_prefixes=/api,/webhook
denied_path_prefixes=/admin,/internal
allowed_content_types=application/json,text/plain
limits.max_headers_bytes=8192
limits.max_body_bytes=1048576
EOF

# Apply
curl -X POST "http://127.0.0.1:8080/policy/set_dsl" \
     -H "Content-Type: text/plain" \
     --data-binary @policy.dsl
```

---

## 🧪 Testing

### Core Tests (Zero-Deps)

```bash
# Library tests
cargo test --no-default-features

# Strict Clippy
cargo clippy --lib --no-default-features -- -D warnings

# Formatting
cargo fmt --all

# Miri (memory safety check)
cargo +nightly miri test --no-default-features
```

### Server Tests

```bash
# Tests with api_std_http
cargo test --features api_std_http

# Clippy for binaries
cargo clippy --bins --features api_std_http -- -D warnings
```

### Fuzz-Like Testing

```bash
# Test random inputs
cargo test --test fuzz_like --features api_std_http
```

---

## 🔐 Security

### Vulnerability Reporting

If you discover a security vulnerability, please send a private report to:
**mkt-edge@outlook.sa**

Please **do not** publish vulnerabilities in public Issues.

### Implemented Best Practices

✅ Constant-time comparisons (ct_eq) for fingerprints and signatures  
✅ Strict input limits (headers/body)  
✅ UTF-8 validation and XSS detection  
✅ Egress guard against SSRF  
✅ Strong anti-replay  
✅ Internal HMAC-SHA512  
✅ Adaptive risk-based tightening  
✅ Continuous auditing (Clippy/Miri/Tests)  

### External Auditing

The project is fully open-source and auditable. Security reviews from the community are welcome.

---

## 📄 License

This project is licensed under **Apache License 2.0**.

See [LICENSE](LICENSE) file for full details.

---

## 📞 Contact

### Author
**Mansour Khalid**  
📧 mkt-edge@outlook.sa

### Links

- 🌐 **Repository**: [github.com/mktmansour/MKT-KSA-Geolocation-Security](https://github.com/mktmansour/MKT-KSA-Geolocation-Security)
- 📚 **Documentation**: [docs.rs/MKT_KSA_Geolocation_Security](https://docs.rs/MKT_KSA_Geolocation_Security)
- 📦 **Crates.io**: [crates.io/crates/MKT_KSA_Geolocation_Security](https://crates.io/crates/MKT_KSA_Geolocation_Security)
- 🐛 **Issues**: [GitHub Issues](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/issues)

---

## 🙏 Acknowledgments

Thanks to the Rust community for excellent tools and continuous support.

---

## 📚 Additional Resources

- [docs/SBOM.md](docs/SBOM.md) - Software Bill of Materials
- [docs/Final_Engineering_Report.md](docs/Final_Engineering_Report.md) - Comprehensive Engineering Report
- [docs/Test_Plan.md](docs/Test_Plan.md) - Test Plan
- [include/mkt_ksa_geo_sec.h](include/mkt_ksa_geo_sec.h) - FFI C-ABI Header

---

<div align="center">

**Made with ❤️ in Saudi Arabia**

</div>
