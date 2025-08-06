# 🛡️🌍 MKT_KSA_Geolocation_Security  
**Smart Saudi Geolocation & Security Library – MKT KSA 🇸🇦**  
**Enterprise-Grade Modular Geolocation Security for Rust**

> 🔐 Rust | 🛰️ Multi-Factor Security | 🏙️ Smart City Ready | 📄 Apache 2.0 | 👨‍💻 Author: Mansour Khalid

---

## 📘 Table of Contents

- [🗺️ Project Overview](#-project-overview)
- [📂 Main Files](#-main-files)
- [🧩 Constants & Functions](#-constants--functions)
- [🔑 Config & Endpoints](#-config--endpoints)
- [🧭 Architecture](#-architecture)
- [🛠️ Verification Examples](#-verification-examples)
- [⚠️ Dependency Audit](#-dependency-audit)
- [✅ Test Results](#-test-results)
- [⭐ Features & Audiences](#-features--audiences)
- [🧠 Developer Guide](#-developer-guide)
- [📈 System State Summary](#-system-state-summary)

---

## 🗺️ Project Overview

**MKT_KSA_Geolocation_Security**  
A next-gen security library designed for smart cities, financial, and critical sectors.  
Enables composite geolocation verification, behavioral analytics, device fingerprinting, and AI-driven adaptive security — all with fully modular, extensible architecture and comprehensive documentation.

---

## 📂 Main Files

| File Name            | Path                      | Role (EN)                                         |
|----------------------|---------------------------|---------------------------------------------------|
| main.rs              | src/main.rs               | Main entry point, server & module initialization  |
| models.rs            | src/db/models.rs          | Database models                                   |
| crud.rs              | src/db/crud.rs            | Database CRUD logic                               |
| mod.rs (db)          | src/db/mod.rs             | DB module index                                   |
| ratelimit.rs         | src/security/ratelimit.rs | Rate limiting (DoS protection)                    |
| input_validator.rs   | src/security/input_validator.rs | Input validation                           |
| policy.rs            | src/security/policy.rs    | Policy engine                                     |
| geo_resolver.rs      | src/core/geo_resolver.rs  | Geolocation resolver engine                       |
| behavior_bio.rs      | src/core/behavior_bio.rs  | Behavioral analytics engine                       |
| device_fp.rs         | src/core/device_fp.rs     | Device fingerprinting                             |
| network_analyzer.rs  | src/core/network_analyzer.rs | Network analysis, concealment detection      |
| auth.rs              | src/api/auth.rs           | Auth endpoints                                    |
| alerts.rs            | src/api/alerts.rs         | Security alert endpoints                          |
| mod.rs (utils)       | src/utils/mod.rs          | Utility helpers/cache/logger                      |
| Cargo.toml           | Cargo.toml                | Project dependencies and setup                    |

---

## 🧩 Constants & Functions

### Constants

| Name                    | Default Value | Defined In                   |
|-------------------------|--------------|------------------------------|
| MAX_ACCURACY_THRESHOLD  | 50.0         | src/core/geo_resolver.rs     |
| MIN_SIGNAL_STRENGTH     | 30           | src/core/geo_resolver.rs     |
| QUANTUM_SECURITY_LEVEL  | 90           | src/core/geo_resolver.rs     |
| MAX_HISTORY_SIZE        | 100          | src/core/geo_resolver.rs     |

---

### Key Public Functions

| Function Name          | Signature                                | Defined In                       |
|------------------------|------------------------------------------|----------------------------------|
| get_user_by_id         | async fn get_user_by_id(pool, user_id)   | src/db/crud.rs                   |
| verify_smart_access    | async fn verify_smart_access(...)        | src/core/composite_verification.rs|
| process                | async fn process(input)                  | src/core/behavior_bio.rs         |
| check                  | async fn check(ip)                       | src/security/ratelimit.rs        |

---

## 🔑 Config & Endpoints

### .env / Config Keys

| Key Name      | Role                      | Example                        |
|---------------|---------------------------|--------------------------------|
| API_KEY       | Main authentication key   | API_KEY=your_secret_key        |
| DATABASE_URL  | DB connection string      | DATABASE_URL=mysql://...       |
| LOG_LEVEL     | Logging verbosity         | LOG_LEVEL=debug                |
| GEO_PROVIDER  | Geolocation provider      | GEO_PROVIDER=ipapi             |

---

### API Endpoints

| Path            | Method | Role                     | Defined In          |
|-----------------|--------|--------------------------|---------------------|
| /users/{id}     | GET    | Fetch user data          | src/api/auth.rs     |
| /alerts/trigger | POST   | Trigger security alert   | src/api/alerts.rs   |
| /auth/login     | POST   | User login               | src/api/auth.rs     |

---

## 🧭 Architecture

```mermaid
graph TD
    A[main.rs 🧩\nEntry] --> B[API Layer 🌐]
    A --> C[Core Engines 🧠]
    A --> D[DB Layer 🗄️]
    B -->|Endpoints| E[🔓 /auth, /alerts, /users]
    C --> F[GeoResolver 🌍]
    C --> G[BehaviorEngine 🧠]
    C --> H[DeviceFingerprint 📱]
    C --> I[NetworkAnalyzer 🌐🔍]
    C --> J[SensorsAnalyzer 📡]
    C --> K[WeatherEngine ☁️]
    C --> L[CrossValidator 🔄]
    C --> M[CompositeVerifier 🛡️]
    D --> N[CRUD + Models ⚙️]
    B --> O[Security Layer 🔐]
    O --> P[InputValidator 📥]
    O --> Q[JWT Manager 🔑]
    O --> R[Policy Engine ⚖️]
    O --> S[RateLimiter 🚦]
```

> 🎯 **Description:** Shows integration of all main modules up to the smart composite security layer.

---

## 🛠️ Practical Verification Examples

### Full Composite Security Check

```rust
let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
let allowed_hours = Some((6, 18));
let access_granted = verify_user_full_access(
    &db_pool, &user_id, &device_id, "admin",
    geo_input, behavior_input, &geo_resolver, &behavior_engine,
    &allowed_zones, allowed_hours,
).await?;
if !access_granted {
    // Deny access or log suspicious attempt
}
```

---

### Geo Verification Only

```rust
let geo_location = geo_resolver.resolve(Some(ip), Some(gps), None, None, None, None, None).await?;
if let Some(city) = &geo_location.city {
    if allowed_zones.contains(city) {
        // Geo verification successful
    } else {
        // Access denied due to location
    }
}
```

---

### Behavior Verification Only

```rust
let behavior_result = behavior_engine.process(behavior_input).await?;
if behavior_result.risk_level as u8 < 3 {
    // Low risk behavior
} else {
    // Medium or high risk behavior
}
```

---

### Device Verification Only

```rust
let mut conn = db_pool.get_conn().await?;
let device_query = r#"SELECT id FROM devices WHERE id = ? AND user_id = ?"#;
let device_row: Option<Row> = mysql_async::prelude::Queryable::exec_first(
    &mut conn, device_query,
    (device_id.to_string(), user_id.to_string()),
).await?;
if device_row.is_some() {
    // Device recognized
} else {
    // Unknown or unauthorized device
}
```

---

### Role Verification Only

```rust
let mut conn = db_pool.get_conn().await?;
let role_query = r#"SELECT role FROM user_roles WHERE user_id = ? AND role = ?"#;
let role_row: Option<Row> = mysql_async::prelude::Queryable::exec_first(
    &mut conn, role_query,
    (user_id.to_string(), "admin"),
).await?;
if role_row.is_some() {
    // User has required role
} else {
    // User lacks required role
}
```

---

## ⚠️ Dependency Audit

| Dependency         | Type     | Direct? | Indirect? | Risk? | Action  |
|--------------------|----------|---------|-----------|-------|---------|
| instant            | Std Native | Yes   | No        | None  | None    |
| lexical            | External   | No    | Yes       | None  | None    |
| lexical-core       | External   | No    | Yes       | None  | None    |
| proc-macro-error   | External   | No    | Yes       | None  | None    |

- ✅ All dependencies are reviewed, no unsafe crates.
- 🔁 Regular `cargo update` recommended.
- 📌 No current security warnings.

---

## ✅ Test Results

```bash
running 35 tests
... all tests passed ...

test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.04s
```
- ✅ All tests passed (35/35).

---

## ⭐ Features & Audiences

### Main Features
- 🔐 **Composite multi-source verification** (Geo, Behavior, Device, Network, Weather, Sensors)
- 🧠 **AI-driven adaptive security** (fully integrable)
- 🛰️ **Advanced concealment detection** (VPN/Proxy/Tor detection)
- 🏙️ **Smart City & Enterprise Policies** (zones, permissions, timing)
- ⚡ **Highly modular, plug-and-play architecture**
- 📄 **Fully bilingual documentation (EN/AR)**
- 🔑 **Secrets management & post-quantum crypto**
- 🚦 **Integrated Rate Limiting (RateLimiter)**
- 🔌 **Effortless integration via REST API or Rust Traits**

---

### Target Audiences
- Government agencies (Smart city, cyber, passport, traffic)
- Financial and banking sector
- Large tech enterprises (Cloud, IoT, AI, Security)
- Identity and access apps (Access Control, MFA)
- Any developer seeking modern, customizable security

---

### Unique Selling Points

- Composite security: location, behavior, device, and network in a unified decision
- Multiple geolocation sources (GPS, IP, SIM, Satellite, Indoor, AR)
- AI or ML logic easily injectable
- Advanced anti-concealment: built-in VPN/Proxy/Tor detection
- Smart city/enterprise plug-and-play readiness
- Full bilingual documentation and flexible dev API

---

## 🧠 Developer Guide

### Basic Integration Steps

1. **Set required environment variables (.env/config):**
   ```bash
   API_KEY=your_secret_key
   DATABASE_URL=mysql://user:pass@host/db
   ```
2. **Initialize core engines in your app:**  
   Call public functions:  
   `verify_smart_access`, `process`, `generate_fingerprint`
3. **Customize security logic:**  
   - Inject your own AI model or verification logic via Traits
   - Customize policies (zones, timing, permissions) easily
4. **Use REST API endpoints or direct Rust integration:**  
   - Call `/users/{id}`, `/alerts/trigger`, etc.
   - Or invoke functions directly

#### Quick Rust Integration Example

```rust
let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
let allowed_hours = Some((6, 18));
let access_granted = composite_verifier.verify_smart_access(
    geo_input,
    behavior_input,
    device_info,
    &allowed_zones,
    allowed_hours,
).await?;
if !access_granted {
    // Deny access or log suspicious attempt
}
```

#### Advanced Tips

- All engines are fully replaceable (inject your logic!)
- Full flexibility (session/device/role can be customized)
- All constants, functions, and examples are fully documented EN/AR

---

## 📈 System State Summary

| Module          | Status                   |
|-----------------|-------------------------|
| Core Engines    | ✅ Fully implemented     |
| API Layer       | ✅ All endpoints active  |
| Security Layer  | ✅ JWT, RateLimiter, Dynamic Policies |
| DB Layer        | ✅ CRUD/models integrated|
| Utils           | ✅ Ready & modular       |

- ✅ All modules interconnected, no open risks or warnings.
- ✅ Bilingual documentation, complete practical examples.
- ✅ All tests passed, production-ready for deployment or integration.

---

> **Prepared by Mansour Khalid (MKT KSA 🇸🇦), 2025 – All rights reserved**
