# 🛡️🌍 MKT_KSA_Geolocation_Security

**Smart Saudi Geolocation & Security Library – MKT KSA 🇸🇦**
> 🔐 Rust | 🛰️ Smart Security | 🏙️ Smart City Ready | 📄 Apache 2.0 | Developed by Mansour Bin Khalid (KSA 🇸🇦)
>
[![Rust](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml)      [![Clippy](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml/badge.svg)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml)
[![Crates.io](https://img.shields.io/crates/v/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![Docs.rs](https://img.shields.io/docsrs/MKT_KSA_Geolocation_Security?style=for-the-badge)](https://docs.rs/MKT_KSA_Geolocation_Security)
[![Downloads](https://img.shields.io/crates/d/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![License](https://img.shields.io/crates/l/MKT_KSA_Geolocation_Security?style=for-the-badge)](LICENSE)
![MSRV](https://img.shields.io/badge/MSRV-1.89%2B-informational?style=for-the-badge)
![Audit](https://img.shields.io/badge/audit-clean-success?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/maintenance-actively%20maintained-success?style=for-the-badge)
![Edition](https://img.shields.io/badge/edition-2021-blue?style=for-the-badge)
![Made in KSA](https://img.shields.io/badge/Made_in-KSA-006c35?style=for-the-badge)
![Post‑Quantum](https://img.shields.io/badge/Post--Quantum-ready-8A2BE2?style=for-the-badge)

## 🔔 Update Notice (2026-03-14)

Latest hardening and maintenance updates applied:

- Enforced strict security gate: `cargo audit --deny warnings` passes.
- Kept `db-mysql` intentionally disabled in the current hardened profile until a non-vulnerable backend path is integrated.
- Removed repository cache artifacts and strengthened package excludes (`.cargo-home/**`, `target/**`, `.env`, `.env.*`).
- Validation gates are clean: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` (39/39).

---
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/95cf4068-d2f6-4603-9c03-521146a04e0e" />

## 📘 Table of Contents

* [🗺️ Project Overview](#-project-overview)
* [📂 Main Files](#-main-files)
* [🧩 Constants & Public Functions](#-constants--public-functions)
  * [🖊️ Signing Module Functions](#-signing-module-functions)
  * [⏱️ Precision Module Functions](#-precision-module-functions)
* [🔑 Config & Endpoints](#-config--endpoints)
* [🧭 Architecture](#-architecture)
* [🛠️ Verification Examples](#-verification-examples)
* [⚙️ Core Engine Modules](#-core-engine-modules)
* [📡 Sensors Analyzer](#-sensors-analyzer)
* [☁️ Weather Validation](#-weather-validation)
* [📜 History Service](#-history-service)
* [🔄 Cross-Validation Engine](#-cross-validation-engine)
* [⚠️ Dependency Audit](#-dependency-audit)
* [✅ Test Results](#-test-results)
* [🔒 Current Release Stability](#-current-release-stability)
* [⬆️ Full Dependency Upgrade Plan](#-full-dependency-upgrade-plan)
* [⭐ Features](#-features)
* [🧠 Developer Guide](#-developer-guide)
* [📈 System State](#-system-state)
* [📝 Release Notes v1.0.2](#-release-notes-v102)
  * [🔧 Internal Signature Changes](#-internal-signature-changes-no-behaviorroute-changes)
  * [📑 Current Signatures (Reference)](#-current-signatures-reference)
  * [🧹 Formatting and Extra Checks](#-formatting-and-extra-checks)
* [📦 Using as a Rust library](#-using-as-a-rust-library)
* [🔗 Linking via C-ABI](#-linking-via-c-abi)

---

## 🗺️ Project Overview

**MKT_KSA_Geolocation_Security** is an advanced security library for smart cities, sovereign sectors, and technology enterprises. It leverages geolocation verification, behavioral analytics, device fingerprinting, AI, and a modular, extensible architecture – with full English documentation for every module and function.

---

## 📂 Main Files

| File Name            | Path                             | Role (English)                                 |
| -------------------- | -------------------------------- | ---------------------------------------------- |
| main.rs              | src/main.rs                      | Main entry point, initializes server & modules |
| models.rs            | src/db/models.rs                 | DB models                                      |
| crud.rs              | src/db/crud.rs                   | DB CRUD functions                              |
| mod.rs (db)          | src/db/mod.rs                    | DB module index                                |
| ratelimit.rs         | src/security/ratelimit.rs        | Rate limiting module (DoS protection)          |
| input_validator.rs   | src/security/input_validator.rs  | Input validation tools                         |
| policy.rs            | src/security/policy.rs           | Policy engine                                  |
| jwt.rs               | src/security/jwt.rs              | JWT management                                 |
| mod.rs (security)    | src/security/mod.rs              | Security module index                          |
| geo_resolver.rs      | src/core/geo_resolver.rs         | Geolocation resolver engine                    |
| behavior_bio.rs      | src/core/behavior_bio.rs         | Behavioral analytics engine                    |
| device_fp.rs         | src/core/device_fp.rs            | Device fingerprinting                          |
| network_analyzer.rs  | src/core/network_analyzer.rs     | Network analysis & concealment detection       |
| sensors_analyzer.rs  | src/core/sensors_analyzer.rs     | Sensors data analysis engine                   |
| weather_val.rs       | src/core/weather_val.rs          | Weather validation engine                      |
| cross_location.rs    | src/core/cross_location.rs       | Cross-validation engine                        |
| history.rs           | src/core/history.rs              | History management & anomaly detection         |
| mod.rs (core)        | src/core/mod.rs                  | Core engine module index                       |
| auth.rs              | src/api/auth.rs                  | Auth endpoints                                 |
| alerts.rs            | src/api/alerts.rs                | Security alerts endpoints                      |
| geo.rs               | src/api/geo.rs                   | Geolocation endpoints                          |
| device.rs            | src/api/device.rs                | Device endpoints                               |
| behavior.rs          | src/api/behavior.rs              | Behavior analytics endpoints                   |
| network.rs           | src/api/network.rs               | Network analysis endpoints                     |
| sensors.rs           | src/api/sensors.rs               | Sensors endpoints                              |
| weather.rs           | src/api/weather.rs               | Weather endpoints                              |
| dashboard.rs         | src/api/dashboard.rs             | Dashboard endpoints                            |
| smart_access.rs      | src/api/smart_access.rs          | Smart access endpoint                          |
| mod.rs (api)         | src/api/mod.rs                   | API module index                               |
| mod.rs (utils)       | src/utils/mod.rs                 | Utils module index                             |
| precision.rs         | src/utils/precision.rs           | Precision utilities (time/numeric/geospatial)  |
| helpers.rs           | src/utils/helpers.rs             | General helper functions                       |
| logger.rs            | src/utils/logger.rs              | Logger module                                  |
| cache.rs             | src/utils/cache.rs               | Cache module                                   |
| signing.rs           | src/security/signing.rs          | High-security signing (HMAC) utilities         |
| Cargo.toml           | Cargo.toml                       | Dependency management file                     |

---

## 🧩 Constants & Public Functions

### Constants

| Constant Name            | Default Value | Defined In       |
| ------------------------ | ------------- | ---------------- |
| MAX_ACCURACY_THRESHOLD   | 50.0          | geo_resolver.rs  |
| MIN_SIGNAL_STRENGTH      | 30            | geo_resolver.rs  |
| QUANTUM_SECURITY_LEVEL   | 90            | geo_resolver.rs  |
| MAX_HISTORY_SIZE         | 100           | geo_resolver.rs  |

---

### Public Functions & Main Structs

| Function/Struct Name         | Signature                                      | Defined In           | Description (English)                       |
| ---------------------------- | ---------------------------------------------- | -------------------- | ------------------------------------------ |
| get_user_by_id               | async fn get_user_by_id(pool, user_id)         | db/crud.rs           | Fetch user from DB                          |
| verify_smart_access          | async fn verify_smart_access(...)              | core/composite_verification.rs | Smart composite security check              |
| process                      | async fn process(input: BehaviorInput)         | core/behavior_bio.rs | Analyze user/device behavior                |
| generate_fingerprint         | async fn generate_fingerprint(os, device, env) | core/device_fp.rs    | Generate adaptive device fingerprint        |
| analyze                      | async fn analyze(provider: &dyn NetworkInfoProvider) | core/network_analyzer.rs | Analyze network & detect concealment tools  |
| fetch_and_validate           | async fn fetch_and_validate(lat, lng)          | core/weather_val.rs  | Fetch & validate weather data               |
| validate                     | async fn validate(input: CrossValidationInput) | core/cross_location.rs | Full cross-validation                       |
| log_event                    | async fn log_event(event: &HistoryEvent)       | core/history.rs      | Log historical event                        |
| detect_timeline_anomalies    | async fn detect_timeline_anomalies(entity_id, window) | core/history.rs | Detect timeline anomalies                   |
| check                        | async fn check(ip)                             | security/ratelimit.rs | Rate limiting check                         |
| sign_location                | fn sign_location(location: &GeoLocation)       | core/geo_resolver.rs | Digitally sign location data                |
| verify_signature             | fn verify_signature(location: &GeoLocation)    | core/geo_resolver.rs | Verify digital signature                    |
| config                       | fn config(cfg: &mut ServiceConfig)             | api/mod.rs           | Register all API routes                     |

---

### 🖊️ Signing Module Functions

| Function Name                   | Signature                                                                 | Defined In                | Description                                  |
| --------------------------------| ------------------------------------------------------------------------- | ------------------------- | -------------------------------------------- |
| sign_hmac_sha512                | fn sign_hmac_sha512(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs   | HMAC-SHA512 signature over bytes             |
| verify_hmac_sha512              | fn verify_hmac_sha512(data: &[u8], sig: &[u8], key: &SecureBytes) -> bool            | src/security/signing.rs   | Verifies HMAC-SHA512                         |
| sign_hmac_sha384                | fn sign_hmac_sha384(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs   | HMAC-SHA384 signature                        |
| verify_hmac_sha384              | fn verify_hmac_sha384(data: &[u8], sig: &[u8], key: &SecureBytes) -> bool            | src/security/signing.rs   | Verifies HMAC-SHA384                         |
| sign_struct_excluding_field     | fn sign_struct_excluding_field<T: Serialize>(value: &T, exclude_field: &str, key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs | Sign serializable struct excluding one field |
| verify_struct_excluding_field   | fn verify_struct_excluding_field<T: Serialize>(value: &T, exclude_field: &str, sig: &[u8], key: &SecureBytes) -> bool | src/security/signing.rs | Verify serializable struct excluding field   |

---

### ⏱️ Precision Module Functions

| Function Name           | Signature                                                               | Defined In                | Description                                          |
| ----------------------- | ----------------------------------------------------------------------- | ------------------------- | ---------------------------------------------------- |
| time_delta_secs         | fn time_delta_secs(start: DateTime<Utc>, end: DateTime<Utc>) -> f64     | src/utils/precision.rs    | Time delta in seconds (with negative guard)          |
| time_delta_secs_high_res| fn time_delta_secs_high_res(start: DateTime<Utc>, end: DateTime<Utc>) -> f64 | src/utils/precision.rs | High-resolution time delta (secs + nanos)            |
| avg_f32                 | fn avg_f32(values: &[f32]) -> f32                                       | src/utils/precision.rs    | f32 average using internal f64 accumulation          |
| haversine_km            | fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64                    | src/utils/precision.rs    | Haversine distance in kilometers                     |
| speed_kmh               | fn speed_kmh(distance_km: f64, seconds: f64) -> f64                     | src/utils/precision.rs    | Speed (km/h) with division-by-zero guard             |
| weighted_sum_f64        | fn weighted_sum_f64(values: &[f64], weights: &[f64]) -> Option<f64>     | src/utils/precision.rs    | Weighted sum (f64), None if lengths mismatch         |
| rate_of_change_f64      | fn rate_of_change_f64(value_delta: f64, seconds: f64) -> f64            | src/utils/precision.rs    | Rate of change per second with zero-division guard   |
### Main Traits

| Trait Name                | Signature                        | Defined In           | Description (English)                       |
| ------------------------- | -------------------------------- | -------------------- | ------------------------------------------ |
| AiModel                   | trait AiModel: detect_fraud, analyze_movement, ... | core/geo_resolver.rs | AI models for geolocation                   |
| Blockchain                | trait Blockchain: store_location, verify_location, ... | core/geo_resolver.rs | Blockchain integration                      |
| BehavioralModel           | trait BehavioralModel: analyze   | core/behavior_bio.rs | Behavioral analysis models                  |
| AnomalyDetector           | trait AnomalyDetector: detect    | core/behavior_bio.rs | Behavioral anomaly detection                |
| SecurityMonitor           | trait SecurityMonitor: scan_environment, ... | core/device_fp.rs    | Device security monitoring                  |
| QuantumEngine             | trait QuantumEngine: get_secure_key, ... | core/device_fp.rs    | Post-quantum crypto engine                  |
| AiProcessor               | trait AiProcessor: generate_ai_signature | core/device_fp.rs    | AI processor for fingerprinting             |
| NetworkInfoProvider       | trait NetworkInfoProvider: get_connection_type, ... | core/network_analyzer.rs | Network info provider                       |
| AiNetworkAnalyzer         | trait AiNetworkAnalyzer: analyze | core/network_analyzer.rs | AI network analyzer                         |
| SensorAnomalyDetector     | trait SensorAnomalyDetector: analyze | core/sensors_analyzer.rs | Sensor anomaly detection                    |
| WeatherProvider           | trait WeatherProvider: get_weather, ... | core/weather_val.rs  | Weather data provider                       |
| ScoringStrategy           | trait ScoringStrategy: calculate_score | core/cross_location.rs | Trust scoring strategy                      |

---

## 🔑 Config & Endpoints

### Environment Keys (.env / config)

| Key Name      | Role                    | Example                       |
| ------------- | ----------------------- | ----------------------------- |
| API_KEY       | Main authentication key | API_KEY=your_secret_key       |
| JWT_SECRET    | JWT signing/verification secret | JWT_SECRET=32+_chars_secret |
| DATABASE_URL  | DB connection string    | DATABASE_URL=mysql://...      |
| LOG_LEVEL     | Logging verbosity       | LOG_LEVEL=debug               |
| GEO_PROVIDER  | Geolocation provider    | GEO_PROVIDER=ipapi            |

---

### API Endpoints

| Path                  | Method | Role (English)                  | Defined In                 |
| --------------------- | ------ | ------------------------------- | -------------------------- |
| /api/auth/login       | POST   | User login                      | api/auth.rs                |
| /api/auth/user        | GET    | Fetch user data                 | api/auth.rs                |
| /api/alerts/trigger   | POST   | Trigger security alert          | api/alerts.rs              |
| /api/geo/resolve      | POST   | Geolocation resolve             | api/geo.rs                 |
| /api/device/resolve   | POST   | Device resolve/register         | api/device.rs              |
| /api/behavior/analyze | POST   | Behavior analysis               | api/behavior.rs            |
| /api/network/analyze  | POST   | Network analysis                | api/network.rs             |
| /api/sensors/analyze  | POST   | Sensors data analysis           | api/sensors.rs             |
| /api/weather/summary  | GET    | Weather summary                 | api/weather.rs             |
| /api/dashboard        | GET    | Dashboard summary               | api/dashboard.rs           |
| /api/smart_access     | POST   | Smart composite access check    | api/smart_access.rs        |

---

## 🧭 Architecture

```mermaid
graph TD
    A[main.rs 🧩\nEntry] --> B[API Layer 🌐]
    A --> C[Core Engines 🧠]
    A --> D[DB Layer 🗄️]
    B -->|Endpoints| E[🔓 /auth, /alerts, /users, ...]
    C --> F[GeoResolver 🌍]
    C --> G[BehaviorEngine 🧠]
    C --> H[DeviceFingerprint 📱]
    C --> I[NetworkAnalyzer 🌐🔍]
    C --> J[SensorsAnalyzer 📡]
    C --> K[WeatherEngine ☁️]
    C --> L[CrossValidator 🔄]
    C --> M[CompositeVerifier 🛡️]
    C --> N[HistoryService 🕓]
    D --> O[CRUD + Models ⚙️]
    B --> P[Security Layer 🔐]
    P --> Q[InputValidator 📥]
    P --> R[JWT Manager 🔑]
    P --> S[Policy Engine ⚖️]
    P --> T[RateLimiter 🚦]
```

> **Description:**
> The diagram shows the interaction of main units (API, core engine, DB, security layer) highlighting new engines (sensors, weather, cross-validation, history) up to the smart composite security layer.

---

## 🛠️ Verification Examples

### Full Composite Security Check

```rust
let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
let allowed_hours = Some((6, 18));
let access_granted = composite_verifier.verify_smart_access(
    geo_input, // (Option<IpAddr>, Option<(f64, f64, u8, f64)>)
    behavior_input, // BehaviorInput
    (os, device, env), // (&str, &str, &str)
    &allowed_zones,
    allowed_hours,
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
let device_fp = device_fp_engine.generate_fingerprint(os, device, env).await?;
if device_fp.security_level >= 5 {
    // Device is trusted
} else {
    // Device is not trusted
}
```

---

### Role Verification Only

```rust
use mkt_ksa_geo_sec::security::policy::{Role, has_permission, Permission};

let role = Role::Admin;
if has_permission(role, Permission::AccessDashboard) {
  // User has required role/permission
} else {
  // User lacks required role/permission
}
```

---

## ⚙️ Core Engine Modules

### 🕓 History Service

- **Description:** Manages, stores, and analyzes historical events and behaviors for users/devices, with anomaly detection and DB integration.
- **Key functions:** log_event, get_entity_history, detect_timeline_anomalies

---

### 🔄 Cross-Validation Engine

- **Description:** Advanced orchestrator combining results from verification engines (geo, behavior, device, etc.) to issue a final, signed verdict.
- **Key functions:** validate, sign_verdict

---

### 📡 Sensors Analyzer

- **Description:** Analyzes sensor data (e.g., accelerometer, gyroscope) for anomalies/tampering, issuing a digitally signed analysis certificate.
- **Key functions:** analyze (SensorsAnalyzerEngine)

---

### ☁️ Weather Validation

- **Description:** Aggregates and validates weather data from multiple providers, comparing results and providing unified, reliable data.
- **Key functions:** fetch_and_validate (WeatherEngine)

---

## ⚠️ Dependency Audit

This section reflects the current hardened profile (`main`, strict CI):

- `db-mysql` exists as a feature flag but is intentionally blocked at compile time in the current secure profile.
- Active graph avoids vulnerable MySQL transitive paths; `cargo audit --deny warnings` passes.
- No OpenSSL dependency in the default path (`reqwest` is configured with `rustls-tls`).
- Packaging excludes local cache and secrets (`.cargo-home/**`, `target/**`, `.env`, `.env.*`).

Current core direct dependencies in `Cargo.toml` include:

- Web/runtime: `actix-web`, `actix-rt`, `tokio`
- Security/crypto: `aes-gcm`, `hmac`, `sha2`, `blake3`, `jsonwebtoken`, `secrecy`, `zeroize`, `pqcrypto-mlkem`
- Data/validation: `serde`, `serde_json`, `validator`, `regex`, `chrono`, `uuid`
- Networking/geo: `reqwest` (Rustls), `maxminddb`
- Utilities: `anyhow`, `thiserror`, `rayon`, `lru`, `config`, `futures`, `log`

---

## ✅ Test Results

```bash
running 39 tests
... all tests passed ...

test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

* All tests passed (39 tests).

---

## 🔒 Current Release Stability

- Toolchain/Env: Stable Rust toolchain with clean lockfile and deterministic CI checks.
- Build: `cargo check` successful.
- Tests: `cargo test --workspace` fully passing (39/39).
- Formatting: `cargo fmt --check` clean.
- Linter: `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Security: `cargo audit --deny warnings` clean.
- Operational note: `db-mysql` path is intentionally disabled in this hardened release profile.

---

## ⬆️ Full Dependency Upgrade Plan

### Scope
- Keep dependencies patched on a rolling basis while preserving public API compatibility.

### Policy
- No general breaking changes: upgrade in stages, running build/tests and `audit/clippy/fmt` after each stage.
- Do not modify the public API behavior in this track; any breaking adjustments are deferred to a major release.

### Stages
1) Refresh lockfile and run strict local gates.
2) Apply patch/minor updates for direct dependencies only.
3) Re-run compatibility checks for API and FFI surfaces.
4) Promote only changes that pass strict security/lint/test gates.

### Guarantees
- Run full CI at each stage: `check`, `test`, `fmt`, `clippy`, `audit`.
- Document outcomes of each stage in release notes before merge.

## ⭐ Features & Target Audiences

### 🎯 Library Purpose & Security Strength

- **Purpose:**
  - To provide a comprehensive smart security verification platform for smart cities, sovereign entities, financial institutions, and technology companies, with full support for customization and integration.
  - Designed to be a standard for geolocation and behavioral security in high-sensitivity environments, with scalability and easy integration into any modern system.
- **Security Strength:**
  - The library is built on a modular, multi-layered architecture, combining geolocation verification, behavioral analytics, device fingerprinting, network analysis, tamper detection, cross-validation, and weather/sensor auditing.
  - All operations are backed by advanced encryption (AES-GCM, HMAC, Post-Quantum), secure secret management (secrecy, zeroize), and digital signatures.
  - No reliance on OpenSSL; only secure, modern Rust libraries are used.
  - Supports smart city policies, concealment tool detection (VPN/Proxy/Tor), and provides historical logging and anomaly analysis.

---

### 🏆 Main Features

* 🔐 Multi-source composite verification: (geo, behavior, device, network, sensors, weather).
* 🧠 AI integration & adaptive security: AI support and adaptive security algorithms.
* 🛰️ Advanced concealment detection: VPN/Proxy/Tor detection and advanced methods.
* 🏙️ Smart city & enterprise policies: advanced zones/permissions/times support.
* ⚡ Modular, flexible architecture: pluggable and customizable for any engine or logic.
* 📄 Full English documentation: every part is fully documented in English.
* 🔑 Secret management & post-quantum crypto: secrecy and post-quantum crypto support.
* 🚦 Rate limiting: built-in RateLimiter module.
* 🔌 Easy integration: REST API or direct Rust Traits.
* 🕓 Historical logging & anomaly analysis: advanced history module.
* ☁️ Weather data auditing: weather module for environmental checks.
* 📡 Sensor data analysis: supports smart device and IoT scenarios.

---

### 👤 Target Audiences

- **Sovereign and Governmental Entities:**
  - Sovereign agencies, security sectors, command and control centers, smart cities, cybersecurity, passports, traffic, civil defense, municipalities, emergency systems.
- **Financial and Banking Institutions:**
  - Banks, insurance companies, digital payment providers, stock exchanges.
- **Large and Medium Technology Companies:**
  - Cloud service providers, AI companies, cybersecurity, IoT, smart city solutions.
- **Transport and Logistics Companies:**
  - Delivery companies, smart transport, fleet management, aviation, airports.
- **Healthcare Sector:**
  - Hospitals, digital health systems, emergency medical management.
- **Education Sector:**
  - Universities, smart schools, secure digital exam systems.
- **Identity and Access Applications:**
  - Access control systems, multi-factor authentication (MFA), digital identity solutions.
- **Energy and Utilities Companies:**
  - Electricity, water, oil & gas, smart infrastructure networks.
- **Industrial and Control Sector:**
  - Smart factories, SCADA systems, industrial robotics.
- **Any developer or organization seeking modern, customizable, and integrable security solutions.**

---

## 🧠 Developer Guide

### 🚀 Basic Integration Steps

1. **Set up environment variables (.env/config):**

   ```bash
   API_KEY=your_secret_key
   DATABASE_URL=mysql://user:pass@host/db
   ```
2. **Initialize core engines in your app:**

   * Call public functions like:
     `verify_smart_access`, `process`, `generate_fingerprint`
3. **Customize security logic:**

   * Inject your own AI model or custom verification logic via Traits
   * Easily customize policies (zones, times, permissions)
4. **Use API endpoints or direct Rust integration:**

   * Call REST API (/users/{id}, /alerts/trigger)
   * Or bind functions directly in code

#### Quick Integration Example (Rust)

```rust
let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
let allowed_hours = Some((6, 18)); // 6 AM to 6 PM
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

## 🔌 Feature Flags

#### This crate supports advanced feature flags to activate specialized capabilities.  
#### You can enable them via `Cargo.toml` like this:

toml
#### [dependencies]
#### MKT_KSA_Geolocation_Security = { version = "1.0.0", features = ["adaptive", "quantum"] }

| Feature Name          | Description                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `adaptive`            | Enables AI-driven adaptive behavior analysis.                                                |
| `ar_integration`      | Integrates Augmented Reality (AR) sources for enhanced location validation.                  |
| `autonomous_vehicles` | Activates modules designed for autonomous cars and smart fleet systems.                      |
| `blockchain`          | Supports blockchain-based authentication and data anchoring.                                 |
| `generative_ai`       | Uses generative AI models to dynamically generate and adjust security policies.              |
| `gpu`                 | Enables GPU acceleration for heavy analysis (e.g. sensor or network data).                   |
| `predictive`          | Adds predictive modeling and anomaly detection based on behavioral patterns.                 |
| `quantum`             | Activates modules compatible with post-quantum cryptography.                                 |
| `quantum_computing`   | Enables integrations with quantum computing backends and processors.                         |
| `v1_1`                | Enables compatibility with API version 1.1 for legacy support.                               |
| `v2_0`                | Enables compatibility with API version 2.0 (default for most modules).                       |
| `v3_0`                | Enables next-gen modules for upcoming API version 3.0.                                       |
| `zkp`                 | Adds support for Zero-Knowledge Proofs for privacy-preserving validation and access control. |
```
 
## 📦 Using as a Rust library

```toml
[dependencies]
MKT_KSA_Geolocation_Security = "1.0.2" # import path in Rust: mkt_ksa_geo_sec
# Or from Git:
# MKT_KSA_Geolocation_Security = { git = "https://github.com/mktmansour/MKT-KSA-Geolocation-Security" }
```

```rust
use mkt_ksa_geo_sec::core::geo_resolver::{
    GeoResolver, DefaultAiModel, DefaultBlockchain, GeoReaderEnum, MockGeoReader,
};
use mkt_ksa_geo_sec::security::secret::SecureBytes;
use std::sync::Arc;

let resolver = GeoResolver::new(
    SecureBytes::new(vec![1; 32]),
    Arc::new(DefaultAiModel),
    Arc::new(DefaultBlockchain),
    true,
    false,
    Arc::new(GeoReaderEnum::Mock(MockGeoReader::new())),
);
```

Note: The Rust import path is `mkt_ksa_geo_sec`.

## 🔗 Linking via C-ABI

- Built as `cdylib/staticlib` and consumable from C/C++/Python/.NET/Java/Go.
- Exported functions:
  - `generate_adaptive_fingerprint(os: *const c_char, device_info: *const c_char, env_data: *const c_char) -> *mut c_char`
  - `free_fingerprint_string(ptr: *mut c_char)`

Generated header filename: `mkt_ksa_geo_sec.h`.

Minimal C usage:

```c
// header generated via cbindgen
char* fp = generate_adaptive_fingerprint("Windows", "LaptopX", "Office");
printf("%s\n", fp);
free_fingerprint_string(fp);
```
---

## 🌐 Multi-language Support

- The library is language-agnostic and fits all projects through three parallel paths:
  - **C-ABI**: Direct binding via `mkt_ksa_geo_sec.h` and `cdylib/staticlib` (recommended for performance).
  - **REST API**: When network-based integration is preferred.
  - **Official wrappers (planned)**: Python/Java/.NET/Node/Go. Meanwhile, use C-ABI directly as below.

### Python (ctypes)
```python
import ctypes
lib = ctypes.cdll.LoadLibrary("./libmkt_ksa_geo_sec.so")  # or mkt_ksa_geo_sec.dll / dylib
lib.generate_adaptive_fingerprint.restype = ctypes.c_void_p
fp_ptr = lib.generate_adaptive_fingerprint(b"Windows", b"LaptopX", b"Office")
print(ctypes.cast(fp_ptr, ctypes.c_char_p).value.decode())
lib.free_fingerprint_string(fp_ptr)
```

### Java (JNA)
```java
public interface GeoSec extends com.sun.jna.Library {
  GeoSec INSTANCE = com.sun.jna.Native.load("mkt_ksa_geo_sec", GeoSec.class);
  com.sun.jna.Pointer generate_adaptive_fingerprint(String os, String dev, String env);
  void free_fingerprint_string(com.sun.jna.Pointer p);
}
```

### .NET (P/Invoke)
```csharp
[DllImport("mkt_ksa_geo_sec")]
static extern IntPtr generate_adaptive_fingerprint(string os, string dev, string env);
[DllImport("mkt_ksa_geo_sec")] static extern void free_fingerprint_string(IntPtr p);
```

### Node.js (ffi-napi)
```js
const ffi = require('ffi-napi');
const lib = ffi.Library('mkt_ksa_geo_sec', { 'generate_adaptive_fingerprint': ['pointer',['string','string','string']], 'free_fingerprint_string': ['void',['pointer']] });
```

> Note: Filenames and symbol names may vary by OS and library extension. Use `mkt_ksa_geo_sec.h` as the authoritative reference for FFI signatures.



#### 💡 Advanced Tips

* All engines are pluggable or replaceable
* Full customization (session/device/role)
* All examples, functions, and constants are fully documented in English

---

## 📝 Release Notes v1.0.2

- **Severity**: Low to Medium – code quality and linter cleanups, no public behavior changes.
- **Key Fixes:**
  - Full strict Clippy pass with `-D warnings` across all targets; zero warnings remain.
  - Unified JWT extraction patterns in API and adopted `let-else` where suitable.
  - Localized `#[allow(...)]` only when changing code would risk public API/behavior.
  - Added `# Errors`/`# Panics` documentation in critical Result-returning functions.
  - Addressed floating-point and suboptimal_flops hints via targeted allows without changing logic.
  - Resolved `unused_async`/`unused_self` for internal/experimental functions.
  - No public API changes; no logic/files removed.
- **Tests**: 39/39 passing.
- **Clippy**: fully clean.
- **Dependencies**:
  - No production dependency versions changed in this release.
  - Note: duplicate transitive versions (e.g., base64/http/lru/windows-sys) retained intentionally to avoid breakage.
  - `cargo audit --deny warnings` is currently clean in the active hardened profile.

#### 🔄 Dependency Changes (this session)
- **Removed**:
  - `once_cell`, `lazy_static`: replaced by `std::sync::LazyLock`.
  - `serde_derive`: redundant since `serde` enables `derive` feature.
  - `getrandom` (direct): removed as a direct dependency; switched to `rand::rngs::OsRng::try_fill_bytes` for secure randomness.
- **Updated**:
  - `reqwest`: 0.12.22 → 0.12.23 (Rustls; minor patches).
  - `pqcrypto-mlkem`: 0.1.0 → 0.1.1.
  - `secrecy`: 0.8.x → 0.10.3. Introduced internal wrappers `security::secret::{SecureString, SecureBytes}` to abstract breaking API changes. All call sites updated with no behavior/security change.
- **Transitive bumps**:
  - `async-trait`, `hyper`, `thiserror`, and others auto-updated within constraints.

#### 🆕 New Files Created
- `src/security/signing.rs`: Central high-security HMAC signing module (no OpenSSL).
- `src/utils/precision.rs`: Precision utilities for time/numeric/geospatial calculations.

### 🔧 Internal Signature Changes (no behavior/route changes)

- **API layer** (`src/api/*.rs`):
  - Switched from `HttpRequest` to extractors: `web::Data<AppState>`, `web::Json<...>`, and `BearerToken` to ensure Send-safe futures and cleaner handler signatures.
- **Geo engine** (`src/core/geo_resolver.rs`):
  - `resolve` now takes a `ResolveParams` struct instead of many positional args; all call sites updated.
- **Behavior engine** (`src/core/behavior_bio.rs`):
  - `get_user_profile_data` is now synchronous (removed `async` as there was no `await`); updated call in `src/api/auth.rs` (removed `.await`).
- **Device FP / FFI** (`src/core/device_fp.rs`):
  - C-ABI functions are now `unsafe extern "C"` with `# Safety` docs, preserving implementation logic.
  - All `secrecy::Secret`/`SecretVec` usages migrated to `security::secret::{SecureString, SecureBytes}`.

### 🧹 Formatting and Extra Checks
- Applied `cargo fmt --all` to fix minor formatting diffs reported by `--check`.
- `cargo tree -d` shows acceptable transitive duplicates at present: `base64 (0.21/0.22)`, `http (0.2/1.x)`, `lru (0.14/0.16)`, `hashbrown (0.14/0.15)`, `socket2 (0.5/0.6)`, `windows-sys (0.52/0.59)`.

#### 📑 Current Signatures (Reference)

- **API Handlers**

```rust
pub async fn trigger_alert(
    payload: web::Json<AlertTriggerRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn analyze_behavior(
    app_data: web::Data<AppState>,
    payload: web::Json<BehaviorAnalyzeRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn dashboard_summary(bearer: BearerToken) -> impl Responder;

pub async fn resolve_device(
    app_data: web::Data<AppState>,
    payload: web::Json<DeviceResolveRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn resolve_geo(
    app_data: web::Data<AppState>,
    payload: web::Json<GeoResolveRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn analyze_network(
    app_data: web::Data<AppState>,
    payload: web::Json<NetworkAnalyzeRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn analyze_sensors(
    app_data: web::Data<AppState>,
    payload: web::Json<SensorsAnalyzeRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn weather_summary(
    _payload: web::Json<WeatherSummaryRequest>,
    bearer: BearerToken,
) -> impl Responder;
```

- **Core**

```rust
impl GeoResolver {
    pub async fn resolve(
        &self,
        params: ResolveParams,
    ) -> Result<GeoLocation, GeoResolverError>;
}

impl UserService {
    pub fn get_user_profile_data(
        &self,
        _requester_id: Uuid,
        _target_user_id: Uuid,
    ) -> Result<User, BehaviorError>;
}
```

- **FFI surface (C ABI)**

```rust
pub unsafe extern "C" fn generate_adaptive_fingerprint(
    os: *const c_char,
    device_info: *const c_char,
    env_data: *const c_char,
) -> *mut c_char;

pub unsafe extern "C" fn free_fingerprint_string(ptr: *mut c_char);
```
---
