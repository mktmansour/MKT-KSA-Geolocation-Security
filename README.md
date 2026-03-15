# MKT_KSA_Geolocation_Security

Production-grade geolocation and behavioral security system for Rust services and smart-city access control.

[![Rust](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml/badge.svg?branch=main&event=push)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml)
[![Clippy](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml/badge.svg?branch=main&event=push)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml)
[![Crates.io](https://img.shields.io/crates/v/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![Docs.rs](https://img.shields.io/docsrs/MKT_KSA_Geolocation_Security?style=for-the-badge)](https://docs.rs/MKT_KSA_Geolocation_Security)
[![Downloads](https://img.shields.io/crates/d/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)

![MKT KSA Geolocation Security Cover](docs/images/mkt_ksa.png)

## Latest Status and Strategic Notice (2026-03-15)

- Active release target is now **2.0.1** due to security and engineering fixes.
- Security hardening and architecture cleanup have been completed on `main`.
- The active runtime database path is hardened SQLite (`tokio-rusqlite`) with migrations.
- JWT authorization and rate limiting are centralized for all API routes.
- Dashboard code and legacy stale reports were removed to reduce attack/documentation drift.
- Repository entered strict hygiene mode: stale docs removed and active file-role map added.

## Maintenance Policy (Important)

- This repository is now in **security-maintenance mode**.
- **No new feature development is planned** in this repository.
- Future updates here will be limited to security fixes and critical stability corrections.
- A new sovereign successor platform is under development and planned for announcement in 2026.
- The successor project is being built from scratch with **zero external dependencies** and sovereign internal packages.

### Successor Program Announcement

![MKT KSA Integrated Cyber Defense Platform Announcement](docs/images/2026mkt.png)

## Community Note

- The crate has been downloaded thousands of times.
- Engagement feedback (issues/comments/reactions) has been significantly lower than expected.
- Constructive security and production feedback is highly encouraged.

## Contents

- 🧭 [1. What This Project Does](#1-what-this-project-does)
- 🎯 [1.1 Project Goal](#11-project-goal)
- ⭐ [1.2 Key Features](#12-key-features)
- 🏛️ [1.3 Target Audiences](#13-target-audiences)
- 🛡️ [2. Runtime and Security Posture](#2-runtime-and-security-posture)
- 🗂️ [3. Complete Repository Role Map](#3-complete-repository-role-map)
- 🔄 [4. Module Interactions and Control Flow](#4-module-interactions-and-control-flow)
- 🏗️ [4.1 Project Architecture Diagram](#41-project-architecture-diagram)
- 🌐 [5. API Reference and Invocation](#5-api-reference-and-invocation)
- 🔐 [6. Environment Variables](#6-environment-variables)
- ✅ [7. Build, Run, and Validate](#7-build-run-and-validate)
- 🧱 [8. Current Hardening and Fix History](#8-current-hardening-and-fix-history)
- 🔌 [9. Library Integration and C-ABI](#9-library-integration-and-c-abi)
- 📚 [10. Detailed Folder and File Responsibilities](#10-detailed-folder-and-file-responsibilities)

## 1. What This Project Does

![Section 01 Banner](docs/images/banners/section-01.svg)

`MKT_KSA_Geolocation_Security` combines multiple trust signals into one security decision:

- Geolocation verification
- Behavioral anomaly analysis
- Device fingerprint analysis
- Network concealment analysis (proxy/VPN risk)
- Sensor signal anomaly analysis
- Weather consistency checks
- Smart composite access verification

The API layer is served through Actix Web, while core engines are reusable as a Rust library.

### 1.1 Project Goal

- Provide a strict, engineering-grade geolocation security core for sovereign and enterprise workloads.
- Reduce fraud risk by combining multiple signals into one verifiable trust decision.
- Maintain a deterministic and auditable security posture under production pressure.

### 1.2 Key Features

- Multi-signal trust evaluation: location, behavior, device, network, sensors, weather.
- Centralized authorization controls: JWT validation + per-IP rate limiting.
- Hardened runtime policy: SQLite-only profile with migration-managed schema.
- Security-safe secret handling and runtime-generated internal engine keys.
- API + library dual usage model for service integration and internal embedding.

### 1.3 Target Audiences

- Sovereign and government entities.
- Financial institutions and digital payment systems.
- Critical infrastructure operators (energy, transport, utilities).
- Healthcare and identity-sensitive platforms.
- Security engineering teams building smart-city and fraud-resilient services.

## 2. Runtime and Security Posture

![Section 02 Banner](docs/images/banners/section-02.svg)

- Language: Rust 2021
- Framework: Actix Web
- Async runtime: Tokio
- Active DB: SQLite only (`DATABASE_URL=sqlite://...`)
- JWT: centralized decode/validation via `JwtManager`
- Rate limiting: centralized per-IP checks before endpoint logic
- Internal engine secrets: generated securely at runtime (no hardcoded secret literals)
- Secret handling: `secrecy` + `zeroize`
- Signing: HMAC-SHA512/HMAC-SHA384
- Migrations: versioned SQL migrations in `src/db/migrations`

## 3. Complete Repository Role Map

![Section 03 Banner](docs/images/banners/section-03.svg)

### Root files

| Path | Role |
|---|---|
| `Cargo.toml` | Package metadata, dependencies, features, crate types |
| `Cargo.lock` | Deterministic dependency resolution |
| `rust-toolchain.toml` | Toolchain lock and MSRV governance |
| `README.md` | Primary English technical documentation |
| `README_AR.md` | Primary Arabic technical documentation |
| `SECURITY.md` | Vulnerability disclosure policy |
| `CHANGELOG.md` | Release and maintenance history |
| `CONTRIBUTING.md` | Contribution workflow and conventions |
| `Dockerfile` | Containerized deployment entry |
| `audit.toml` | `cargo-audit` configuration |
| `cbindgen.toml` | C-ABI header generation config |
| `.env.example` | Environment template |
| `GeoLite2-City-Test.mmdb` | Test geolocation fixture |

### Directories

| Directory | Role |
|---|---|
| `.github/` | CI/CD, CodeQL, PR governance, code ownership |
| `docs/` | Security hardening reports and repository governance docs |
| `examples/` | Library usage examples |
| `scripts/` | CI/maintenance scripts |
| `src/` | Production source code |
| `tests/` | Integration and security surface tests |
| `target/` | Local build artifacts (non-source) |

### `src/` detailed map

| Path | Role | Interactions |
|---|---|---|
| `src/main.rs` | Process bootstrap, engine wiring, server startup | Builds `AppState`, registers API routes |
| `src/lib.rs` | Public library entry and re-exports | Exposes `api/core/db/security/utils` |
| `src/app_state.rs` | Shared runtime state container | Injected into all handlers |
| `src/api/mod.rs` | Unified API route registration + auth gate helper | Calls submodules and centralized authorization |
| `src/api/*.rs` | Endpoint handlers by domain | Use `authorize_request`, call core/db |
| `src/core/*.rs` | Core analysis engines and domain logic | Consumed by API and tests |
| `src/db/mod.rs` | DB module wiring | Exposes models/crud/migrations |
| `src/db/models.rs` | DB model structs | Used by CRUD and handlers |
| `src/db/crud.rs` | SQLite DB operations | Called by auth/alerts and bootstrap |
| `src/db/migrations.rs` + SQL files | Schema versioning and migration execution | Called on startup |
| `src/security/*.rs` | JWT, policy, rate-limit, validation, secret/signing | Used across API and core |
| `src/utils/*.rs` | Caching, precision math, helpers, logging | Shared utilities |

## 4. Module Interactions and Control Flow

![Section 04 Banner](docs/images/banners/section-04.svg)

1. `main.rs` loads environment and validates security-critical config (`JWT_SECRET`, DB policy).
2. `main.rs` initializes engines and shared services, then constructs `AppState`.
3. HTTP request hits `/api/...` route configured in `src/api/mod.rs`.
4. `authorize_request()` enforces:
   - Authorization header presence
   - Rate limit policy
   - JWT decode/validation
5. Handler calls the relevant core engine or DB layer.
6. Response is returned as JSON (or HTTP error with strict status semantics).

### 4.1 Project Architecture Diagram

![Project Architecture Diagram](docs/images/project-architecture.svg)

The diagram maps real repository structure from entry and API layers to security controls, core engines, and data/support modules.

## 5. API Reference and Invocation

![Section 05 Banner](docs/images/banners/section-05.svg)

Base URL: `http://127.0.0.1:8080`
All endpoints are under `/api`.
All endpoints require: `Authorization: Bearer <JWT>`.

### 5.1 Route table

| Method | Path | Module | Purpose |
|---|---|---|---|
| `GET` | `/api/users/{id}` | `src/api/auth.rs` | Fetch user by UUID (self/admin check) |
| `POST` | `/api/geo/resolve` | `src/api/geo.rs` | Cross-location validation |
| `POST` | `/api/device/resolve` | `src/api/device.rs` | Device fingerprint analysis |
| `POST` | `/api/behavior/analyze` | `src/api/behavior.rs` | Behavioral risk analysis |
| `POST` | `/api/sensors/analyze` | `src/api/sensors.rs` | Sensor anomaly analysis |
| `POST` | `/api/network/analyze` | `src/api/network.rs` | Network trust / concealment analysis |
| `POST` | `/api/alerts/trigger` | `src/api/alerts.rs` | Persist and register a security alert |
| `POST` | `/api/weather/summary` | `src/api/weather.rs` | Weather validation summary |
| `POST` | `/api/smart_access/verify` | `src/api/smart_access.rs` | Composite smart access decision |

### 5.2 Invocation examples

Get user:

```bash
curl -X GET "http://127.0.0.1:8080/api/users/<uuid>" \
  -H "Authorization: Bearer <jwt>"
```

Geo resolve:

```bash
curl -X POST "http://127.0.0.1:8080/api/geo/resolve" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address":"8.8.8.8",
    "gps_data":[24.7136,46.6753,8,1.0],
    "os_info":"ios",
    "device_details":"iphone-15",
    "environment_context":"mobile-4g",
    "behavior_input":{
      "user_id":"00000000-0000-0000-0000-000000000000",
      "event_type":"login",
      "ip_address":"8.8.8.8",
      "device_id":"device-1",
      "timestamp":"2026-03-15T00:00:00Z"
    }
  }'
```

Device resolve:

```bash
curl -X POST "http://127.0.0.1:8080/api/device/resolve" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"os":"android","device_info":"pixel-8","environment_data":"corp-wifi"}'
```

Behavior analyze:

```bash
curl -X POST "http://127.0.0.1:8080/api/behavior/analyze" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "input":{
      "user_id":"00000000-0000-0000-0000-000000000000",
      "event_type":"payment",
      "ip_address":"8.8.4.4",
      "device_id":"device-1",
      "timestamp":"2026-03-15T00:00:00Z"
    }
  }'
```

Network analyze:

```bash
curl -X POST "http://127.0.0.1:8080/api/network/analyze" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.1.1.1","conn_type":"WiFi"}'
```

Sensors analyze:

```bash
curl -X POST "http://127.0.0.1:8080/api/sensors/analyze" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "reading":{"timestamp":1710000000,"accel":0.9,"gyro":0.3,"temp":25.0},
    "history":[{"timestamp":1709999900,"accel":0.8,"gyro":0.2,"temp":24.8}]
  }'
```

Weather summary:

```bash
curl -X POST "http://127.0.0.1:8080/api/weather/summary" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"latitude":24.7136,"longitude":46.6753}'
```

Trigger alert:

```bash
curl -X POST "http://127.0.0.1:8080/api/alerts/trigger" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id":"00000000-0000-0000-0000-000000000000",
    "entity_type":"user",
    "alert_type":"suspicious_login",
    "severity":"high",
    "details":{"ip":"8.8.8.8","reason":"impossible_travel"}
  }'
```

Smart access verify:

```bash
curl -X POST "http://127.0.0.1:8080/api/smart_access/verify" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "geo_input":["8.8.8.8",[24.7136,46.6753,8,1.0]],
    "behavior_input":{
      "user_id":"00000000-0000-0000-0000-000000000000",
      "event_type":"entry_attempt",
      "ip_address":"8.8.8.8",
      "device_id":"device-1",
      "timestamp":"2026-03-15T00:00:00Z"
    },
    "os_info":"ios",
    "device_details":"iphone-15",
    "env_context":"office-gate"
  }'
```

## 6. Environment Variables

![Section 06 Banner](docs/images/banners/section-06.svg)

| Variable | Required | Description | Example |
|---|---|---|---|
| `API_KEY` | Yes | Application key consumed by config layer | `API_KEY=change_me` |
| `JWT_SECRET` | Yes | JWT signing/validation secret (32+ chars) | `JWT_SECRET=32+_chars_secret_here` |
| `DATABASE_URL` | Recommended | SQLite path; if missing DB endpoints return 503 | `DATABASE_URL=sqlite://data/app.db` |
| `BOOTSTRAP_ADMIN_PASSWORD_HASH` | Optional | If set, seeds bootstrap-admin user on startup with provided hash | `BOOTSTRAP_ADMIN_PASSWORD_HASH=<argon2_hash>` |
| `LOG_LEVEL` | Optional | Log verbosity | `LOG_LEVEL=info` |
| `GEO_PROVIDER` | Optional | Geolocation source selector | `GEO_PROVIDER=ipapi` |

## 7. Build, Run, and Validate

![Section 07 Banner](docs/images/banners/section-07.svg)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Run:

```bash
API_KEY=change_me \
JWT_SECRET=replace_with_a_long_secret_32_chars_min \
DATABASE_URL=sqlite://data/app.db \
BOOTSTRAP_ADMIN_PASSWORD_HASH=replace_with_hash_if_needed \
cargo run
```

## 8. Current Hardening and Fix History

![Section 08 Banner](docs/images/banners/section-08.svg)

Current 2.0.1 coverage includes the following fix/development scope:

- Security hardening: SQLite-only hardened runtime posture with migration enforcement.
- Security hardening: unified JWT and per-IP rate-limit enforcement through centralized API authorization flow.
- Security hardening: runtime generation of internal engine secrets (removed hardcoded runtime secret literals).
- Security hardening: optional bootstrap admin seeding only through `BOOTSTRAP_ADMIN_PASSWORD_HASH`.
- Operational fixes: complete dashboard endpoint/module removal from API surface.
- Operational fixes: replaced dummy endpoint behavior with real logic paths (weather/alerts).
- Operational fixes: bounded in-memory alert store to protect runtime memory.
- Repository hygiene and docs governance: removed stale legacy reports that no longer match active architecture/security posture.
- Repository hygiene and docs governance: added authoritative repository file-role mapping document.
- Repository hygiene and docs governance: rebuilt both primary READMEs with strict bilingual engineering structure.
- Documentation UX: section-by-section visual banners for professional readability, with section names embedded.
- Validation and quality gates: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all` are clean on this update path.

Recent security and maintenance milestones are documented in:

- `docs/SECURITY_HARDENING_2026-03-15.md`
- `docs/GITHUB_ADVANCED_SCAN_2026-03-15.md`
- `docs/REPOSITORY_FILE_ROLES_2026-03-15.md`
- `CHANGELOG.md`

## 9. Library Integration and C-ABI

![Section 09 Banner](docs/images/banners/section-09.svg)

Crate exports include:

- Rust library (`rlib`)
- C-compatible dynamic library (`cdylib`)
- C-compatible static library (`staticlib`)

This supports Rust-native usage and cross-language integration paths.

## 10. Detailed Folder and File Responsibilities

### `.github/`

- `workflows/`: CI pipelines (`rust`, `clippy`, `codeql`, `security-gates`, release automation).
- `actions/secure-workspace/action.yml`: shared workspace-hardening step used by workflows.
- `codeql/codeql-config.yml`: controlled CodeQL scan scope.
- `CODEOWNERS`: review ownership for sensitive paths.
- `pull_request_template.md`: security and quality checklist.

### `docs/`

- `SECURITY_HARDENING_2026-03-15.md`: hardening implementation report.
- `GITHUB_ADVANCED_SCAN_2026-03-15.md`: GitHub/code scanning summary and remediation trail.
- `REPOSITORY_FILE_ROLES_2026-03-15.md`: source-of-truth for active repository file roles.
- `images/cover-mkt-ksa.svg`: primary documentation hero visual.
- `images/banners/section-01.svg` ... `section-09.svg`: section-level visual banners.

### `scripts/`

- `ci/cleanup_workspace.sh`: deterministic CI/local cleanup for stale advisory/cache residue.

### `examples/`

- `using_lib.rs`: practical example of library-level engine usage.

### `tests/`

- `api_integration_auth_rate_limit_db.rs`: integrated auth + rate-limit + DB behavior checks.
- `api_security_surface_integration.rs`: endpoint security-surface checks and burst-rate behavior.
- `support/mod.rs`: shared test support utilities.

### `src/api/`

- `mod.rs`: route registration and centralized authorization helper.
- `auth.rs`: user retrieval endpoint with claim/role checks.
- `geo.rs`: cross-location verification endpoint.
- `device.rs`: device fingerprint endpoint.
- `behavior.rs`: behavioral analysis endpoint.
- `network.rs`: network trust/concealment endpoint.
- `sensors.rs`: sensor anomaly endpoint.
- `alerts.rs`: alert creation endpoint (memory + DB persistence path).
- `weather.rs`: weather summary/validation endpoint.
- `smart_access.rs`: composite smart-access decision endpoint.

### `src/core/`

- `geo_resolver.rs`: geolocation resolution and signature logic.
- `device_fp.rs`: adaptive fingerprint generation and verification paths.
- `behavior_bio.rs`: behavioral analytics and anomaly scoring.
- `network_analyzer.rs`: proxy/vpn/connection analysis.
- `sensors_analyzer.rs`: sensor telemetry anomaly detection.
- `weather_val.rs`: weather provider integration and validation.
- `cross_location.rs`: multi-signal verification orchestrator.
- `composite_verification.rs`: composite smart access policy engine.
- `history.rs`: timeline and anomaly history logic.
- `mod.rs`: core module exports.

### `src/db/`

- `models.rs`: DB model definitions.
- `crud.rs`: async SQLite data operations.
- `migrations.rs`: migration runner.
- `migrations/0001_initial.sql`: baseline schema.
- `migrations/0002_indexes.sql`: index/performance schema upgrade.
- `mod.rs`: DB module exports.

### `src/security/`

- `jwt.rs`: token generation/validation and claims policy checks.
- `ratelimit.rs`: per-IP throttling controls.
- `policy.rs`: authorization policy and role/status guards.
- `input_validator.rs`: normalization and sanitization utilities.
- `secret.rs`: secure wrappers for sensitive values.
- `signing.rs`: HMAC signing and verification helpers.
- `mod.rs`: security module exports.

### `src/utils/`

- `cache.rs`: caching helpers.
- `helpers.rs`: generic utility helpers.
- `logger.rs`: logging helpers.
- `precision.rs`: deterministic precision/math helpers.
- `mod.rs`: utils exports.

### Root operational files

- `Cargo.toml`: package metadata, dependency/runtime policy, and current version (`2.0.1`).
- `Cargo.lock`: pinned dependency graph.
- `README.md` / `README_AR.md`: authoritative primary docs.
- `CHANGELOG.md`: chronological release details.
- `SECURITY.md`: vulnerability disclosure policy.
- `CONTRIBUTING.md`: contribution contract.
- `Dockerfile`: container runtime recipe.
- `audit.toml`: cargo-audit policy.
- `cbindgen.toml`: C-ABI header generation config.
- `GeoLite2-City-Test.mmdb`: test geo fixture used by geolocation-related paths.

## License

Apache-2.0. See `LICENSE`.
