# Changelog

All notable changes to **MKT KSA Geolocation Security** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.1] - 2026-03-17

### Security

- Enforced global request correlation with `X-Request-ID` propagation at middleware level.
- Added strict adaptive AI gate response contract with `AI_RISK_BLOCKED` + `Retry-After` semantics.
- Added centralized structured security event logging for denied/blocked authorization decisions.
- Added request success audit logging with latency metrics (`request_audit outcome=success ... latency_ms=...`).

### Changed

- Standardized successful JSON responses with a strict trace envelope shape:
  - `trace_id`
  - `data`
- Extended centralized API authorization flow to include request payload risk assessment.
- Strengthened CI with security-profile matrix workflow checks for both `strict` and `ultra-strict` modes.

### Testing

- Added integration test for request-id propagation across multiple API endpoints.
- Added integration test validating successful JSON response trace envelope.

### Validation

- `cargo fmt --all`: pass
- `cargo clippy --all-targets -- -D warnings`: pass
- `cargo test --all-targets`: pass
- Live probes: verified `RATE_LIMIT_EXCEEDED` and `AI_RISK_BLOCKED` include `Retry-After` and request correlation.

---

## [2.0.1] - 2026-03-15

### Security

- Added strict multi-language security gate workflow with Semgrep, Gitleaks, and Trivy SARIF upload.
- Added hardened reusable CI action for secure workspace preparation to remove duplicated workflow logic.
- Constrained CodeQL scanning to repository-relevant scope and eliminated stale false-positive alert noise.
- Updated SECURITY.md to a strict language-agnostic security baseline with enforceable CI and incident controls.
- Hardened Dockerfile to run as a non-root user to eliminate container privilege risk.
- Upgraded `jsonwebtoken` to `10.3.0` with explicit crypto provider to remediate `CVE-2026-25537`.
- Enabled GitHub Secret Scanning and Push Protection at repository level.
- Hardened default-branch ruleset: zero bypass actors, required review approval, squash-only merge, required signatures, and enforced code-owner review.
- Strengthened CODEOWNERS mapping for security-critical paths and added strict PR security checklist template.

### Security (Runtime)

- Replaced legacy MySQL runtime posture with hardened SQLite backend (`tokio-rusqlite`) in active profile.
- Unified JWT verification into centralized API path and removed hardcoded secrets from handlers.
- Enforced per-IP rate limiting uniformly through shared API authorization flow.
- Closed unauthenticated access on `smart_access_verify` endpoint.
- Removed hardcoded runtime engine secret literals from startup path and switched to secure OS-random secret generation.
- Made bootstrap admin seed opt-in using `BOOTSTRAP_ADMIN_PASSWORD_HASH` only.

### Fixed

- Removed dashboard endpoint/module completely from API surface and routing.
- Removed duplicated bearer extractor implementation from sensors route.
- Replaced dummy endpoint logic in weather/alerts with real engine and DB-backed behavior.
- Reworked `/users/{id}` endpoint to use strict claim checks (subject or admin role) and SQLite user fetch.
- Added bounded in-memory alert store to cap runtime memory usage.
- Replaced inline DB bootstrap with versioned SQL migration runner.
- Added integration API test covering Auth + Rate Limit + DB in one executable test file.
- Added strict burst integration test validating hard rate-limit behavior under high request pressure.

### Validation

- `cargo check --all-targets`: pass
- `cargo clippy --all-targets -- -D warnings`: pass
- `cargo clippy --all-targets --all-features -- -D warnings`: pass
- `cargo test --all`: pass (39/39)

### Docs

- Added hardening report: `docs/SECURITY_HARDENING_2026-03-15.md`.
- Added advanced GitHub scan report: `docs/GITHUB_ADVANCED_SCAN_2026-03-15.md`.
- Removed outdated legacy documentation (`AUDIT_REPORT.md`, `EVALUATION.md`, `docs/QA_Audit_Clippy_and_Dependencies.md`) to eliminate stale architecture/security claims.
- Added active repository file-role map: `docs/REPOSITORY_FILE_ROLES_2026-03-15.md`.
- Rebuilt `README.md` and `README_AR.md` with strict sectioned engineering structure.
- Added section-level visual SVG banners under `docs/images/banners/` for professional documentation layout.

---

## [2.0.0] - 2026-03-14

### Changed

- **Versioning**: Bumped crate version to `2.0.0` to reflect breaking compatibility impact.
- **Security Profile**: `db-mysql` path remains intentionally disabled in the hardened default profile.
- **Documentation**: Updated `README.md` and `README_AR.md` release references and usage snippets to `2.0.0`.

### Security

- Enforced strict audit gate: `cargo audit --deny warnings`.
- Hardened packaging excludes for cache/secrets paths remain active (`.cargo-home/**`, `target/**`, `.env`, `.env.*`).

### Validation

- `cargo fmt --check`: pass
- `cargo clippy --workspace --all-targets -- -D warnings`: pass
- `cargo test --workspace`: pass (39/39)

### Breaking

- Consumers relying on `db-mysql` runtime path must treat this release as a breaking update and remain on `1.x` until a secure backend path is reintroduced.

## [1.0.2] - 2026-03-13

### Fixed

- **Cargo.toml**: Removed invalid `v` prefix from the package version (`"v1.0.2"` → `"1.0.2"`).
  Cargo requires strict semver without a leading `v`.
- **Cargo.toml**: Removed invalid `disallowed-types` key that was incorrectly placed inside
  the `[dependencies]` section. This is a Clippy lint configuration, not a dependency.
- **.gitignore**: Resolved merge conflict markers (`<<<<<<< HEAD`, `=======`, `>>>>>>>`)
  left over from a previous merge. Both sides specified `secrets.json`; the file is now
  listed once without conflict markers.
- **.gitignore**: Removed the overly broad `**/*.lock` pattern that would incorrectly
  suppress all lock files. Added `.cargo-home/` to prevent the local Cargo cache
  directory from being committed.
- **`src/core/mod.rs`**: Registered the two previously orphaned modules:
  `composite_verification` and `history`. Both source files existed in the `src/core/`
  directory but were never declared in `mod.rs`, making them invisible to the rest of
  the crate.
- **`src/security/mod.rs`**: Restored the `pub mod ratelimit;` declaration that was
  incorrectly removed with a comment claiming the file no longer existed, even though
  `src/security/ratelimit.rs` was still present.
- **`src/api/mod.rs`**: Registered the `smart_access` sub-module and its
  `smart_access_verify` endpoint, which existed in `src/api/smart_access.rs` but were
  not wired into the router.
- **`src/core/history.rs`**: Replaced the `sqlx::PgPool` and `tracing` dependencies
  (which are not present in `Cargo.toml`) with the project's existing stack
  (`mysql_async` / `log`). Removed `#[instrument]` macro usage. Updated
  `HistoryService::new()` signature to no longer require a database pool argument
  (actual DB calls are stubbed out pending full CRUD implementation).
- **`src/core/composite_verification.rs`**: Fixed an `E0223` ambiguous associated type
  error caused by `GeoResolver::ResolveParams` being used as a path expression.
  `ResolveParams` is now imported directly, and unused imports were cleaned up.
- **`src/app_state.rs`**: Added the `composite_verifier: Arc<CompositeVerifier>` field
  that `src/api/smart_access.rs` already referenced via `data.composite_verifier`.
- **`src/main.rs`**: Initialised the `CompositeVerifier` using already-created engine
  `Arc`s (`geo_resolver`, `fp_engine`, `behavior_engine`, `network_engine`) and
  supplied it to `AppState`.

### Improved

- **`src/core/geo_resolver.rs`**: Suppressed the `unused_imports` warning for the
  `log::error` import to keep the compiler output clean until the import is needed.

---

## [1.0.1] - 2025 (previous release)

*No changelog was maintained for this version.*

---

## [1.0.0] - 2025 (initial release)

### Added

- Smart geolocation & behavioural security library for Rust.
- GeoResolver with MaxMind GeoIP2, GPS, SIM, indoor, AR, and satellite data sources.
- AdaptiveFingerprintEngine for device fingerprinting with quantum-safe key exchange.
- BehaviorEngine with anomaly detection (impossible travel, biometric patterns).
- SensorsAnalyzerEngine for hardware sensor integrity checking.
- NetworkAnalyzer with proxy/VPN detection and AI-assisted classification.
- CrossValidationEngine that combines all verification signals into a unified verdict.
- CompositeVerifier for smart-city zone/time access control policies.
- HistoryService for logging and timeline anomaly detection.
- JWT issuance and verification (RS256/HS512).
- Rate-limiting module (`RateLimiter`) with per-IP, per-user, and per-endpoint controls.
- AES-GCM and HMAC-SHA512 signing utilities.
- Input validation and sanitisation helpers (HTML stripping via Ammonia).
- Actix-web HTTP API with endpoints for geo, device, behaviour, sensors, network,
  alerts, weather, and smart-city access verification.
- MySQL Async database layer with optional connection pool.
- C-ABI compatible `cdylib`/`staticlib` crate types for FFI.
