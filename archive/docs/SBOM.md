## SBOM (Software Bill of Materials)

Arabic: قائمة مكوّنات البرمجيات للمشروع مع إبراز أن النواة تعمل بلا تبعيات خارجية افتراضيًا، والميزات اختيارية عبر خصائص `features` دون إضافة مكتبات.

English: Project software bill of materials highlighting the zero-deps core by default; optional capabilities are toggled via `features` without pulling external crates.

---

### Crate metadata
- Name: `MKT_KSA_Geolocation_Security`
- Version: 1.0.2
- Edition: 2021
- License: Apache-2.0
- Crate types: `rlib`, `cdylib`, `staticlib`

### Binaries
- `MKT_KSA_Geolocation_Security` (requires features: `api_actix`, `rt_tokio`, `db_mysql`, `geo_maxminddb`) — not enabled by default
- `std_dashboard_demo` (requires feature: `api_std_http`) — local demo only; no production UI

### Dependency model
- Default feature set: no external dependencies (zero-deps core)
- Optional features (no external crates pulled unless explicitly integrated):
  - `sign_hmac`, `ledger_blake3`, `ffi_c`
  - Functional areas: `egress`, `api_std_http`, `compress_rle`, `smtp_std`, `egress_http_std`
  - Legacy names (kept empty): `db_mysql`, `core_full`, `api_actix`, `jwt`, `validation`, `jws`, `serde`, `secure_secrecy`, `webhook_out`, `egress_url`, `egress_reqwest`, `rt_tokio`, `geo_maxminddb`, `uuid_fmt`, `parallel`, `crypto_aesgcm`, `webhook_in`
  - Utilities: `core_utils`, `input_validation`, `config_loader`

### Public surfaces (high-level)
- API (zero-deps HTTP): `src/api/std_http.rs`
  - Routes include: `/metrics`, `/events.ndjson`, `/toggle`, `/fw/*`, `/backup/*`, `/features/*`, `/export/csv`, `/cloud/push`, `/webhook/guard/*`, `/anti_replay/purge/*`, `/memory/*`, `/policy/*`, `/keys/*`, `/webhook/in` (UI routes are removed and return 404)
  - Per-path guards registry: `src/webhook/guards/` with `GuardConfig` and built-in registrations
- Key management (in-memory, zero-deps): `src/crypto/key_rotation.rs`
  - Create/rotate keys, anti-replay, adaptive purge scheduler, optional RNG provider, auto-rotation controller
- Security inspection: `src/security/inspection_policy.rs`, `src/security/inspection.rs`
  - Live runtime policy; JSON and DSL configuration
- Telemetry: `src/telemetry/mod.rs`
  - Counters, events, risk scoring, adaptive tightening/relaxation, memory guard, backups, feature toggles

### FFI surface (when `ffi_c` enabled)
- `mkt_abi_version() -> u32` — stable ABI version
- `mkt_version_string() -> *const c_char` — C-ABI NUL-terminated version string
- `mkt_semver_string() -> *const c_char` — C-ABI NUL-terminated SemVer string
- `mkt_hmac_sha512(data,key,out) -> i32` — compute HMAC-SHA512 tag (64 bytes)

### Security capabilities (core)
- HMAC-SHA512 signing/verification (feature-gated)
- Anti-replay per key with nonce/timestamp windows; adaptive purge policy (daily/weekly/monthly)
- Per-path webhook guards: signature required/optional, timestamp window, anti-replay on/off, adaptive hardening/relaxation
- Egress Guard (feature-gated): allowlist and private-range protections for outbound HTTP
- Inspection policy (limits, content-type, path/method allow/deny)
- Memory guard with auto/manual purging and alerts

### Localization
- Dashboard UI removed in production; API responses remain language‑agnostic

### Build and features matrix (examples)
- Core library (zero-deps): `cargo build`
- Demo sidecar (std HTTP): `cargo run --bin std_dashboard_demo --features api_std_http`
- With HMAC signing: add `--features sign_hmac`
- With RLE compression: add `--features compress_rle`
- With FFI C-ABI: add `--features ffi_c`

### Notes
- No external crypto or HTTP clients are linked by default; optional code paths are implemented in-house or behind feature flags.
- All guards and policies are runtime-configurable through zero-deps HTTP endpoints.



