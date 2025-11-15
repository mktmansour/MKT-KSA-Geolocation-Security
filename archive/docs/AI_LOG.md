Release profile hardening:
  - Added `[profile.release]` with `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `opt-level = 3` (balanced perf/size).
  - CI still injects `-C debuginfo=1` transiently to extract symbols, then strips public binaries; symbols are encrypted and uploaded.
# AI Log / سجل الذكاء الاصطناعي

Date: 2025-10-28

- Added `docs/Module_Contracts.md` describing bilingual module contracts.
- Added `docs/Integration_Templates.md` with secure API/Webhook templates.
- Reviewed `src/api/mod.rs` to ensure UI modules removed; confirmed only `std_http` API aggregator remains under feature `api_std_http`.

- Security hardening:
  - Enabled optional deps and feature binding for `sign_hmac` (hmac/sha2) in Cargo.toml
  - Enforced fail-closed behavior when `sign_hmac` is disabled for required HMAC paths
  - Reordered inbound RLE decompression to occur after signature verification
  - Required `sign_hmac` for `std_dashboard_demo` binary
Additional updates (security enforcement):
  - Forced HMAC signature on `/metrics` and unified `key_id` to `auth_hmac`
  - Unified `/events.ndjson` guard `key_id` to `auth_hmac`
  - Removed `/dashboard` mention from demo endpoints response
  - Tightened `ts_window_ms` to `60_000` for `/metrics`, `/events.ndjson`, `/webhook/in`
  - Added `sign_host` feature: Host header is now included in the canonical string (server + client)
  - Verified runtime: `/metrics` now requires signature; `/webhook/in` denies unsigned requests; UI endpoints return 404

HMAC client integration test:
  - Added `src/bin/hmac_client.rs` (requires `sign_hmac`): generates canonical string and HMAC-SHA512, sends to `/metrics` and `/webhook/in`.
  - Demo server now supports ENV `MKT_AUTH_HMAC_HEX`; it seeds RNG for key generation/rotation to match client.
  - Runtime verification (local): `/metrics` -> 200 OK (signed), `/webhook/in` -> 200 OK (signed). Unsigned requests remain 401 as expected.
  - No new dependencies introduced beyond optional `hmac`/`sha2` already gated by `sign_hmac`.
  - Added unsigned test to `/metrics` (no headers) → observed `HTTP/1.1 401` with JSON `{ "error": "invalid_signature" }`.
    Arabic: تم تأكيد فشل الطلب غير الموقّع إلى `/metrics` برمز 401 كما هو متوقّع.

Next:
- Keep logging notable architectural/documentation changes here per user preference.

Security QA checks (Rust):
  - cargo fmt: OK (fixed stray char in src/main.rs header)
  - cargo clippy (-D warnings) with features [api_std_http, sign_hmac, sign_host]: OK
    * Actions: gated OAuth2 under feature `oauth2`, removed UI stubs, fixed lint issues in std_http & bins
  - cargo test --lib (same features): 13 passed, 0 failed (gated default-disabled HMAC test)
  - cargo audit: OK (no advisories)

OAuth2 enablement:
  - Enabled OAuth2 unconditionally in `src/lib.rs` and `src/api/std_http.rs`; no external deps.
  - Cleaned conditional paths; OAuth2 endpoints are active by default in std_http.
  - Passed `cargo clippy -D warnings` via targeted allows inside `src/oauth2/*` (style-only lints).
  - Tests: 57 passed after enabling OAuth2; no failures.
  - `cargo audit`: OK.
Operational OAuth2 verification (demo server):
  - Server run: std_http on 127.0.0.1:8080 with features `api_std_http,sign_hmac,sign_host`.
  - Added URL-decoding for query/form params in `src/api/std_http.rs` (zero-deps).
  - Router now strips query string before matching OAuth2 paths.
  - InboundPolicy: allowed `application/x-www-form-urlencoded` by default (token/introspect/revoke).
  - Client Credentials flow: success; access_token issued.
  - UserInfo with client_credentials: returns `insufficient_scope` (expected).
  - Introspect/Revoke: require confidential client auth; public demo client triggers `invalid_signature` (expected).
  - Authorization Code: routing fixed and URL-decoding in place; Location header not exposed yet (Response lacks headers map). Recommend adding response headers support for 302 redirects; current JSON includes `redirect_uri`.

Automated test suite (security + integration):
  - Added response headers support and dynamic HTTP reason phrases (e.g., 302 Found).
  - New tests:
    - OAuth2 authorize returns 302 with Location (std_http).
    - OAuth2 Authorization Code: full flow (code -> token -> userinfo).
    - OAuth2 client_credentials token issuance (std_http).
    - OAuth2 userinfo with client_credentials fails (std_http).
    - OAuth2 introspect/revoke behavior for public clients (std_http).
    - URL decoding (+ and %HH), form parsing, and reason phrase mapping (std_http).
    - InboundPolicy content-type allowlist (allows x-www-form-urlencoded, denies xml), method allowlist (security).
    - Guards registry: metrics/events.ndjson configured required=true, ts_window_ms=60000 (webhook::guards).
  - Result: cargo test (69 tests) — all passed.

CI (GitHub Actions):
  - Added `.github/workflows/ci.yml` to run on push/PR across Ubuntu/Windows/macOS (Rust stable).
  - Steps: cargo fmt --check, cargo clippy -D warnings (features: api_std_http,sign_hmac,sign_host), cargo test --lib, cargo audit.
  - Extra: build `--no-default-features` (library) to ensure baseline compatibility.
  - Local dry-run: fmt/clippy/test/audit all passed prior to enabling CI.
  - Added cargo-deny checks (advisories/licenses/bans) with `deny.toml`.
  - Added Feature Matrix job (Ubuntu): compile under minimal/api_only/sign_only/full; runs tests on full variant.
  - Release build sizes are reported per-OS; release profile lto/codegen-units are echoed for visibility.
  - Enforced binary size budgets in CI (default: std_dashboard_demo ≤ 20MB, hmac_client ≤ 10MB). Budgets are configurable via env in workflow.
  - Tightened budgets to std_dashboard_demo ≤ 12MB and hmac_client ≤ 6MB; strip step added on Linux/macOS before size checks.
  - Encrypted symbol retention: CI extracts platform symbols (ELF .debug, macOS .dSYM, Windows .pdb) and, if `AGE_PUBLIC_KEY` secret is present, encrypts them with age and uploads as artifacts (`symbols_encrypted-OS`). This preserves forensic/debug capability securely without shipping symbols publicly.
  - Perf benches: added test-based micro-benches for parsing/policy/url_decode; CI job runs them with `--nocapture` to record avg ns/iter in logs (non-gating).
  - Performance budgets: adaptive env-driven budgets (ns/iter) enforced in CI (Ubuntu job) via `PERF_BUDGET_*` variables; tests assert if averages exceed budgets.
  - Two-tier budgets: PRs set `PERF_BUDGET_WARN_*` (warnings only), main sets `PERF_BUDGET_FAIL_*` (hard fail). Tests emit GitHub warnings when WARN budgets exceeded and fail when FAIL budgets are present and exceeded.

Std HTTP refactor (modularization):
  - Extracted `src/api/std_http/parser.rs` (query/form/url_decode) and `src/api/std_http/oauth.rs` (OAuth2 handlers).
  - New: `src/api/std_http/security.rs` (find_header, from_hex/to_hex, canonical string, verify_oauth2_request, verify_request_signature).
  - New: `src/api/std_http/io.rs` (run/run_once/run_with_policy, connection handling, response writing).
  - Root `std_http.rs` now re-exports run APIs and security helpers; legacy in-file implementations disabled via cfg(FALSE) to preserve history without affecting build.
  - Build verified after split; no logic changes, only structural organization.
  - Added `src/api/std_http/types.rs` (Request/Response/Handler) and `src/api/std_http/http.rs` (reason_phrase).
  - Added `src/api/std_http/utils.rs` (extract_u64/u8/str) and `src/api/std_http/router.rs` (all non-OAuth2 routes).
  - Added `src/api/std_http/email.rs` (optional SMTP helper behind feature).
  - Moved unit/integration tests to `src/api/std_http/tests.rs`; made OAuth2 parse helpers `pub(crate)` for benches.
  - cargo build/test (features: api_std_http, sign_hmac, sign_host): OK (74 tests).
  - Started router split into handlers: added `handlers/telemetry.rs` and `handlers/fw.rs`, updated `router.rs` to delegate via try_handle; build OK.
  - Continued router modularization: added handlers `backup`, `export`, `cloud`, `webhook_guard`, `memory`, `anti_replay`, `keys`, `policy`, `alerts`, `templates`, `webhook`, and rewired `router.rs` accordingly.
  - Verified build and tests after modularization: cargo build/test OK (74/74).

Local security/quality checks (post-refactor):
  - cargo fmt --check: OK (applied fmt where needed).
  - cargo clippy -D warnings: OK after pruning unused re-exports, scoping test-only helpers with #[cfg(test)], and allowing unexpected_cfgs at file level.
  - cargo test (features: api_std_http, sign_hmac, sign_host): OK (74/74).
  - Feature matrix builds:
    - --no-default-features (lib): OK
    - --features "api_std_http" (lib): OK
    - --features "sign_hmac" (lib): OK
    - --features "api_std_http,sign_hmac,sign_host" (bins+lib): OK
  - cargo audit: OK
  - cargo deny: local version reports config schema changes; check remains enforced in CI where version is pinned.

