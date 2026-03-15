# Security Hardening Report - 2026-03-15

## Scope
This update applies strict security remediation across API authentication, routing integrity, database backend hardening, and memory footprint control.

## Errors Found
1. Hardcoded JWT secret repeated in multiple API handlers.
2. `smart_access` endpoint had no JWT protection.
3. `sensors` duplicated bearer extractor separately from central API extractor.
4. `alerts` and `weather` had dummy behavior instead of real runtime logic.
5. MySQL path was disabled but still the conceptual backend path in docs and architecture.
6. `auth` endpoint relied on unimplemented service path and returned unstable behavior.
7. In-memory growth controls were missing for runtime alert tracking.

## Fixes Implemented
1. Added centralized authorization helper in `src/api/mod.rs`:
   - Uniform bearer parsing.
   - Central JWT validation via shared `AppState.jwt_manager`.
   - Per-IP rate limiting via `AppState.rate_limiter`.
   - Token zeroization after decode to reduce memory exposure.
2. Enforced JWT + rate-limit checks on all endpoints including `smart_access`.
3. Removed local duplicate bearer extractor in `src/api/sensors.rs` and unified route auth path.
4. Replaced dummy endpoint logic:
   - `weather` now calls `WeatherEngine::fetch_and_validate`.
   - `alerts` now persists alerts to SQLite (when configured) and bounded in-memory store.
5. Replaced vulnerable/legacy DB posture:
   - Added hardened SQLite backend using `tokio-rusqlite`.
   - Added schema bootstrap in `src/db/crud.rs` (`users`, `devices`, `security_alerts`).
   - Enforced `DATABASE_URL` to accept only `sqlite://` in hardened runtime.
6. Reworked `auth` endpoint:
   - Uses centralized claims.
   - Requires subject match or `admin` role.
   - Fetches user from SQLite backend.
7. Added bounded alert memory store (`AlertMemoryStore`) to cap runtime memory growth.

## Security Outcomes
- No hardcoded JWT secret remains in API handlers.
- Unauthorized smart access path closed.
- Dummy routes removed from active API path.
- Full strict lint passes with all features.
- Test suite remains green.

## Validation Executed
- `cargo check --all-targets`
- `cargo clippy --all-targets -- -D warnings`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`
- `cargo audit --deny warnings`

## Notes
- This update is focused on strict hardening and route integrity.
- Further enhancement can include full migration of historical service writes to SQLite and endpoint-level integration tests for auth/rate-limit policy.
