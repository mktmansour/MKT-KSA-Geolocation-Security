# GitHub Advanced Scan Report - 2026-03-15

## Scope
Advanced GitHub-level verification for CI health and repository security surfaces.

## GitHub Checks Executed
1. GitHub CLI authentication and repository connectivity.
2. Actions workflow status history (recent runs).
3. Code Scanning alerts API.
4. Dependabot alerts API.
5. Secret Scanning alerts API.

## Results
- `gh auth status`: authenticated as `mktmansour` using stored GitHub CLI credentials.
- Repository visibility and default branch confirmed (`PUBLIC`, `main`).
- Workflow hardening applied:
	- Added explicit job-level `permissions` in `rust.yml` and `release-binaries.yml`.
	- Added dedicated `CodeQL` workflow constrained to repository-relevant scope.
- Code Scanning API now returns `NONE` for open alerts.
- Previously open legacy C/C++ alerts (`#3`..`#8`) were dismissed as `false positive` with recorded rationale because they originated from dependency cache paths (`.cargo-home`) rather than first-party source.
- Newly detected alerts from strict gates were remediated:
	- `dockerfile.security.missing-user.missing-user` fixed by enforcing non-root execution in `Dockerfile`.
	- `CVE-2026-25537` fixed by upgrading `jsonwebtoken` to `10.3.0` with explicit `rust_crypto` provider.
- Dependabot alerts API is accessible and returns `NONE` (no open alerts).
- Secret Scanning is enabled and Push Protection is enabled.
- Secret Scanning alerts API returns `NONE` for open alerts.

## Security Interpretation
- Code Scanning and Dependabot are currently clean at open-alert level.
- CI quality still depends on keeping `Clippy` passing on each push.
- Secret leak detection is active at GitHub level through Secret Scanning and Push Protection.

## Recommended GitHub Actions
1. Keep strict workflow permissions (`contents: read` minimum, add only required scopes per job).
2. Keep CodeQL scope focused on first-party repository code to avoid dependency-cache noise.
3. Keep Security Gates (`Semgrep`, `Gitleaks`, `Trivy`) as required checks before merge.
4. Enforce PR-only merges and signed commits for protected branches.

## Local Compensating Controls Executed
- `cargo audit --deny warnings`
- `cargo clippy --all-targets --all-features -- -D warnings`
- Full integration tests including strict API security surface checks and burst rate-limit behavior.

## Conclusion
The project passes strict local security and integration gates, with zero open alerts across Code Scanning, Dependabot, and Secret Scanning at report time. The primary remaining discipline is to keep required checks enforced for every merge.
