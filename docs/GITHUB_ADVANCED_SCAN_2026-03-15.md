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
- Recent workflow runs are mostly successful, with one recent `Clippy` workflow failure (`run id: 23102059602`, job: `clippy`).
- Code Scanning API is accessible and returns `8` open alerts:
	- `6` alerts with rule `cpp/weak-cryptographic-algorithm` (severity: `error`).
	- `2` alerts with rule `actions/missing-workflow-permissions` (severity: `warning`).
- Dependabot alerts API is accessible and returns `NONE` (no open alerts).
- Secret Scanning alerts API returns `404` because Secret Scanning is disabled for this repository.

## Security Interpretation
- CI health is generally good, but there is an unresolved recent `Clippy` failure that should be reviewed.
- Dependency vulnerability posture is currently clean at GitHub level (no open Dependabot alerts).
- The dominant open GitHub security risk is in Code Scanning alerts and should be triaged as priority.
- Secret leak detection at GitHub level is currently inactive because Secret Scanning is disabled.

## Recommended GitHub Actions
1. Triage and remediate Code Scanning alerts `#1` to `#8`.
2. Add explicit workflow permissions where needed to close `actions/missing-workflow-permissions` warnings.
3. Enable Secret Scanning in repository Security settings to activate leaked-secret detection.
4. Re-run failed `Clippy` workflow and enforce passing status on `main`.

## Local Compensating Controls Executed
- `cargo audit --deny warnings`
- `cargo clippy --all-targets --all-features -- -D warnings`
- Full integration tests including strict API security surface checks and burst rate-limit behavior.

## Conclusion
The project passes strict local security and integration gates, with clean Dependabot status. Remaining GitHub-side gaps are the open Code Scanning findings, one recent Clippy CI failure, and disabled Secret Scanning coverage.
