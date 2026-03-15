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
- `gh auth status`: authenticated as `mktmansour`.
- Repository visibility and default branch confirmed (`PUBLIC`, `main`).
- Recent workflows mostly green (`Rust`, `Clippy`, `rust-clippy analyze`) with latest runs successful.
- Code Scanning, Dependabot, and Secret Scanning APIs returned `403 Resource not accessible by integration` for the current token scope.

## Security Interpretation
- CI health signal is positive from recent completed successful workflows.
- Security-alert APIs are not readable with current integration token; this is a permissions limitation, not necessarily zero-alert proof.

## Recommended GitHub Permission Upgrade
Grant token scopes/repo permissions for:
- Code scanning alerts (read)
- Dependabot alerts (read)
- Secret scanning alerts (read)

After permission update, re-run:
- `gh api repos/<owner>/<repo>/code-scanning/alerts`
- `gh api repos/<owner>/<repo>/dependabot/alerts`
- `gh api repos/<owner>/<repo>/secret-scanning/alerts`

## Local Compensating Controls Executed
- `cargo audit --deny warnings`
- `cargo clippy --all-targets --all-features -- -D warnings`
- Full integration tests including strict API security surface checks and burst rate-limit behavior.

## Conclusion
The project passed strict local security and integration gates. GitHub advanced security APIs require elevated read permissions for complete remote alert visibility.
