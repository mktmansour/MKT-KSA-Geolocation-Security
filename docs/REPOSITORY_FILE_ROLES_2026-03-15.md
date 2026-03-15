# Repository File Roles (2026-03-15)

This document is the authoritative map for active top-level files and their purpose.

## Active Root Files

- `Cargo.toml`: package metadata, dependencies, feature flags.
- `Cargo.lock`: deterministic dependency lockfile for builds and CI.
- `rust-toolchain.toml`: pinned Rust toolchain policy.
- `Dockerfile`: secure containerized build/lint execution (non-root runtime user).
- `README.md`: primary English project documentation.
- `README_AR.md`: primary Arabic project documentation.
- `SECURITY.md`: security baseline, reporting process, and controls.
- `CHANGELOG.md`: release and hardening history.
- `CONTRIBUTING.md`: contribution workflow and expectations.
- `LICENSE`: repository licensing terms.
- `.env.example`: environment variable template (no secrets).
- `audit.toml`: cargo-audit configuration.
- `cbindgen.toml`: C header generation configuration.
- `GeoLite2-City-Test.mmdb`: MaxMind test fixture used by geolocation-related tests.

## Active Folders

- `.github/`: workflows, code scanning configuration, templates, and ownership policy.
- `src/`: application and library source code.
- `tests/`: integration and security-focused tests.
- `docs/`: active hardening and scan reports.
- `examples/`: usage examples.
- `scripts/`: CI helper scripts.

## Removed Legacy Files

The following files were removed because they contained outdated or conflicting project status:

- `AUDIT_REPORT.md`
- `EVALUATION.md`
- `docs/QA_Audit_Clippy_and_Dependencies.md`

They were replaced by current, scoped reports:

- `docs/SECURITY_HARDENING_2026-03-15.md`
- `docs/GITHUB_ADVANCED_SCAN_2026-03-15.md`
- `docs/REPOSITORY_FILE_ROLES_2026-03-15.md`
