# Security Advisory Template (English)

Use this template when publishing a GitHub Security Advisory and preparing a crates.io security patch release.

## Summary

- Project: MKT_KSA_Geolocation_Security
- Advisory ID: GHSA-XXXX-XXXX-XXXX
- Severity: High
- Affected crate versions: <= 2.0.1
- Patched crate version: 2.0.2
- Ecosystem: Rust / crates.io

## Description

A security issue was identified in the package dependency chain and/or runtime behavior. This advisory documents the impact, affected versions, and required upgrade path.

## Impact

- Risk type: dependency vulnerability and/or security control bypass risk.
- Potential impact: reduced trust guarantees in production environments.
- Exploitability: depends on runtime context and integration pattern.

## Affected Versions

- Affected: <= 2.0.1
- Patched: 2.0.2

## Remediation

1. Upgrade to 2.0.2 immediately.
2. Re-run strict validation:
   - cargo fmt --all -- --check
   - cargo clippy --all-targets --all-features -- -D warnings
   - cargo test --all
   - cargo audit
3. Rotate any impacted secrets if operational exposure is suspected.

## Maintainer Security Statement

Maintainers must proactively update dependencies to reduce vulnerability exposure.

Minimum operational policy:

- Monitor advisories daily (Dependabot, RustSec, GitHub Security).
- Merge security dependency updates immediately after CI passes.
- Publish patch releases without delay when high/critical findings appear.

## crates.io Actions

1. Publish patched release (2.0.2).
2. Yank affected release only if required by risk level:
   - cargo yank --vers 2.0.1
3. Keep changelog and security documentation synchronized.

## Credits

- Reporter: <name or private>
- Maintainer contact: mkt-edge@outlook.sa
