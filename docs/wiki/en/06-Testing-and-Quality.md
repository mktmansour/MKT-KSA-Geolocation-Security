# 06. Testing and Quality

This page defines quality gates and verification strategy.

## 1. Quality Philosophy

- Deterministic build and lint checks.
- Integration-first validation for security-critical surfaces.
- Release-level confidence through repeatable gate execution.

## 2. Local Validation Pipeline

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## 3. Test Coverage Areas

- Authentication and authorization behavior.
- Rate-limit contracts and deny semantics.
- Request correlation propagation.
- Security-surface integration behavior.
- Database and migration flow behavior.

## 4. CI Coverage

Current CI posture includes:

- Rust build and formatting checks.
- Clippy quality enforcement.
- CodeQL analysis.
- Multi-language security gates.

## 5. Release Readiness Checklist

- All local quality commands pass.
- CI checks pass on main branch.
- Changelog updated with technical deltas.
- Readme and wiki updated for behavior changes.
- Dry-run publish verification completed for crate packaging.

## 6. Regression Strategy

- Add integration test for every security contract change.
- Preserve deterministic error-code behavior.
- Validate no accidental route exposure.
- Keep behavior parity between strict profile updates.

## 7. Next Step

Continue to [07. FAQ and Troubleshooting](07-FAQ-and-Troubleshooting.md).

## Search Keywords

Rust testing strategy, security integration tests, quality gates for crates, release readiness checklist.
