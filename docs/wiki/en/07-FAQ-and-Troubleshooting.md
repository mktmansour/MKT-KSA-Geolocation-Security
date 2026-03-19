# 07. FAQ and Troubleshooting

This page answers common operational and integration questions.

## 1. Why do I get unauthorized responses?

Check:

- API key value and header name.
- JWT token validity and signature source.
- Clock drift between token issuer and server.

## 2. Why do I get rate-limited quickly?

Check:

- Traffic profile and burst behavior.
- RATE_LIMIT_MAX_REQUESTS and related policy settings.
- Shared source IP behavior behind reverse proxy.

## 3. Why are requests blocked by risk controls?

Check:

- Payload patterns that match deny logic.
- Request body anomalies and suspicious markers.
- Endpoint sensitivity and profile strictness.

## 4. Why does startup fail in fresh environment?

Check:

- Missing API_KEY or JWT_SECRET.
- Invalid DATABASE_URL format.
- Missing write permission for SQLite path.
- Toolchain mismatch with lockfile expectations.

## 5. How do I prepare crate publishing safely?

Checklist:

- Validate Cargo include list.
- Run package listing and dry-run publish.
- Ensure test and operational extras are excluded from package payload.

## 6. Useful Commands

```bash
cargo check --locked
cargo test --all
cargo package --allow-dirty --list
cargo publish --dry-run --allow-dirty
```

## 7. Next Step

Continue to [08. SEO and Documentation Strategy](08-SEO-and-Documentation-Strategy.md).

## Search Keywords

Rust API troubleshooting, JWT auth errors, rate limit debugging, crate publishing checklist.
