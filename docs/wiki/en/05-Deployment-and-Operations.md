# 05. Deployment and Operations

This page covers production deployment patterns and day-2 operations.

## 1. Deployment Modes

- Native service deployment on Linux host.
- Container deployment using repository Dockerfile.
- Internal platform deployment with managed runtime controls.

## 2. Required Environment Baseline

- API_KEY
- JWT_SECRET
- DATABASE_URL

Recommended hardening controls:

- SECURITY_PROFILE
- HTTP_WORKERS
- HTTP_BACKLOG
- HTTP_MAX_CONNECTIONS
- HTTP_MAX_CONNECTION_RATE
- HTTP_KEEP_ALIVE_SECONDS
- HTTP_CLIENT_REQUEST_TIMEOUT_SECONDS
- HTTP_CLIENT_DISCONNECT_TIMEOUT_SECONDS
- HTTP_SHUTDOWN_TIMEOUT_SECONDS

## 3. Operational Run Command

```bash
API_KEY=change_me \
JWT_SECRET=replace_with_a_long_secret_32_chars_min \
DATABASE_URL=sqlite://data/app.db \
SECURITY_PROFILE=strict \
HTTP_MAX_CONNECTIONS=50000 \
HTTP_MAX_CONNECTION_RATE=1024 \
cargo run
```

## 4. Runbook Checklist

- Confirm migration readiness before startup.
- Confirm environment variables are injected from secure source.
- Confirm health and key endpoints after startup.
- Confirm logs include request correlation entries.
- Confirm alerts path behavior for deny events.

## 5. Monitoring Baseline

Track at minimum:

- Request rate and latency by endpoint.
- Deny rates by security code.
- Rate-limit activation frequency.
- Server saturation signals.
- Error trends grouped by route and profile.

## 6. Backup and Recovery Notes

- Snapshot SQLite data at controlled intervals.
- Keep migration history versioned and immutable.
- Validate restore procedure in staging before production use.

## 7. Next Step

Continue to [06. Testing and Quality](06-Testing-and-Quality.md).

## Search Keywords

Rust production deployment, secure runtime operations, Actix Web hardening, API observability and runbook.
