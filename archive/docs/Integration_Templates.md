---
title: Integration Templates (API/Webhook Only)
description: Ready-to-use flow templates for integrating domains. Arabic/English bilingual.
updated: 2025-10-28
---

العربية / Arabic

الغرض: تقديم قوالب جاهزة لتكامل الأنظمة عبر API/Webhook بدون واجهة رسومية إنتاجية، مع ضمانات أمنية موحّدة.

English / الإنجليزية

Purpose: Provide ready-to-use templates for domain integration via API/Webhook (no production UI) with unified security guarantees.

## 1) Inbound Secure Webhook / Webhook داخلي آمن

Sequence:
1. Client → `POST /webhook/in` (headers: x-ts, x-nonce, x-signature; body: JSON)
2. `api/std_http` parses + normalizes
3. Security Guard: timestamp window, Anti‑Replay, HMAC‑SHA512
4. Route to domain handler (e.g., guards under `/webhook/guards/*`)
5. Telemetry: emit event + risk score
6. Respond: `{ "ok": true, "trace_id": "..." }`

Notes:
- Rejects on missing/invalid headers or replay.
- Domain handler must be deterministic and idempotent when possible.

## 2) Outbound Webhook with Egress Guard / Webhook خارجي بخروج آمن

Sequence:
1. Internal event triggers egress send
2. Apply egress policy (dest allowlist, rate caps)
3. Sign payload (HMAC‑SHA512) + add `x-ts`, `x-nonce`
4. Send; on failure → retry with backoff and bounded attempts
5. Telemetry: record delivery result

Notes:
- Use stable JSON schemas; avoid breaking changes.
- Keep nonces unique; avoid clock drift.

## 3) Key Rotation Flow / تدفق تدوير المفاتيح

Sequence:
1. Admin/API → `/keys/create` or `/keys/rotate`
2. `crypto` generates material + updates active key ID
3. Security guard uses latest key for verification
4. Telemetry emits `key_rotation` event
5. Expose `/keys/auto/config` and `/keys/auto/disable` if needed

Notes:
- Support manual and auto rotation (time/usage thresholds).
- Export/backup with explicit authorization.

## 4) OAuth2 (Optional) / اختيارية

Sequence:
1. Obtain token via configured provider
2. `api/std_http` → introspect/verify claims (if enabled)
3. Apply scopes/policies per path

Notes:
- Keep provider endpoints configurable.
- Cache token introspection cautiously.

## Request/Response Shape / شكل الطلب/الاستجابة

- Request headers: `x-ts`, `x-nonce`, `x-signature`
- Success: `{ "ok": true, "data": ... }`
- Error: `{ "ok": false, "err": "code", "msg": "..." }`

## Feature Flags / ميزات البناء

- `api_std_http`: enables the HTTP server for local/demo usage
- `core_*`: optional engines, off by default

## Operational Guides / إرشادات تشغيلية

- Rate limiting per deployment policy
- Telemetry backpressure and retention windows
- Anti‑Replay purge schedule


