---
title: Module Contracts (API/Webhook-Only Architecture)
description: High-level contracts for major modules. Arabic/English bilingual.
updated: 2025-10-28
---

العربية / Arabic

الغرض: توثيق عقود الوحدات الرئيسية بشكل مختصر وواضح لضمان الفصل المنطقي والترابط المتكامل دون واجهة رسومية إنتاجية.

- مبدأ: المكتبة تعرض Webhook وواجهات API فقط. لا UI إنتاجي.
- الأمن: حراسة HMAC‑SHA512 + نافذة زمنية + Anti‑Replay لكل مسار.
- التشفير: ضمن مجلد مستقل عن security كما هو متطلب المستخدم.

English / الإنجليزية

Purpose: Concise contracts for the main modules to ensure clean separation of concerns and cohesive integration. No production UI; API/Webhook only.

- Principle: API & Webhook only. No production dashboard UI.
- Security: Per-path guards with HMAC‑SHA512, timestamp window, Anti‑Replay.
- Crypto: Lives in its own top-level folder separate from security as requested.

## Contracts Table / جدول العقود

| Module | Purpose (EN) | الغرض (AR) | Public Surface | Inputs | Outputs | Depends On | Notes |
|---|---|---|---|---|---|---|---|
| `api/std_http` | HTTP router + handlers for API/Webhook | موجه HTTP ومعالجات لمسارات API/Webhook | Stable JSON endpoints; health; webhook in/out; keys mgmt; telemetry | HTTP Request, headers, body | HTTP Response (JSON), status codes | Security, Telemetry, Crypto, Webhook, AppState | Feature `api_std_http`; IO boundary only; no heavy logic |
| `webhook` | Inbound/Outbound contracts | عقود الدخول/الخروج | Traits for endpoint/client | Messages, signatures | Delivery result | Security (verify), AppState | Retry/backoff via policy |
| `security` | Guards and policy | الحراسة والسياسات | Verify HMAC, timestamps, nonce | Headers/body, nonce, ts | Allow/Deny + reason | AppState (keys refs) | Stateless decisions where possible |
| `crypto` | Keys & rotation | إدارة المفاتيح والتدوير | Create/Rotate/Export/Import | Key ops requests | Key IDs/fingerprints | AppState storage | Separate from `security` folder |
| `telemetry` | Metrics/events/risk | القياسات/الأحداث/المخاطر | `/metrics`, `/events`, risk queries | Event structs | Aggregations/streams | AppState | Backpressure limits |
| `oauth` | OAuth2 client flows | تدفقات عميل OAuth2 | Token mgmt/introspection | OAuth endpoints | Tokens/claims | Security (optional) | Optional per deployment |
| `app_state` | Shared configuration | الحالة العامة للتطبيق | State getters/setters | Config/clock/stores | Shared refs | — | Injected into all handlers |
| `core` | Optional engines | محرّكات اختيارية | Internal APIs behind features | Domain data | Results | — (feature-gated) | Not required by default |

## Response Shape / شكل الاستجابة

- Success: `{ "ok": true, "data": ... }`
- Error: `{ "ok": false, "err": "code", "msg": "..." }`

## Security Envelope / غلاف الأمان

- Required headers: `x-ts`, `x-nonce`, `x-signature` (HMAC‑SHA512 over canonical payload)
- Time window: configurable; rejects skew/out-of-window
- Anti‑Replay: nonce store with retention window

## Versioning / إدارة الإصدارات

- Backward compatible JSON when possible
- Additive fields; never silently change semantics

## SLA & Limits / حدود الخدمة

- Rate limiting optional (per deployment)
- Payload size caps; structured errors

## Notes / ملاحظات

- Production UI removed entirely by design. All UI paths return 404.
- Crypto folder is separate from security per user policy.


