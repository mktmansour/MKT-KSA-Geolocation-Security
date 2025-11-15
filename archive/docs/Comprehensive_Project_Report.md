******************************************************************************************
التقرير الشامل للمشروع (AR) – MKT KSA Geolocation Security
Comprehensive Project Report (EN)
******************************************************************************************

الغرض/Scope (AR): هذا التقرير يقدّم وصفًا معماريًا دقيقًا، جردًا لنقاط الـ API/Webhook، 
نموذج الأمان والضوابط، مسارات التشغيل، وخلاصة المراجعة الأمنية بعد إزالة لوحة التحكم نهائيًا.

Purpose (EN): This report provides an accurate architectural description, API/Webhook inventory, 
security model and controls, operational guidance, and the post‑removal audit outcome (dashboard UI fully removed).

---

1) ملخص تنفيذي / Executive Summary
- (AR) النواة السيادية بلا تبعيات افتراضيًا؛ الواجهة الآن API/Webhook فقط. لوحة التحكم (UI) حُذفت بالكامل؛ جميع مساراتها تُعيد 404. 
  نقاط الـ API الأساسية للعمل: قياسات/تليمترية، نسخ احتياطي وتنبيهات، حارس مانع إعادة، إدارة المفاتيح، سياسات التفتيش، وويب‑هوك داخلي.
- (EN) Zero‑deps core by default; interface is API/Webhook only. Dashboard UI removed; all its routes return 404. 
  Core API entry points remain: telemetry, backup/alerts, anti‑replay, key management, inspection policies, and inbound webhook.

النتيجة الأمنية / Security Outcome:
- (AR) لا تعرض لصفحات عامة؛ لا اعتماد على TLS داخليًا (مقصود). يُنصح بالتشغيل خلف Proxy آمن مع TLS. 
- (EN) No public UI exposure. Built‑in HTTP is non‑TLS by design; front with a secure reverse proxy for production.

---

2) نظرة معمارية / Architecture Overview
- (AR) طبقات رئيسية: security::{inspection, inspection_policy, fingerprint, egress_guard}, 
  telemetry (مخاطر/عدادات/أحداث/نسخ احتياطي/تنبيهات)، api/std_http (خادم HTTP صفري)، webhook (تعريفات الاستقبال/الإرسال)، utils (ct_eq, rle)، crypto/key_rotation.
- (EN) Primary layers: security, telemetry, std HTTP API, webhook traits, utilities, crypto key rotation. Zero external crates by default.

ميزات عبر Features:
- api_std_http، egress، egress_http_std، compress_rle، smtp_std، ffi_c (اختيارية). لا تُسحب تبعيات خارجية إلا عبر إضافات.

---

3) جرد نقاط API/Webhook / API & Webhook Inventory
(AR) جميع المسارات أدناه فعّالة؛ مسارات الـ UI السابقة تُعيد 404.
(EN) All routes below are active; former UI routes return 404.

- Webhook Inbound:
  - POST /webhook/in
  - Guards Management:
    - POST /webhook/guard/set?path=..&alg=..&key=..&ts=..&required=1|0&replay=1|0
    - POST /webhook/guard/disable?path=..
    - GET  /webhook/guard/list
    - GET  /webhook/guard/stats

- Telemetry & FW Controls:
  - GET  /metrics
  - GET  /events.ndjson
  - GET  /fw/metrics
  - POST /fw/open
  - POST /fw/close
  - GET  /toggle?compression=on|off

- Backup & Export:
  - GET  /backup/download
  - POST /backup/send?url=..&consent=TOKEN
  - POST /backup/consent?token=TOKEN
  - POST /backup/schedule?interval=..&risk=..&url=..&email=..
  - POST /backup/schedule/disable
  - POST /backup/email?to=.. (smtp_std)
  - GET  /export/csv?type=metrics|events

- Features Flags:
  - POST /features/enable?name=ai_insights|cloud|csv_export
  - POST /features/disable?name=ai_insights|cloud|csv_export

- Anti‑Replay Purge:
  - POST /anti_replay/purge/config?mode=..&sensitivity=..&window=..&capacity=..
  - POST /anti_replay/purge/disable
  - POST /anti_replay/purge/run
  - GET  /anti_replay/purge/status

- Key Management:
  - POST /keys/auto/config?threshold=..&interval=..&ids=a,b&len=..
  - POST /keys/auto/disable
  - POST /keys/create?id=..&ver=..&len=..&ts=..&fp=..
  - POST /keys/rotate?id=..&ver=..&len=..&ts=..
  - GET  /keys/meta?id=a,b
  - GET  /keys/export_hex?id=a,b&consent=TOKEN

- Policies & Risk:
  - GET  /policy/get
  - POST /policy/set      (JSON in body)
  - POST /policy/set_dsl  (DSL text in body)
  - POST /risk            (body: {"risk":42})

- Templates & Language:
  - POST /templates/set?lang=..&subject=..&body=..
  - POST /templates/default?lang=ar|en
  - POST /lang/set?lang=ar|en

- Cloud Push:
  - POST /cloud/push?url=.. (egress + egress_http_std)

ملاحظة OAuth (AR/EN): `/oauth/token` موجود ضمن الراوتر داخليًا؛ استخدامه اختياري حسب الحاجة.

---

4) نموذج الأمان والضوابط / Security Model & Controls
- تفتيش (Inspection): قيود طرق/مسارات، حجم رؤوس/جسم، UTF‑8، allowlist لمحتوى، بصمة سلامة.
- حُرّاس Webhook: HMAC‑SHA512، نافذة زمنية، Anti‑Replay، required/optional لكل مسار.
- تكيّف خطر (Risk Adaptation): شد/إرخاء الحدود حسب `current_risk`.
- حارس الإخراج (Egress Guard): فحوص RFC1918/Link‑Local/Unix sockets، allow/deny للمضيف/المنفذ.
- إدارة المفاتيح: إنشاء/تدوير/تصدير (Hex) بموافقة صريحة (consent) ونوافذ محدودة.

توصيات تقسية (Hardening) إضافية:
- فرض حارس توقيع حتى لمسارات القراءة العامة `/metrics`, `/events.ndjson`, `/fw/metrics` عند الإنتاج.
- تقليل نافذة الزمن للمسارات الحساسة (`/keys/*`, `/policy/*`, `/anti_replay/*`).
- تشغيل خلف Proxy مع TLS، وتفعيل معدل الطلبات ديناميكيًا لواجهات الإدارة الحساسة.

---

5) التشغيل والبناء / Operations & Build
أوامر أمثلة (بدون تبعيات خارجية):
```bash
cargo build --no-default-features --lib
cargo run --no-default-features --features "api_std_http" --bin std_dashboard_demo
```
ميزات إضافية عند الحاجة:
```bash
cargo run --no-default-features --features "api_std_http,egress,egress_http_std,compress_rle,smtp_std" --bin std_dashboard_demo
```

دمج Webhook Endpoint (Rust):
```rust
use std::sync::Arc;
use mkt_ksa_geo_sec::webhook::{WebhookEndpoint};
use mkt_ksa_geo_sec::api::std_http;

struct Ep;
impl WebhookEndpoint for Ep {
    fn receive(&self, json_payload: &str) -> Result<(), mkt_ksa_geo_sec::webhook::WebhookError> {
        // ... business logic ...
        Ok(())
    }
}
std_http::set_webhook_endpoint(Arc::new(Ep));
```

---

6) الاختبار والجودة / Testing & QA
- Clippy/Formatting: نظيف بلا تحذيرات على الملفات المعدّلة.
- Test Plan: موثّق في `docs/Test_Plan.md` (وحدات/تكامل/شبه‑Fuzz/تحميل خفيف/أمان/FFI).
- DoS/Load (ملف DoS_Results إن وجد): تشغيل محلي عبر `std_dashboard_demo` فقط.

---

7) إزالة لوحة التحكم / Dashboard Removal
- تم حذف `src/api/pages/*` و`src/api/dashboard_ui.rs` بالكامل.
- أي طلبات لمسارات UI السابقة تُعيد 404 (`ui_removed` أو `dashboard_removed`).
- تم تحديث التوثيقات (`Final_Engineering_Report.md`, `SBOM.md`, `OAuth2_Implementation_Report.md`) لتعكس ذلك.

---

8) نقاط تحقق نهائية / Final Audit Checklist
- [x] لا مراجع متبقية لـ UI في الراوتر.
- [x] جميع نقاط API المذكورة تعمل وغير متأثرة.
- [x] الوثائق محدثة ثنائيًا (AR/EN) وتُبيّن إزالة الـ UI.
- [x] لا تحذيرات لِنتر على الملفات المعدلة.
- [x] توصيات تقسية مُسجّلة للتشغيل الإنتاجي.

الخلاصة / Conclusion
- (AR) المشروع جاهز للتشغيل كـ مكتبة أمان تعتمد Webhook + API فقط، مع طبقات تفتيش/تليمترية/حراس متقدمة. إزالة الواجهة تقلّل سطح الهجوم وتحافظ على السيادة. 
- (EN) The project is production‑ready as a security library exposing Webhook + API only. Removing the UI reduces the attack surface and preserves sovereignty.

******************************************************************************************

