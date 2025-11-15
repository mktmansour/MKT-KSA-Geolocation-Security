## Addons Guide (Zero‑Deps Core, Optional Integrations)

Arabic (العربية) — English (EN)

---

### 🎯 الهدف / Purpose
- Arabic: هذا الدليل يشرح كيفية تفعيل الميزات الاختيارية وربط محولات خارجية دون المساس بـ "صفر تبعية" في النواة.
- English: This guide explains how to enable optional features and connect external adapters while keeping the core zero‑dependency.

---

### ✅ مبدأ أساسي / Core Principle
- Arabic: البناء الافتراضي بدون أي تبعيات خارجية. كل تكامل خارجي يتم عبر `features` فقط وبتفعيل صريح.
- English: Default build links no external crates. Any integration is opt‑in via feature flags only.

---

### 🧩 ميزات داخلية اختيارية / Internal Optional Features (no external crates)
- `api_std_http`: خادم HTTP داخلي بسيط (std فقط) لواجهات المراقبة والويب هوك.
- `egress`: تمكين سياسات الخروج (حارس egress) دون عميل HTTP خارجي.
- `egress_http_std`: عميل HTTP/1.1 بسيط عبر `TcpStream` للاستخدام مع الحارس.
- `compress_rle`: ضغط/فك RLE داخلي للطلب/الاستجابة.
- `smtp_std`: إرسال بريد بسيط عبر SMTP/TCP بدون TLS (للتجارب/البيئات المغلقة).
- `core_utils`, `input_validation`: أدوات داخلية مساعدة.

Example build:
```bash
cargo build --no-default-features --features "api_std_http,egress,egress_http_std,compress_rle,smtp_std"
```

---

### 🔌 أسماء ميزات احتياطية للمحولات الخارجية / Placeholder feature names
هذه الميزات معرّفة كميزات فارغة لتجنّب تحذيرات `#[cfg]`، ويمكن ربطها لاحقًا عبر crate خارجي أو طبقة اختيارية:
- `api_actix`, `rt_tokio`: ربط إطار ويب خارجي (Actix/Tokio) عند الحاجة.
- `egress_reqwest`, `webhook_out`: استخدام `reqwest` لعميل HTTP متقدم.
- `db_mysql`: ربط قاعدة بيانات MySQL.
- `geo_maxminddb`: قاعدة بيانات MaxMind.
- `jwt`, `jws`: JSON Web Tokens/Signatures.
- `serde`, `validation`, `uuid_fmt`, `parallel`, `crypto_aesgcm`, `secure_secrecy`, `config_loader`.

أين نكتب التبعيات؟
- Arabic: لا تُضاف لأي تبعية في `Cargo.toml` للنواة. أنشئ crate/feature خارجي (addon) يعرّف هذه الميزات ويضيف التبعيات.
- English: Do not add deps to the core. Create a separate addon crate enabling the feature and specifying dependencies.

Template for an external addon crate:
```toml
[package]
name = "mkt-addon-egress-reqwest"
version = "0.1.0"
edition = "2021"

[dependencies]
reqwest = { version = "0.12", default-features = false, features = ["blocking"] }
mkt_ksa_geo_sec = { path = "..", default-features = false, features = ["egress_reqwest", "webhook_out"] }
```

---

### 🌐 Webhook In/Out
- Inbound (std): عبر `api_std_http`، المسار `/webhook/in` يستدعي `WebhookEndpoint` إن تم ضبطه.
- Outbound (std): عبر `egress + egress_http_std`، إرسال HTTP/1.1 بسيط مع حارس سياسات الخروج.
- Outbound (advanced): فعّل `webhook_out` في إضافة خارجية واستخدم عميلًا متقدمًا.

Setting a custom endpoint (Rust):
```rust
use std::sync::Arc;
use mkt_ksa_geo_sec::webhook::{FnWebhookEndpoint, WebhookEndpoint};
use mkt_ksa_geo_sec::api::std_http;

let ep = FnWebhookEndpoint::new(|json| { println!("{}", json); Ok(()) });
std_http::set_webhook_endpoint(Arc::new(ep));
```

---

### 🔐 التفتيش والبصمة / Inspection & Fingerprinting
- Arabic: كل طلب/استجابة تمر عبر `security::inspection` ويُولَّد `X-Integrity-Fingerprint` داخليًا.
- English: Every request/response is inspected and fingerprinted; responses include `X-Integrity-Fingerprint`.

---

### 🧪 نسخ احتياطي وتنبيهات / Backup & Alerts
Endpoints (std server):
- `GET /backup/download` — تنزيل NDJSON.
- `POST /backup/send?url=...&consent=TOKEN` — إرسال عبر HTTP (std) إن مُمكّن.
- `POST /backup/consent?token=TOKEN` — تعيين رمز موافقة.
- `POST /backup/schedule?interval=3600&risk=50&url=...&email=...` — جدولة دورية.
- `POST /backup/schedule/disable` — تعطيل الجدولة.
- `POST /backup/email?to=...` — إرسال عبر SMTP (إن مُمكّن).
- `POST /alerts/set?risk=80&cooldown=300&email=...&url=...` — إعداد تنبيهات مخاطرة.
- `POST /alerts/disable` — تعطيل التنبيهات.

Features required:
- HTTP paths: `api_std_http` (+ `egress`,`egress_http_std` للإرسال الخارجي).
- Email: `smtp_std`.

Security notes:
- Arabic: يجب تفعيل الموافقة قبل أي إرسال خارجي للنسخ الاحتياطي.
- English: Consent token is required before any backup egress.

---

### 🌍 اللغة والقوالب / Localization & Templates
- Arabic: اللغة الافتراضية تُكتشف من متغيرات البيئة (مثل `LANG`). يمكن ضبطها عبر `/templates/default?lang=ar|en`.
- English: Default language auto-detected; override via `/templates/default?lang=ar|en`.

---

### 🔧 بناء أمثلة / Build Examples
Zero-deps lib only:
```bash
cargo build --no-default-features --lib
```

Std dashboard server demo:
```bash
cargo run --no-default-features --features "api_std_http,egress,egress_http_std,compress_rle,smtp_std" --bin std_dashboard_demo
```

---

### 📦 سياسة التبعيات / Dependency Policy
- Arabic: لا تُضاف تبعيات إلى النواة. أي اعتماد خارجي يجب أن يكون عبر إضافة خارجية/ميزة اختيارية.
- English: No deps in core. External crates belong in addons only.

---

### 📝 ملاحظات أمنية / Security Notes
- Arabic: عميل/خادم HTTP المضمّن لأغراض داخلية واختبارية، لا يدعم TLS. استخدم بوابة عكسية آمنة أو محوّل خارجي عند الإنتاج.
- English: Built-in HTTP/SMTP are minimal and non‑TLS. For production, front with a secure proxy or use an external adapter.


