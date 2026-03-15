# MKT_KSA_Geolocation_Security

نظام تحقق جغرافي وأمني متقدم للإنتاج، مخصص لخدمات Rust ومنصات الوصول الذكي.

[![Rust](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml/badge.svg?branch=main&event=push)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml)
[![Clippy](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml/badge.svg?branch=main&event=push)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml)
[![Crates.io](https://img.shields.io/crates/v/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![Docs.rs](https://img.shields.io/docsrs/MKT_KSA_Geolocation_Security?style=for-the-badge)](https://docs.rs/MKT_KSA_Geolocation_Security)
[![Downloads](https://img.shields.io/crates/d/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)

![MKT KSA Geolocation Security Cover](docs/images/mkt_ksa.png)

## آخر التحديثات والتنبيه الاستراتيجي (2026-03-15)

- الإصدار المستهدف حاليًا هو **2.0.1** بسبب الإصلاحات الأمنية والهندسية.
- تم إكمال التقوية الأمنية والتنظيف المعماري على فرع `main`.
- مسار قاعدة البيانات التشغيلي أصبح SQLite محصنًا (`tokio-rusqlite`) مع ترحيلات (migrations).
- تم توحيد التحقق JWT وتحديد المعدل لجميع مسارات API بشكل مركزي.
- تم حذف وحدة Dashboard والوثائق القديمة المتضاربة لتقليل الانحراف الأمني/التوثيقي.
- تم اعتماد نهج نظافة مستودع صارم مع خريطة أدوار ملفات محدثة.

## سياسة الصيانة (مهم)

- هذا المستودع دخل وضع **صيانة أمنية فقط**.
- **لا يوجد تطوير ميزات جديدة** لهذا المشروع.
- التحديثات القادمة هنا ستكون فقط: إصلاحات أمنية وتصحيحات استقرار حرجة.
- يجري تطوير مشروع خليفة سيادي جديد وسيتم الإعلان عنه في 2026.
- المشروع الخليفة يُبنى من الصفر بالكامل مع **صفر تبعيات خارجية** وحزم سيادية داخلية.

### إعلان برنامج المشروع الخليفة

![إعلان MKT KSA Integrated Cyber Defense Platform](docs/images/2026mkt.png)

## ملاحظة مجتمعية

- تم تحميل الحزمة آلاف المرات.
- مستوى التفاعل (تعليقات/ردود/تقييمات) أقل بكثير من المتوقع.
- الملاحظات التقنية الأمنية من المستخدمين مرحب بها بشكل كبير.

## المحتويات

- 🧭 [1. وظيفة المشروع](#1-وظيفة-المشروع)
- 🎯 [1.1 هدف المشروع](#11-هدف-المشروع)
- ⭐ [1.2 مميزات المشروع](#12-مميزات-المشروع)
- 🏛️ [1.3 الجهات المستهدفة](#13-الجهات-المستهدفة)
- 🛡️ [2. الوضع التشغيلي والأمني](#2-الوضع-التشغيلي-والأمني)
- 🗂️ [3. خريطة أدوار المستودع كاملة](#3-خريطة-أدوار-المستودع-كاملة)
- 🔄 [4. الترابط وتدفق التحكم](#4-الترابط-وتدفق-التحكم)
- 🏗️ [4.1 مخطط هيكلة المشروع](#41-مخطط-هيكلة-المشروع)
- 🌐 [5. مرجع API وطرق الاستدعاء](#5-مرجع-api-وطرق-الاستدعاء)
- 🔐 [6. متغيرات البيئة](#6-متغيرات-البيئة)
- ✅ [7. البناء والتشغيل والتحقق](#7-البناء-والتشغيل-والتحقق)
- 🧱 [8. آخر الإصلاحات والتقويات](#8-آخر-الإصلاحات-والتقويات)
- 🔌 [9. الاستخدام كمكتبة و C-ABI](#9-الاستخدام-كمكتبة-و-c-abi)
- 📚 [10. تفاصيل مسؤوليات المجلدات والملفات](#10-تفاصيل-مسؤوليات-المجلدات-والملفات)

## 1. وظيفة المشروع

![Section 01 Banner](docs/images/banners/section-01.svg)

`MKT_KSA_Geolocation_Security` يجمع عدة إشارات ثقة ضمن قرار أمني موحّد:

- التحقق الجغرافي
- تحليل الشذوذ السلوكي
- تحليل بصمة الجهاز
- تحليل مخاطر الشبكة (Proxy/VPN)
- تحليل شذوذ بيانات الحساسات
- تدقيق اتساق الطقس مع السياق
- تحقق وصول ذكي مركب

طبقة API تعمل عبر Actix Web، بينما المحركات الأساسية قابلة لإعادة الاستخدام كمكتبة Rust.

### 1.1 هدف المشروع

- تقديم نواة أمان جغرافي صارمة بمستوى هندسي عالٍ للقطاعات السيادية والمؤسسية.
- تقليل مخاطر الاحتيال عبر دمج إشارات متعددة في قرار ثقة واحد قابل للتدقيق.
- الحفاظ على وضع أمني ثابت وقابل للمراجعة في بيئات الإنتاج.

### 1.2 مميزات المشروع

- تقييم ثقة متعدد الإشارات: الموقع، السلوك، الجهاز، الشبكة، الحساسات، الطقس.
- تحكم مركزي بالمصادقة: تحقق JWT مع تحديد معدل لكل IP.
- وضع تشغيل محصن: SQLite فقط مع إدارة المخطط عبر الترحيلات.
- إدارة أسرار آمنة وتوليد مفاتيح داخلية وقت التشغيل.
- نمط تكامل مزدوج: API وخيارات استخدام كمكتبة داخلية.

### 1.3 الجهات المستهدفة

- الجهات السيادية والحكومية.
- المؤسسات المالية وأنظمة المدفوعات الرقمية.
- مشغلو البنية التحتية الحرجة (الطاقة، النقل، المرافق).
- منصات الرعاية الصحية والهوية الحساسة.
- فرق هندسة الأمن التي تبني خدمات مدن ذكية مقاومة للاحتيال.

## 2. الوضع التشغيلي والأمني

![Section 02 Banner](docs/images/banners/section-02.svg)

- اللغة: Rust 2021
- إطار الويب: Actix Web
- runtime غير متزامن: Tokio
- قاعدة البيانات التشغيلية: SQLite فقط (`DATABASE_URL=sqlite://...`)
- JWT: فك/تحقق مركزي عبر `JwtManager`
- Rate Limiting: فحص مركزي لكل IP قبل تنفيذ منطق المسار
- أسرار المحركات الداخلية: تُولَّد عشوائيًا أثناء التشغيل (بدون أي مفاتيح ثابتة داخل الكود)
- إدارة الأسرار: `secrecy` + `zeroize`
- التوقيع: HMAC-SHA512/HMAC-SHA384
- ترحيلات القاعدة: SQL versioned في `src/db/migrations`

## 3. خريطة أدوار المستودع كاملة

![Section 03 Banner](docs/images/banners/section-03.svg)

### ملفات الجذر

| المسار | الدور |
|---|---|
| `Cargo.toml` | تعريف الحزمة والتبعيات والميزات وأنواع البناء |
| `Cargo.lock` | تثبيت نسخ التبعيات بشكل حتمي |
| `rust-toolchain.toml` | حوكمة نسخة Rust و MSRV |
| `README.md` | التوثيق الأساسي بالإنجليزية |
| `README_AR.md` | التوثيق الأساسي بالعربية |
| `SECURITY.md` | سياسة الإبلاغ الأمني |
| `CHANGELOG.md` | سجل الإصدارات والتعديلات |
| `CONTRIBUTING.md` | دليل المساهمة والمعايير |
| `Dockerfile` | بناء صورة التشغيل بالحاوية |
| `audit.toml` | إعدادات `cargo-audit` |
| `cbindgen.toml` | إعداد توليد رؤوس C-ABI |
| `.env.example` | نموذج متغيرات البيئة |
| `GeoLite2-City-Test.mmdb` | قاعدة بيانات GeoIP تجريبية للاختبارات |

### المجلدات

| المجلد | الدور |
|---|---|
| `.github/` | CI/CD و CodeQL وحوكمة المراجعات |
| `docs/` | تقارير التقوية الأمنية وحوكمة الملفات |
| `examples/` | أمثلة استخدام المكتبة |
| `scripts/` | سكربتات الصيانة و CI |
| `src/` | الكود الإنتاجي الرئيسي |
| `tests/` | اختبارات التكامل وسطح الأمان |
| `target/` | مخلفات بناء محلية (ليست مصدرًا) |

### تفصيل `src/`

| المسار | الوظيفة | الترابط |
|---|---|---|
| `src/main.rs` | تهيئة التطبيق وتشغيل الخادم | يبني `AppState` ويسجل المسارات |
| `src/lib.rs` | واجهة المكتبة وإعادة التصدير | يعرّض `api/core/db/security/utils` |
| `src/app_state.rs` | الحالة المشتركة وقت التشغيل | يتم حقنها داخل كل handlers |
| `src/api/mod.rs` | تسجيل المسارات + مصادقة مركزية | يستدعي الوحدات الفرعية |
| `src/api/*.rs` | handlers حسب المجال | تستخدم `authorize_request` ثم core/db |
| `src/core/*.rs` | المحركات والتحليل الدوميني | تُستهلك من API والاختبارات |
| `src/db/mod.rs` | ربط وحدات قاعدة البيانات | يعرّض models/crud/migrations |
| `src/db/models.rs` | نماذج البيانات | تُستخدم في CRUD وAPI |
| `src/db/crud.rs` | عمليات SQLite | تُستخدم في auth/alerts/bootstrapping |
| `src/db/migrations.rs` + SQL | إدارة نسخة المخطط | تُنفذ عند الإقلاع |
| `src/security/*.rs` | JWT, policy, ratelimit, validation, secrets/signing | مستخدمة عرضيًا عبر المشروع |
| `src/utils/*.rs` | أدوات مساعدة رياضية/كاش/تسجيل | دعم عام للمحركات |

## 4. الترابط وتدفق التحكم

![Section 04 Banner](docs/images/banners/section-04.svg)

1. `main.rs` يحمّل الإعدادات ويتحقق من القيم الأمنية الحرجة (`JWT_SECRET`, DB policy).
2. `main.rs` يهيّئ كل المحركات والخدمات ويبني `AppState`.
3. الطلب يصل إلى `/api/...` عبر المسارات المسجلة في `src/api/mod.rs`.
4. `authorize_request()` يفرض بالتسلسل:
   - وجود `Authorization: Bearer ...`
   - فحص معدل الطلبات
   - فك والتحقق من JWT
5. يتم تمرير الطلب للمحرك/القاعدة المناسبة.
6. تعاد الاستجابة JSON أو خطأ HTTP مناسب.

### 4.1 مخطط هيكلة المشروع

![مخطط هيكلة المشروع](docs/images/project-architecture.svg)

هذا المخطط يمثل البنية الفعلية للمستودع من طبقة الدخول وواجهات API حتى طبقات الأمان والمحركات الأساسية ووحدات البيانات والمساندة.

## 5. مرجع API وطرق الاستدعاء

![Section 05 Banner](docs/images/banners/section-05.svg)

Base URL: `http://127.0.0.1:8080`
جميع المسارات تحت `/api`.
كل المسارات تتطلب: `Authorization: Bearer <JWT>`.

### 5.1 جدول المسارات

| الطريقة | المسار | الملف | الوظيفة |
|---|---|---|---|
| `GET` | `/api/users/{id}` | `src/api/auth.rs` | جلب مستخدم بـ UUID (self/admin) |
| `POST` | `/api/geo/resolve` | `src/api/geo.rs` | تحقق جغرافي متقاطع |
| `POST` | `/api/device/resolve` | `src/api/device.rs` | تحليل بصمة الجهاز |
| `POST` | `/api/behavior/analyze` | `src/api/behavior.rs` | تحليل مخاطر السلوك |
| `POST` | `/api/sensors/analyze` | `src/api/sensors.rs` | تحليل شذوذ الحساسات |
| `POST` | `/api/network/analyze` | `src/api/network.rs` | تحليل الشبكة وكشف الإخفاء |
| `POST` | `/api/alerts/trigger` | `src/api/alerts.rs` | إنشاء وتخزين تنبيه أمني |
| `POST` | `/api/weather/summary` | `src/api/weather.rs` | ملخص تحقق الطقس |
| `POST` | `/api/smart_access/verify` | `src/api/smart_access.rs` | قرار وصول ذكي مركب |

### 5.2 أمثلة استدعاء

جلب مستخدم:

```bash
curl -X GET "http://127.0.0.1:8080/api/users/<uuid>" \
  -H "Authorization: Bearer <jwt>"
```

تحقق جغرافي:

```bash
curl -X POST "http://127.0.0.1:8080/api/geo/resolve" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address":"8.8.8.8",
    "gps_data":[24.7136,46.6753,8,1.0],
    "os_info":"ios",
    "device_details":"iphone-15",
    "environment_context":"mobile-4g",
    "behavior_input":{
      "user_id":"00000000-0000-0000-0000-000000000000",
      "event_type":"login",
      "ip_address":"8.8.8.8",
      "device_id":"device-1",
      "timestamp":"2026-03-15T00:00:00Z"
    }
  }'
```

تحليل الشبكة:

```bash
curl -X POST "http://127.0.0.1:8080/api/network/analyze" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.1.1.1","conn_type":"WiFi"}'
```

إطلاق تنبيه:

```bash
curl -X POST "http://127.0.0.1:8080/api/alerts/trigger" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id":"00000000-0000-0000-0000-000000000000",
    "entity_type":"user",
    "alert_type":"suspicious_login",
    "severity":"high",
    "details":{"ip":"8.8.8.8","reason":"impossible_travel"}
  }'
```

تحقق الوصول الذكي:

```bash
curl -X POST "http://127.0.0.1:8080/api/smart_access/verify" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "geo_input":["8.8.8.8",[24.7136,46.6753,8,1.0]],
    "behavior_input":{
      "user_id":"00000000-0000-0000-0000-000000000000",
      "event_type":"entry_attempt",
      "ip_address":"8.8.8.8",
      "device_id":"device-1",
      "timestamp":"2026-03-15T00:00:00Z"
    },
    "os_info":"ios",
    "device_details":"iphone-15",
    "env_context":"office-gate"
  }'
```

## 6. متغيرات البيئة

![Section 06 Banner](docs/images/banners/section-06.svg)

| المتغير | إلزامي | الوصف | مثال |
|---|---|---|---|
| `API_KEY` | نعم | مفتاح التطبيق في طبقة الإعداد | `API_KEY=change_me` |
| `JWT_SECRET` | نعم | سر JWT بطول 32+ | `JWT_SECRET=32+_chars_secret_here` |
| `DATABASE_URL` | موصى به | مسار SQLite؛ بدونه تعيد مسارات DB حالة 503 | `DATABASE_URL=sqlite://data/app.db` |
| `BOOTSTRAP_ADMIN_PASSWORD_HASH` | اختياري | عند ضبطه يتم إنشاء مستخدم bootstrap-admin عند الإقلاع بالهاش الممرر | `BOOTSTRAP_ADMIN_PASSWORD_HASH=<argon2_hash>` |
| `LOG_LEVEL` | اختياري | مستوى السجلات | `LOG_LEVEL=info` |
| `GEO_PROVIDER` | اختياري | اختيار مزود الموقع | `GEO_PROVIDER=ipapi` |

## 7. البناء والتشغيل والتحقق

![Section 07 Banner](docs/images/banners/section-07.svg)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

تشغيل:

```bash
API_KEY=change_me \
JWT_SECRET=replace_with_a_long_secret_32_chars_min \
DATABASE_URL=sqlite://data/app.db \
BOOTSTRAP_ADMIN_PASSWORD_HASH=replace_with_hash_if_needed \
cargo run
```

## 8. آخر الإصلاحات والتقويات

![Section 08 Banner](docs/images/banners/section-08.svg)

نطاق الإصلاحات والتطويرات في 2.0.1 يشمل بشكل كامل:

- التقوية الأمنية: اعتماد SQLite المحصن فقط مع فرض الترحيلات.
- التقوية الأمنية: توحيد التحقق JWT وتحديد المعدل لكل IP عبر مسار مصادقة مركزي.
- التقوية الأمنية: توليد أسرار المحركات داخليًا وقت التشغيل وإلغاء أي أسرار ثابتة داخل الكود.
- التقوية الأمنية: جعل seed لمستخدم bootstrap-admin اختياريًا فقط عبر `BOOTSTRAP_ADMIN_PASSWORD_HASH`.
- الإصلاحات التشغيلية: حذف وحدة Dashboard بالكامل من سطح API.
- الإصلاحات التشغيلية: استبدال السلوك الوهمي في بعض المسارات بمنطق فعلي مربوط بالمحركات/القاعدة.
- الإصلاحات التشغيلية: إضافة مخزن تنبيهات في الذاكرة بحد أعلى لمنع التضخم.
- الحوكمة ونظافة المستودع: إزالة التقارير القديمة غير المتوافقة مع الوضع الحالي.
- الحوكمة ونظافة المستودع: إضافة وثيقة مرجعية نهائية لأدوار الملفات.
- الحوكمة ونظافة المستودع: إعادة بناء التوثيقين الأساسيين (إنجليزي/عربي) بصياغة هندسية صارمة.
- تجربة التوثيق: إضافة بنرات رسومية لكل قسم مع كتابة اسم القسم داخل البنر.
- التحقق والجودة: نجاح فحوص `fmt` و`clippy -D warnings` و`test` على مسار هذا التحديث.

تم توثيق التحديثات الأمنية والهندسية الحديثة في:

- `docs/SECURITY_HARDENING_2026-03-15.md`
- `docs/GITHUB_ADVANCED_SCAN_2026-03-15.md`
- `docs/REPOSITORY_FILE_ROLES_2026-03-15.md`
- `CHANGELOG.md`

## 9. الاستخدام كمكتبة و C-ABI

![Section 09 Banner](docs/images/banners/section-09.svg)

أنواع التصدير المدعومة:

- `rlib` (استخدام Rust مباشر)
- `cdylib` (مكتبة ديناميكية متوافقة C)
- `staticlib` (مكتبة ثابتة متوافقة C)

وهذا يدعم التكامل المباشر مع Rust وكذلك الربط متعدد اللغات.

## 10. تفاصيل مسؤوليات المجلدات والملفات

### `.github/`

- `workflows/`: خطوط CI للتحقق (`rust`, `clippy`, `codeql`, `security-gates`, وإصدار النسخ).
- `actions/secure-workspace/action.yml`: خطوة مشتركة لتقوية بيئة العمل في CI.
- `codeql/codeql-config.yml`: ضبط نطاق فحص CodeQL.
- `CODEOWNERS`: ملكية المراجعة للمسارات الحساسة.
- `pull_request_template.md`: قائمة تحقق أمنية وجودة عند فتح PR.

### `docs/`

- `SECURITY_HARDENING_2026-03-15.md`: تقرير تنفيذ التقوية الأمنية.
- `GITHUB_ADVANCED_SCAN_2026-03-15.md`: ملخص الفحص المتقدم والمعالجات.
- `REPOSITORY_FILE_ROLES_2026-03-15.md`: المرجع الرسمي لأدوار الملفات الحالية.
- `images/cover-mkt-ksa.svg`: الصورة الرئيسية للتوثيق.
- `images/banners/section-01.svg` ... `section-09.svg`: بنرات مخصصة لكل قسم.

### `scripts/`

- `ci/cleanup_workspace.sh`: تنظيف منهجي لبيئة CI/المحلي من آثار الكاش والملفات المتبقية.

### `examples/`

- `using_lib.rs`: مثال عملي لاستخدام المكتبة ومحركاتها.

### `tests/`

- `api_integration_auth_rate_limit_db.rs`: اختبار تكاملي للمصادقة + تحديد المعدل + قاعدة البيانات.
- `api_security_surface_integration.rs`: اختبار سطح API الأمني وسلوك burst.
- `support/mod.rs`: أدوات مساعدة مشتركة للاختبارات.

### `src/api/`

- `mod.rs`: تسجيل المسارات وتوحيد مسار التفويض.
- `auth.rs`: جلب مستخدم مع فحص claims/roles.
- `geo.rs`: التحقق الجغرافي المتقاطع.
- `device.rs`: تحليل بصمة الجهاز.
- `behavior.rs`: التحليل السلوكي.
- `network.rs`: تحليل الثقة الشبكية وكشف الإخفاء.
- `sensors.rs`: تحليل شذوذ الحساسات.
- `alerts.rs`: إنشاء التنبيهات وتخزينها (ذاكرة + قاعدة بيانات).
- `weather.rs`: ملخص الطقس والتحقق.
- `smart_access.rs`: قرار الوصول الذكي المركب.

### `src/core/`

- `geo_resolver.rs`: تحليل/حل الموقع وتوقيع النتائج.
- `device_fp.rs`: توليد وتحليل بصمة الجهاز التكيفية.
- `behavior_bio.rs`: التحليل السلوكي وحساب المخاطر.
- `network_analyzer.rs`: كشف proxy/vpn ونمط الاتصال.
- `sensors_analyzer.rs`: كشف شذوذ قراءات الحساسات.
- `weather_val.rs`: مزودات الطقس والتحقق من الاتساق.
- `cross_location.rs`: منسق التحقق متعدد الإشارات.
- `composite_verification.rs`: محرك السياسات المركبة للوصول.
- `history.rs`: منطق التاريخ وكشف الشذوذ الزمني.
- `mod.rs`: تصدير وحدات النواة.

### `src/db/`

- `models.rs`: تعريف نماذج البيانات.
- `crud.rs`: عمليات SQLite غير المتزامنة.
- `migrations.rs`: تشغيل الترحيلات.
- `migrations/0001_initial.sql`: المخطط الأساسي.
- `migrations/0002_indexes.sql`: فهارس وتحسين الأداء.
- `mod.rs`: تصدير وحدات قاعدة البيانات.

### `src/security/`

- `jwt.rs`: إنشاء/تحقق الرموز وسياسات claims.
- `ratelimit.rs`: ضوابط الحد من المعدل لكل IP.
- `policy.rs`: محرك السياسات والصلاحيات والحالات.
- `input_validator.rs`: التطبيع والتنقية والتحقق من المدخلات.
- `secret.rs`: حاويات آمنة للقيم الحساسة.
- `signing.rs`: التوقيع والتحقق HMAC.
- `mod.rs`: تصدير وحدات الأمان.

### `src/utils/`

- `cache.rs`: أدوات التخزين المؤقت.
- `helpers.rs`: وظائف مساعدة عامة.
- `logger.rs`: مساعدات التسجيل.
- `precision.rs`: حسابات الدقة الرياضية/الزمنية.
- `mod.rs`: تصدير وحدات الأدوات.

### ملفات الجذر التشغيلية

- `Cargo.toml`: تعريف الحزمة وسياسة التبعيات والإصدار الحالي (`2.0.1`).
- `Cargo.lock`: تثبيت شجرة التبعيات.
- `README.md` و`README_AR.md`: المرجع الأساسي للتوثيق.
- `CHANGELOG.md`: سجل التعديلات حسب الإصدارات.
- `SECURITY.md`: سياسة الإبلاغ الأمني.
- `CONTRIBUTING.md`: معايير وإجراءات المساهمة.
- `Dockerfile`: وصف بيئة التشغيل بالحاوية.
- `audit.toml`: إعدادات تدقيق التبعيات.
- `cbindgen.toml`: إعدادات توليد واجهة C-ABI.
- `GeoLite2-City-Test.mmdb`: ملف اختبار جغرافي مستخدم في مسارات مرتبطة بالتحقق الجغرافي.

## الترخيص

Apache-2.0. راجع `LICENSE`.
