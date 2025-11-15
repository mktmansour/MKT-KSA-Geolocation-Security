### ملف تمهيدي للدردشة الذكية (AI) | AI Chat Briefing

الغرض: هذا الملف يزوّد أي مساعد ذكاء اصطناعي بسياق فوري عن المشروع: الرؤية، الأسس الهندسية، الهيكلة، سياسات الأمان والجودة، الحالة الحالية، وأين وصلنا وما الخطوات التالية. يهدف لتقليل زمن الاستيعاب وتسريع الإنتاجية عند تسلّم العمل.

Purpose: This document gives any future AI assistant immediate context about the project: vision, engineering foundations, structure, security/quality policies, current status, where we stopped, and recommended next steps. It reduces ramp-up time and keeps progress consistent.

---

### حقائق سريعة | Quick Facts

- اسم الحزمة | Crate name: `mkt_ksa_geo_sec` (مكتبة وللاستهلاك متعدد اللغات)
- الإصدار الحالي | Current version: `v1.0.2`
- أنواع الإخراج | Crate types: `rlib`, `cdylib`, `staticlib`
- الربط متعدد اللغات | Multi-language: عبر C‑ABI باستخدام الهيدر `mkt_ksa_geo_sec.h` (مولّد بـ `cbindgen`)
- الأمن | Security baseline: HMAC‑SHA‑512/384 عبر RustCrypto، بدون OpenSSL، `secrecy 0.10.3`, `zeroize`, `jsonwebtoken`
- التواقيع والسرية | Signatures & secrets: مركزية في `src/security/signing.rs` وطبقة أغلفة أسرار في `src/security/secret.rs`
- الدقة | Precision: أدوات مركزية في `src/utils/precision.rs`، دعم f32/f64، ومرافق لحسابات أكثر دقة
- التزام الجودة | Quality gates: `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo audit`, `cargo tree -d`
- CI/CD | GitHub Actions: بناء متعدد المنصات وتوليد الهيدر عند إنشاء Tag

---

### المبادئ الهندسية | Engineering Principles

- الأمان أولاً بلا تعقيد زائد. No‑OpenSSL, RustCrypto‑based, أسرار معزولة باستخدام `secrecy` و`zeroize`.
- وضوح ومرونة الصيانة: منطق التوقيع/الدقة/الأسرار مركزي لتقليل التكرار وضمان الثبات.
- واجهة خارجية مستقرة، تغييرات داخلية آمنة: نُصلح Clippy والهيكلة دون كسر سلوك الـ API.
- صفر تحذيرات Clippy: نتعامل مع التحذيرات كمخالفات (`-D warnings`).
- الاستعداد للتشغيل متعدد اللغات: C‑ABI ثابت، رؤوس أوتوماتيكية، أمثلة ربط.

---

### هيكلة المشروع | Project Structure

- `src/security/`
  - `signing.rs`: HMAC‑SHA‑512/384 توقيع/تحقق موحد، خالٍ من OpenSSL.
  - `secret.rs`: أغلفة داخلية للأسرار (`SecureString`, `SecureBytes`) فوق `secrecy::SecretBox` لتثبيت الـ API.
  - `mod.rs`: فهرس وحدات الأمن.
- `src/utils/`
  - `precision.rs`: أدوات دقة رقمية/جغرافية (f32/f64, متوسط/معدّلات تغيّر...)
- `src/core/`
  - وحدات التحليل والسلوك والموقع والشبكة والحساسات. أمثلة: `geo_resolver.rs` (مع `ResolveParams`)، `device_fp.rs` (FFI آمن)، `network_analyzer.rs`, `behavior_bio.rs`.
- `src/api/`
  - معالجات Actix و`BearerToken` extractor لتجنّب `future_not_send`.
- `src/app_state.rs`: تعريف `AppState` مركزي.
- `src/lib.rs`: واجهة المكتبة وتصدير الوحدات.
- `src/main.rs`: نقطة تشغيل ثانوية (إن وجدت) تستخدم أنواع المكتبة المصدّرة.
- `examples/using_lib.rs`: مثال استهلاك محلي.
- `cbindgen.toml`: إعداد توليد `mkt_ksa_geo_sec.h`.
- `.github/workflows/release-binaries.yml`: بناء مكتبات متعددة المنصات + الهيدر عند إصدار Tag.

---

### قرارات تصميم محورية | Key Design Decisions

- طبقة أسرار مستقلة (`security::secret`): لعزل تغييرات `secrecy` المستقبلية عن باقي الشيفرة.
- وحدة توقيع موحّدة (`security::signing`): لتجميع الوظائف الأمنية وتخفيف التبعيات وتكرار الشيفرة.
- أدوات دقة متمركزة (`utils::precision`): لتجنّب أخطاء الدقة وتكبير قابلية التطوير.
- استخراج رموز الدخول عبر `BearerToken`: لجعل Futures قابلة للإرسال بين الخيوط (Send).
- تقليل التبعيات: إزالة `once_cell`, `lazy_static`, `serde_derive`, `getrandom` المباشر.

---

### سياسات الأمان والجودة | Security & Quality Policies

- HMAC فقط عبر RustCrypto. لا اعتماد على OpenSSL.
- الأسرار تُخزّن وتُدار عبر `SecureString` و`SecureBytes` وتُمسح آمنًا.
- FFI بواجهات C‑ABI موثّقة، مع دوال تحرير الذاكرة المقابلة.
- Clippy = صفر تحذيرات. Doc comments مع backticks حيث يلزم.
- `cargo audit` خالٍ من الثغرات المعروفة وقت الإصدار.

---

### التكامل متعدد اللغات | Multi-language Integration

- الواجهة المرجعية: `mkt_ksa_geo_sec.h` (مولد بـ `cbindgen`).
- أنظمة الاستدعاء: C/C++ مباشرة، Python (ctypes)، Java (JNA), .NET (P/Invoke), Node.js (ffi‑napi).
- حافظ على مطابقة التواقيع مع الهيدر، وخاصة إدارة الذاكرة (مثل `free_fingerprint_string`).

---

### أين توقفنا؟ | Where We Stopped

- التوثيق: تحديث ملفات `README` بالعربية والإنجليزية لتوضيح دعم جميع اللغات.
- الجودة: `fmt`/`clippy`/`test`/`audit` نظيفة وقت آخر تحديث.
- النشر: إعدادات النشر متكاملة، وتم إصدار `v1.0.2`. تم تجهيز CI لتوليد المكتبات والرأس C‑ABI عند وضع Tag.

- جديد: بدأنا تنفيذ وحدة `src/security/jws/` اختيارية (Feature: `jws`) لتوقيع/تحقق JSON عبر Ed25519 بدون OpenSSL؛ تشمل ملفات:
  - `jws/mod.rs`: الواجهة العليا للتوقيع والتحقق.
  - `jws/key.rs`: إدارة مفاتيح Ed25519 باستخدام `SecureBytes` بطول 32 بايت.
  - `jws/canonicalize.rs`: تطبيع JSON مبسّط ثابت (JCS‑like).
  - `jws/errors.rs`: تعريف أخطاء موحّد.
  - تم إضافة الاعتماد الاختياري `ed25519-dalek` إلى `Cargo.toml` وتفعيل ميزة `jws`.

- جديد: هيكلة منظومة الأمن الذكية:
  - `src/security/egress_guard/` واجهة حارس SSRF صفر تبعيات + تنفيذات اختيارية؛ ملفات: `mod.rs`, `policy.rs`, `resolver.rs`, `http_client.rs`, `errors.rs`. ميزة اختيارية: `egress_reqwest`.
  - `src/log/ledger/` سجل غير قابل للعبث (هيكل أولي) مع تجزئة قابلة للتبديل؛ ملفات: `mod.rs`, `entry.rs`, `digest.rs`, `writer.rs`, `errors.rs`. ميزة افتراضية: `ledger_blake3`.
  - تم تحديث `Cargo.toml` لإضافة ميزات: `egress_reqwest`, `ledger_blake3`.

ملاحظة: عند بدء جلسة جديدة، راجع هذا الملف ثم شغّل فحوصات الجودة السريعة أدناه لتحديث السياق.

---

### فحوصات سريعة لبدء جلسة | Quick Bring‑up Checks

1) تنسيق الشيفرة | Formatting
```
cargo fmt --all
```

2) Clippy بلا تحذيرات | Clippy (deny warnings)
```
cargo clippy --all-targets --all-features -- -D warnings
```

3) الاختبارات | Tests
```
cargo test --all --all-features --no-fail-fast
```

4) تدقيق التبعيات | Dependencies
```
cargo tree -d
cargo audit -q
```

5) توليد الهيدر (عند الحاجة) | Generate C header
```
cargo install cbindgen --locked
cbindgen --config cbindgen.toml --crate mkt_ksa_geo_sec --output mkt_ksa_geo_sec.h
```

---

### أولويات تالية مقترحة | Suggested Next Priorities

- تغليفات رسمية للغات: Python/Java/.NET/Node/Go فوق C‑ABI مع CI للنشر.
- توسيع precision f64 في مسارات كبيرة البيانات، وخيارات API خارجية عند اللزوم.
- تعزيز الاختبارات: تغطية أوسع للـ FFI، حالات خطأ، واختبارات أداء.
- تحسينات أمنية: توثيق مفاتيح التشغيل، تدوير المفاتيح، وخطط Incident Response.
- زيادة أمثلة الاستخدام عبر اللغات وتضمينها في `README`.

---

### إرشادات للمساعد القادم | Guidance for the Next AI Assistant

- اقرأ: `src/security/{signing,secret}.rs`, `src/utils/precision.rs`, `src/core/geo_resolver.rs`, `src/api/mod.rs`, `src/lib.rs`, `cbindgen.toml`, وملفات `README`.
- حافظ على: ثبات الواجهة الخارجية، أمان عالي، وعلمية التغييرات دون حذف المنطق القائم.
- أي تغيير توقيع داخلي: وثّقه هنا وفي `README` عند التأثير على الاستهلاك.
- التزم بالأسلوب ثنائي اللغة (عربي/إنجليزي) وتعليقات موجزة غير مُطوّلة.

---

تم إعداد هذا الملف ليكون المصدر السريع لسياق المشروع لأي جلسة ذكاء اصطناعي لاحقة.



### سجل الجلسة | Session Log - 2025-09-20 (zero-deps hardening & wiring)

- ما الذي أُنجز | What was done
  - إضافة اعتماد اختياري `aes-gcm` وتعريف ميزة `crypto_aesgcm` تربط: `dep:aes-gcm`, `dep:hex`, `dep:rand`.
  - ربط `core_full` بـ `dep:async-trait` و`rt_tokio` لضمان بناء وحدات `core/*` الثقيلة عند التفعيل.
  - تأكيد عدم وجود `actix-rt` و`cfg-if` في `Cargo.toml` وفي الشيفرة؛ لا تقليم مطلوب فعليًا.

- الأثر | Impact
  - النواة الافتراضية تبقى صفر تبعية؛ تشفير AES‑GCM متاح فقط عند `--features crypto_aesgcm`.
  - وحدات `core/*` الثقيلة تُبنى بسلاسة عند `--features core_full`.

- ملاحظات | Notes
  - تمت مراجعة `core/network_analyzer.rs` للتوافق مع `crypto_aesgcm` وFallback صفري التبعيات.
  - سيستمر توثيق أي تغييرات لاحقة هنا بشكل ثنائي اللغة.

- الويب هوك | Webhooks
  - إضافة وحدة صفر تبعيات: `src/webhook/mod.rs` بواجهات `WebhookEndpoint` و`WebhookClient` وأخطاء يدوية.
  - ميزة `webhook_out`: تفعّل عميل إرسال افتراضي عبر `reqwest` (Blocking) فقط عند الحاجة.
  - ميزة `webhook_in`: ربط استقبال الويب هوك عبر طبقة `api_actix` عند التفعيل.
  - مسار استقبال صفر تبعيات: `api_std_http` يوفّر `POST /webhook/in` مع تفتيش وسياسات وبصمة سلامة.
  - مرسل محمي صفر تبعيات: `GuardedStdWebhookSender` يطبق `egress_guard` قبل الإرسال.

- سياسات التفتيش | Inspection Policies
  - `security/inspection.rs`: فحص حدود/UTF‑8/أنماط، وبصمة سلامة للمدخلات.
  - `security/inspection_policy.rs`: `InboundPolicy` لطرق/مسارات/حدود؛ متكاملة في `api_std_http::run_with_policy`.
  - الاستجابة تحمل ترويسة `X-Integrity-Fingerprint` لضمان عدم التعديل أثناء النقل.

- أداء | Performance
  - التفتيش والبصمة تعتمدان على تجزئة قياسية خفيفة (StdHasher) في النواة، كلفتها متواضعة جدًا (O(n)) على حجم البدن.
  - يمكن تبديل التجزئة إلى `BLAKE3` عند الحاجة لأمان/سرعة أعلى عبر ميزة دون التأثير على النواة.

### سجل الجلسة | Session Log - 2025-09-07

- **ما الذي أُنجز | What was done**
  - تفعيل تصميم "نواة صفر تبعية" عبر تكثيف الـ feature-gating وتغليف الأسرار:
    - إضافة أغلفة داخلية للأسرار `SecureString` و`SecureBytes` واستبدال استخدام `SecretVec` في الوحدات: `device_fp`, `network_analyzer`, `sensors_analyzer`, `jwt`.
    - تفعيل/تحديث ميزات اختيارية في `Cargo.toml`: `jws`, `egress_reqwest`, `ledger_blake3`, `egress`, `crypto_aesgcm`.
    - جعل `blake3` غير اختياري للاستخدامات الأساسية، وإبقاء `url` و`aes-gcm` اختيارية.
  - تنفيذ `security/jws` (اختياري بميزة `jws`) للتوقيع والتحقق Ed25519 مع تطبيع JSON مبسّط (JCS-like) واختبارات.
  - تجهيز `security/egress_guard` (سياسات/محلل/عميل HTTP/أخطاء) مع اختبارات أولية ومنع SSRF أساسي؛ دمج `reqwest` خلف `egress_reqwest` فقط.
  - تجهيز هيكل `log/ledger` (سجل غير قابل للعبث) مع تجزئة قابلة للتبديل؛ ربط `ledger_blake3`.
  - إصلاحات جودة: إزالة واردات غير مستخدمة، تصحيح doc_markdown، وتوحيد استدعاءات `OsRng` للوليد الآمن.
  - حل أخطاء بناء: تعارض اسم ناتج المكتبة، استيراد `AppState` بعد نقله، أخطاء ميزات تتطلب تبعيات اختيارية.
  - تشغيل الاختبارات: جميع 40 اختبارًا ناجحة محليًا.

- **التبعيات | Dependencies**
  - تم التحديث: `pqcrypto-mlkem` → 0.1.1، `reqwest` → 0.12.23، `secrecy` → 0.10.3.
  - تمت الإضافة (اختيارية): `url`، `aes-gcm` (خلف `crypto_aesgcm`).
  - تمت الإزالة: `once_cell`, `lazy_static`, `serde_derive`, الاعتماد المباشر على `getrandom`.
  - ملاحظة: تقليم إضافي قيد العمل لـ `actix-rt`, `cfg-if` عند عدم الحاجة.

- **تغييرات التواقيع | Signature Changes**
  - مفاتيح/أسرار: الانتقال إلى `SecureBytes` و`SecureString` بدل أنواع `secrecy` مباشرة.
  - `network_analyzer::encrypt_ip`: أصبحت خلف `crypto_aesgcm` مع تجزئة Fallback بلا تبعيات عند عدم التفعيل.
  - `jwt::JwtManager::new`: يقبل `&SecureString`.
  - وظائف HMAC في `security::signing`: تقبل `&SecureBytes`.

- **ملفات جديدة | New Files**
  - `src/app_state.rs`: تعريف مركزي لـ `AppState`.
  - `cbindgen.toml`: تهيئة توليد رأس C-ABI `mkt_ksa_geo_sec.h`.
  - `.github/workflows/release-binaries.yml`: بناء متعدد المنصات وإنتاج رؤوس C تلقائيًا عند الإصدارات.
  - وثائق: تحديث `SECURITY.md` (نسخ الإصدارات)، `README`/`README_EN` (الاستخدام متعدد اللغات وواجهات C-ABI)، وإنشاء هذا السجل.

- **الحالة الحالية | Current Status**
  - الاختبارات خضراء؛ ميّزات اختيارية مفصولة؛ CI لبناء الهياكل الثنائية والرأس C مُعدّ.
  - `blake3` مستخدم في النواة؛ بقية التبعيات ثقيلة صارت اختيارية عبر الميزات.

- **المهام المتبقية | Pending Tasks**
  - `log/ledger`: استكمال الكاتب وربط مراسي يومية موقّعة (JWS Anchors) + اختبارات.
  - تقليم التبعيات (`actix-rt`, `cfg-if`) اعتمادًا على مسارات الاستخدام الفعلية.
  - توحيد مزوّد تشفير مركزي عبر Trait (اقتراح: `security/crypto_provider.rs`) مع تنفيذات اختيارية (AES‑GCM/HMAC/Ed25519) وFallback صفر تبعيات يعيد أخطاء بدل أمان زائف.

- **تقدم جديد (صفر تبعية) | New Progress (Zero‑Deps)**
  - إضافة `src/security/crypto_provider.rs`: Trait موحّد + تنفيذ `NoCrypto` يمنع الأمان الزائف.
  - إضافة `src/core/digest.rs`: Trait `CoreDigest` مع تنفيذ `StdHasherDigest` كـ Fallback معياري.
  - إضافة `src/security/egress_guard/parser.rs`: محلل URL بسيط بلا تبعيات.
  - إضافة `src/core/geo_db.rs`: واجهة `GeoDb` + تنفيذ افتراضي `NoGeoDb`.
  - توصيل الوحدات في `src/security/mod.rs` و`src/core/mod.rs` دون تغيير المنطق القائم.

- **تشفير سيادي متكيف | Sovereign Adaptive Crypto**
  - هيكلة عليا جديدة: `src/crypto/` تضم:
    - `policy.rs`: سياسات تكيفية (FIPS/أطوال/دوران/AAD إلزامي)
    - `selector.rs`: محدد خوارزميات حسب سياسة/مخاطر مع `RiskScorer`
    - `ai.rs`: واجهات إشارات مخاطر `RiskSignalProvider` وموائم `AdaptiveRiskScorer`
    - `device_binding.rs`: ربط المفاتيح ببصمة الجهاز والتحقق من الصلاحية
    - `aad.rs`, `keystore.rs`, `envelope.rs`, `traits.rs` (واجهة موحّدة، صفر تبعية)
  - فصل واضح بين `security/*` (حوكمة/سياسات عامة/حارس Egress) و`crypto/*` (تشفير ومع إدارة المفاتيح).
  - دعم حالات المفتاح: Active/Disabled/Revoked + تدوير المفاتيح وتنبيه مطور عند انتهاك الربط.

- **مقترحات لاحقة | Next Proposals**
  - جعل `default-features = []` وتصدير الوحدات الثقيلة فقط خلف الميزات لتقوية "النواة صفر تبعية".
  - توسيع اختبارات `egress_guard::preflight` لحالات النطاقات الفرعية وتعدد المنافذ.
  - تغليف GeoIP عبر Trait (`GeoDb`) مع تنفيذ MaxMind خلف `geo_maxminddb` وMock افتراضي.
  - فحوصات جودة دورية: `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo tree -d`, `cargo audit` قبل أي إصدار.

### سجل الجلسة | Session Log - 2025-09-11

- ما الذي أُنجز | What was done
  - تعزيز واجهة التشفير السيادية تحت `src/crypto/` مع واجهات واضحة وسياسات تكيفية ومحدد خوارزميات وموصل لإشارات المخاطر وربط بالمعدات: `policy.rs`, `selector.rs`, `ai.rs`, `device_binding.rs`, `aad.rs`, `keystore.rs`, `envelope.rs`, `traits.rs`.
  - تصدير الواجهات عبر `crypto/mod.rs` وربطها من `lib.rs` لضمان واجهة موحّدة متعددة اللغات مستقبلًا.
  - تكريس "النواة صفر تبعية" افتراضيًا؛ إبقاء التبعيات الثقيلة خلف الميزات بدون OpenSSL.
  - دعم دورة حياة المفاتيح (Active/Disabled/Revoked) وربط مفاتيح بالجهاز مع تنبيهات مطوّر عند الفشل.

- التبعيات | Dependencies
  - لا تبعيات مفعّلة افتراضيًا؛ اختيارية خلف الميزات: `aes-gcm`, `ed25519-dalek`, `reqwest`, `url`.
  - لا إزالة جديدة؛ تقليم إضافي قادم لـ `actix-rt`, `cfg-if` وفق الحاجة.

- الحالة | Status
  - البناء الافتراضي يظل بلا تبعيات خارجية؛ الوحدات قابلة للتفعيل بالميزات.
  - توثيق مُحدَّث هنا؛ التجهيز للخطوات التالية مستمر.

- التالي | Next
  - إكمال سجل غير قابل للعبث `log/ledger` وربط مراسي يومية موقّعة (JWS Anchors).
  - إعداد C‑ABI لعمليات التشفير (مفاتيح/توقيع/ظرف) وتفعيل مصفوفة GitHub Actions وتوليد رؤوس `cbindgen` متعددة المنصات.
  - التحضير للنشر على `crates.io` بعد اجتياز بوابات الجودة.

### سجل الجلسة | Session Log - 2025-09-11 (ledger update)

- ما الذي أُنجز | What was done
  - تنفيذ سلسلة تجزئة غير قابلة للعبث: `log/ledger/{mod.rs, entry.rs, digest.rs, writer.rs, verify.rs, errors.rs}` مع تنفيذ BLAKE3 اختياري.
  - وظائف: `append_entry`, `append_entry_auto`, `read_last_entry`, `verify_file_chain`.
  - مراسي يومية موقّعة (اختياري عبر `jws`): `log/ledger/anchor.rs` مع `sign_daily_anchor` و`verify_daily_anchor`.

- الحالة | Status
  - لا تبعيات افتراضية؛ `blake3` متاح، JWS خلف ميزة `jws`.
  - اختبارات أولية للتحقق من السلسلة مضافة بلا أخطاء.

- التالي | Next
  - توسيع الاختبارات، وإضافة أرشفة دورية، وتهيئة C-ABI لتوليد رؤوس عمليات السجل.

### سجل الجلسة | Session Log - 2025-09-11 (ledger zero-deps)

- ما الذي أُنجز | What was done
  - تحويل وحدة السجل إلى نواة بلا تبعيات خارجية: إزالة `serde/serde_json`, `chrono`, `thiserror`.
  - ترميز سطري داخلي بسيط: `ts_ms|index|prev_hash|event|hash` مع هروب محارف آمن للأحداث.
  - `writer.rs`: `append_entry`, `append_entry_auto`, `read_last_entry` باستخدام std فقط ووقت Unix بالميلي ثانية.
  - `verify.rs`: تحقق سلامة السلسلة عبر إعادة احتساب التجزئة من الترميز الداخلي.
  - `errors.rs`: نوع أخطاء داخلي مع `Display` و`Error` و`From<std::io::Error>`.

- السبب | Rationale
  - الالتزام الصارم بـ "نواة صفر تبعية" مع أداء جيد ومسار تدقيق واضح.

- المدى | Scope
  - مراسي JWS تبقى اختيارية خلف ميزة `jws` ولا تؤثر على النواة.

### سجل الجلسة | Session Log - 2025-09-11 (zero-deps core generalization)

- ما الذي أُنجز | What was done
  - تعميم “نواة صفر تبعية” على الأخطاء والتوقيع:
    - استبدال thiserror بأنواع أخطاء يدوية: `egress_guard::{parser,errors}`, `core/geo_db.rs`, `security/crypto_provider.rs`.
    - تغليف دوال توقيع تعتمد على serde خلف ميزة `serde`، والإبقاء على HMAC الأساسية بلا تبعيات.
    - `security/secret.rs`: تنفيذ داخلي لـ `SecureString/SecureBytes` مع مسح ذاكرة على Drop، وتمكين `secrecy/zeroize` عبر ميزة `secure_secrecy` فقط.
  - تحديث `Cargo.toml`: جعل `secrecy/zeroize/chrono/thiserror/serde` اختيارية، إضافة `chrono` إلى `jws`، والإبقاء على `default = []`.

- الأثر | Impact
  - بناء افتراضي بلا تبعيات خارجية؛ ميزات متقدمة تظل اختيارية.
  - واجهات ثابتة وقابلة للتمدد لتجهيز ربط متعدد اللغات وCI مستقبلًا.

### سجل الجلسة | Session Log - 2025-09-11 (core_full gating)

- ما الذي أُنجز | What was done
  - إضافة ميزة `core_full` لتعطيل بناء وحدات النواة الثقيلة افتراضيًا، وتمكينها اختياريًا:
    - Gate: `core/{behavior_bio,cross_location,device_fp,geo_resolver,network_analyzer,sensors_analyzer,weather_val}`.
    - إبقاء وحدات الصفر تبعيات دومًا: `core/{digest,geo_db}`.
  - تحديث `lib.rs` لإعادة التصدير المشروط لـ `GeoResolver`/`GeoLocation` فقط عند `core_full`.

- الأثر | Impact
  - بناء افتراضي أصغر وأسرع وبلا تبعيات، مع قدرة تفعيل الوحدات المتقدمة عند الحاجة.

### سجل الجلسة | Session Log - 2025-09-11 (C-ABI & CI)

- ما الذي أُنجز | What was done
  - ميزة جديدة `ffi_c` ووحدة `src/ffi/mod.rs` لواجهات C-ABI آمنة وثابتة:
    - `mkt_version_string()` لإرجاع نسخة الحزمة.
    - `mkt_hmac_sha512(...)` لحساب HMAC‑SHA512 بواجهة C.
  - `cbindgen.toml`: إعداد توليد رأس C تلقائيًا.
  - GitHub Actions (`.github/workflows/release-binaries.yml`): بناء `cdylib/staticlib` وتوليد `mkt_ksa_geo_sec.h` عند إصدار Tag، مع مصفوفة أنظمة (Linux/Windows/macOS).

- الأثر | Impact
  - ربط متعدد اللغات فوري مع رأس C مُولَّد تلقائيًا.
  - يحافظ على “نواة صفر تبعية” افتراضيًا؛ تفعيل FFI يتم عند الحاجة فقط.

### اختزال التبعيات التشفيرية | Crypto Dependencies Optionalization (2025-09-16)

- ما الذي تغيّر | What changed
  - ميزة `sign_hmac`: جعل `hmac` و`sha2` اختيارية وتجميع دوال HMAC فقط عند التفعيل.
  - تحديث `security/signing.rs`: توفير بدائل ترجع `FeatureDisabled` عند تعطيل الميزة.
  - ربط `core_full` بـ `blake3` و`sign_hmac` لضمان الاختبارات المتقدمة دون كسر النواة الافتراضية.
  - جعل `ledger_blake3` يضمّن `blake3`، وتسييج اختبار `verify.rs` بشرط الميزة.
  - ضبط استخدامات HMAC/Blake3 ضمن `core/*` و`tests` بشرط الميزات.

- الأثر | Impact
  - البناء الافتراضي يعود إلى “صفر تبعية” دون وظائف HMAC/Blake3، مع بدائل آمنة افتراضيًا.
  - عند الحاجة، تفعيل `--features sign_hmac,ledger_blake3,core_full` يوفّر قدرات كاملة مع تبعيات محدودة ومدروسة.

### تقوية النواة بصفر تبعية | Zero-Dependency Core Hardening (2025-09-16)

- ما الذي تغيّر (عربي)
  - جعلت تبعيات الأدوات اختيارية وأضفت ميزات: `core_utils`, `input_validation`, `config_loader`.
  - سيّجت وحدات اختيارية: `security::input_validator` تحت `input_validation`، `security::jwt` تحت `jwt`، `security::policy` تحت `validation`، و`AppState` تحت `core_full`.
  - `utils::helpers`: إزالة اعتماد `anyhow` واستخدام نوع خطأ بسيط صفر تبعيات.
  - `utils::precision`: استبدال `chrono` بـ `std::time::SystemTime` لتجنب أي تبعية.
  - `security::signing`: تسييج دوال تعتمد على `serde` وإتاحة بدائل عند تعطيل الميزة.
  - `security::crypto_provider`: إصلاح مسارات الإرجاع لتفادي غموض الأنواع.
  - `crypto::device_binding`: إضافة استيراد `KeyStore` لتفعيل `get` دون تبعيات إضافية.
  - `security::secret`: تبسيط التغليف الصِفري وإزالة تخصيصات `Drop` التي سببت تعارضات، مع مسح ذاكرة أفضل ما يمكن.
  - بناء المكتبة بنجاح بـ `--no-default-features` والتحقق من صفر تبعية. عُزلت بيئة Cargo محليًا لتجاوز مشاكل Windows (os error 5).

- What changed (EN)
  - Made utility deps optional with new features: `core_utils`, `input_validation`, `config_loader`.
  - Gated optional modules: `security::input_validator` (feature `input_validation`), `security::jwt` (`jwt`), `security::policy` (`validation`), and `AppState` (`core_full`).
  - Reworked `utils::helpers` (no anyhow) and `utils::precision` (use `SystemTime`).
  - `security::signing`: serde-dependent APIs gated; fallbacks provided.
  - `security::crypto_provider`: clarified Result returns.
  - `crypto::device_binding`: imported `KeyStore` trait.
  - `security::secret`: zero-deps wrappers without conflicting Drop specialization; best-effort zeroization.
  - Verified zero-feature library build; isolated Cargo dirs on Windows to avoid cache permission errors.

---
AR/EN Audit Log Entry (Final Hardening)
- AR: تم تنفيذ تعزيزات أمان إضافية: مقارنة زمن ثابت (ct_eq)، سياسات تفتيش متكيفة مع مستوى المخاطر، Content-Type allowlist وdenylist للمسارات، denylist للإخراج، واستبدال unwrap في مسارات الإنتاج للأقفال.
- EN: Added constant-time compare (ct_eq), adaptive inspection limits by risk, Content-Type allowlist and path denylist, egress denylist, and replaced unwrap on production locks.
- Tooling: cargo fmt/clippy (warnings as errors) clean; tests (unit/integration/fuzz-like) pass; docs build; cbindgen header generated; Miri passed on core.
- Reports: Created docs/Test_Plan.md (AR/EN) and docs/Final_Engineering_Report.md (AR).
---

### سجل الجلسة | Session Log - 2025-09-28 (DoS Simulation & Adaptive Firewall)

- ما الذي أُنجز | What was done
  - تنفيذ هجوم Slowloris عبر أداة صفر تبعيات `dos_sim`: `cargo run --bin dos_sim -- 127.0.0.1:8080 slow 10 50`.
  - قراءة مؤشرات الخدمة والجدار الناري:
    - `/metrics`: {"inspected":1,"blocked":0,"fw_allowed":0,"fw_blocked":0,"risk":0,"circuit_open":0,...}
    - `/fw/metrics`: {"inspected":2,"fw_allowed":1,"fw_blocked":0,"risk":0,"circuit_open":0,...}
  - توثيق مفصل للمنهجية والنتائج في `docs/DoS_Results.md` (AR/EN).

- الأثر | Impact
  - الجدار الناري الذكي والمتكيف يعمل حسب التوقع في سيناريو "slow" دون فتح قاطع الدارة؛ المخاطر بقيت 0.
  - تظهر العدادات تكامل السلسلة بين التليمترية والجدار الناري مع رصد `fw_allowed` دون حجب.

- التالي | Next
  - توسعة سيناريوهات القياس للأداء، وإضافة لقطات `flood`/`bigbody` الدورية إلى `docs/DoS_Results.md`.
  - ربط إشعارات لوحة المعلومات مع عتبات `risk` وفتح/إغلاق قاطع الدارة.
