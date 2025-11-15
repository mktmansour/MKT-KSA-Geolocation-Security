******************************************************************************************
   خطة الاختبار (ثنائية اللغة) – MKT KSA Geolocation Security
******************************************************************************************

Arabic (AR):
الغرض: خطة اختبار عملية قابلة للتكرار لضمان أن النواة السيادية بلا تبعيات تعمل بأمان وكفاءة، مع تغطية الوحدات، التكامل، شبه‑Fuzz، التحميل الخفيف، الأمن، وواجهة C.

English (EN):
Purpose: A practical, repeatable test plan ensuring the sovereign zero‑deps core works safely and efficiently, covering unit, integration, fuzz‑like, light‑load, security, and C‑ABI.

------------------------------------------------------------------------------------------
1) النطاق / Scope
- AR: النواة (Core)، التفتيش، بصمة السلامة، خادم HTTP الداخلي، حارس الإخراج، التليمترية، ضغط RLE، الويب هوك، وواجهة C.
- EN: Core, inspection, integrity fingerprint, std HTTP server, egress guard, telemetry, RLE, webhooks, and C‑ABI.

------------------------------------------------------------------------------------------
2) مصفوفة الميزات / Feature Matrix
- EN/AR: اختبر بمجموعات ميزات تمثل المسارات الإنتاجية:
  - Base: no features
  - API: api_std_http
  - Egress: egress + egress_http_std
  - Compression: compress_rle
  - SMTP (optional demo): smtp_std
  - FFI header only: ffi_c (header generation)

Example commands:
```bash
cargo fmt --all --check
cargo clippy --no-default-features -- -D warnings
cargo clippy --no-default-features --features "api_std_http,egress,egress_http_std,compress_rle,smtp_std" -- -D warnings
cargo test --no-default-features --lib
cargo test --no-default-features --features "api_std_http,egress,egress_http_std,compress_rle" --tests
cargo doc --no-default-features --no-deps

# C header generation (FFI surface only)
cbindgen --crate MKT_KSA_Geolocation_Security --config cbindgen.toml --output include/mkt_ksa_geo_sec.h

# Miri (nightly)
cargo +nightly miri setup
cargo +nightly miri test --no-default-features --lib
```

------------------------------------------------------------------------------------------
3) اختبارات الوحدات / Unit Tests
- AR: تغطي التفتيش، ثبات البصمة، ضغط/فك ضغط RLE، سياسات الإخراج الأساسية.
- EN: Cover inspection, fingerprint stability, RLE round‑trip, basic egress policy checks.
Acceptance: 100% تمر بلا تحذيرات.

------------------------------------------------------------------------------------------
4) اختبارات التكامل / Integration Tests
- AR: تشغيل خادم HTTP الداخلي (run_once) والتحقق من /metrics و/backup و/alerts.
- EN: Single‑shot server, validate /metrics 200 OK and counters JSON keys exist.
Acceptance: 200 OK ووجود حقول counters المتوقعة.

------------------------------------------------------------------------------------------
5) اختبارات شبه‑Fuzz / Fuzz‑like
- AR: بايتات عشوائية تُمرر إلى التفتيش؛ تأكيد عدم وجود panic واحترام الحدود.
- EN: Random bytes to inspection; assert no panics, limits enforced.
Acceptance: لا ذعر، لا تجاوز حدود، نتائج متوافقة مع السياسات.

------------------------------------------------------------------------------------------
6) التحميل الخفيف / Light Load
- AR: محاكاة 100–1000 اتصال متتابع زمنياً بمهلة قصيرة.
- EN: Simulate 100–1000 sequential connections; ensure stable latency and no leaks.
Acceptance: ثبات زمن الاستجابة وعدم تسريب الموارد.

------------------------------------------------------------------------------------------
7) اختبارات الأمان / Security
- AR: XSS/UTF‑8/حدود حجم/Content‑Type allowlist/denylist للمسارات.
- EN: XSS, UTF‑8 validity, size limits, Content‑Type allowlist, denied path prefixes.
Acceptance: حجب غير المسموح وتسجيل السبب وبصمة.

------------------------------------------------------------------------------------------
8) حارس الإخراج / Egress Guard
- AR: رفض RFC1918/Link‑local/Unix sockets؛ تطبيق allow/deny‑list للمضيفين والمنافذ.
- EN: Reject RFC1918 & link‑local; enforce allow/deny lists and allowed ports.
Acceptance: preflight يفشل لغير المسموح ويمر عند السماح الصريح.

------------------------------------------------------------------------------------------
9) التكيّف حسب الخطر / Risk Adaptation
- AR: تغيير risk عبر /risk وملاحظة تقليص حدود Limits عند ارتفاعه.
- EN: Adjust risk; verify dynamic tightening of Limits at high risk.
Acceptance: تقليص نصف/ثلاثة أرباع الحدود حسب العتبات.

------------------------------------------------------------------------------------------
10) ضغط RLE / RLE
- AR/EN: تمكين compress_rle والتأكد من comp_in/comp_out counters مع Bodies > 512B.

------------------------------------------------------------------------------------------
11) مقارنة زمن ثابت / Constant‑time Compare
- AR/EN: استخدام utils::helpers::ct_eq للبصمات والتواقيع لمنع قنوات التوقيت.

------------------------------------------------------------------------------------------
12) واجهة C‑ABI / C Header
- AR/EN: توليد الترويسة وقصر التعرّض على ffi::* فقط؛ عدم وجود تحذيرات مؤثرة.

------------------------------------------------------------------------------------------
13) معايير القبول العامة / General Acceptance
- AR: لا تحذيرات بناء/Clippy، نجاح Miri للنواة، وثائق تُبنى، وترويسة C صحيحة.
- EN: Zero warnings build/Clippy; Miri passes on core; docs build; valid C header.

******************************************************************************************
