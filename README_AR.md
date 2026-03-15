# 🛡️🌍 MKT_KSA_Geolocation_Security
**مكتبة التحقق الجغرافي والأمني السعودي الذكية – MKT KSA 🇸🇦**
> 🔐 Rust | 🛰️ أمن ذكي | 🏙️ جاهزة للمدن الذكية | 📄 Apache 2.0 | تطوير: Mansour Bin Khalid (KSA 🇸🇦)

[![Rust](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml)      [![Clippy](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml/badge.svg)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml)
[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/mktmansour)

[![Crates.io](https://img.shields.io/crates/v/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![Docs.rs](https://img.shields.io/docsrs/MKT_KSA_Geolocation_Security?style=for-the-badge)](https://docs.rs/MKT_KSA_Geolocation_Security)
[![Downloads](https://img.shields.io/crates/d/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![License](https://img.shields.io/crates/l/MKT_KSA_Geolocation_Security?style=for-the-badge)](LICENSE)
![MSRV](https://img.shields.io/badge/MSRV-1.89%2B-informational?style=for-the-badge)
![Audit](https://img.shields.io/badge/audit-clean-success?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/maintenance-actively%20maintained-success?style=for-the-badge)
![Edition](https://img.shields.io/badge/edition-2021-blue?style=for-the-badge)

## 🔔 تنويه التحديثات (2026-03-14)

هذا الملف مخصص للشرح العربي، بينما تبقى أسماء الدوال والأنواع والـ API identifiers باللغة الإنجليزية كما هي في الكود.

**أبرز ما تم تحديثه:**
- اعتماد وضع أمني صارم: `cargo audit --deny warnings` ناجح.
- استبدال مسار MySQL القديم بقاعدة SQLite محصنة (`tokio-rusqlite`) في البروفايل التشغيلي الحالي.
- توحيد التحقق JWT وتحديد المعدل على مستوى مركزي عبر `AppState` لجميع المسارات.
- إزالة المسارات الوهمية وربط `weather` و`alerts` بمنطق فعلي (محرك/قاعدة بيانات).
- تنظيف المستودع من ملفات الكاش غير الضرورية وإيقاف تضمينها في التغليف.
- توحيد نتائج التحقق الحديثة: `fmt`, `clippy -D warnings`, `test` (39/39) كلها ناجحة.

---
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/ffe24b4e-fc3f-4203-8c4a-08633ae43488" />

## 📘 المحتويات

* [🗺️ نبذة عن المشروع](#-نبذة-عن-المشروع)
* [📂 الملفات الأساسية](#-الملفات-الأساسية)
* [🧩 الثوابت والدوال](#-الثوابت-والدوال-العامة)
* [🔷 الثوابت](#-الثوابت)
* [🔷 الدوال العامة والهياكل](#-الدوال-العامة-والهياكل)
* [🖊️ دوال التواقيع](#-دوال-التواقيع)
* [⏱️ دوال الدقة](#-دوال-الدقة)
* [🔷 الواجهات (Traits) الرئيسية](#-الواجهات-traits-الرئيسية)
* [🔑 المفاتيح ونقاط النهاية](#-نقاط-النهاية-api-والإعداد)
* [🧾 مفاتيح البيئة والإعداد](#-مفاتيح-البيئة-والإعداد-env--config)
* [🌐 نقاط النهاية (API Endpoints)](#-نقاط-النهاية-api-endpoints)
* [🧭 البنية المعمارية](#-البنية-المعمارية)
* [🛠️ أمثلة التحقق](#-أمثلة-التحقق-العملي)
* [⚙️ وحدات المحرك الأساسية](#-وحدات-المحرك-الأساسية)
* [🕓 وحدة السجل التاريخي](#-وحدة-السجل-التاريخي)
* [🔄 وحدة التحقق المتقاطع](#-وحدة-التحقق-المتقاطع)
* [📡 وحدة تحليل الحساسات](#-وحدة-تحليل-الحساسات)
* [☁️ وحدة الطقس والتحقق](#-وحدة-الطقس-والتحقق)
* [⚠️ تقرير التبعيات](#-تقرير-فحص-التبعيات)
* [✅ نتائج الاختبار](#-نتائج-الاختبار)
* [🔒 استقرار الإصدار الحالي](#-استقرار-الإصدار-الحالي)
* [⬆️ خطة ترقية التبعيات بالكامل](#-خطة-ترقية-التبعيات-بالكامل)
* [⭐ مزايا المشروع والفئات المستهدفة](#-مزايا-المشروع-والفئات-المستهدفة)
* [🧠 دليل المطور](#-دليل-المطور)
* [🔌 أعلام الميزات](#-أعلام-الميزات)
* [📦 استخدام المكتبة من Rust](#-استخدام-المكتبة-من-rust)
* [🔗 الربط عبر C-ABI للغات الأخرى](#-الربط-عبر-c-abi-للغات-الأخرى)
* [🌐 دعم جميع اللغات](#-دعم-جميع-اللغات)
* [📝 ملاحظات الإصدار](#-ملاحظات-الإصدار-v200)

---

## 🗺️ نبذة عن المشروع

**MKT\_KSA\_Geolocation\_Security**
مكتبة أمنية متقدمة للمدن الذكية، القطاعات السيادية، والشركات والمؤسسات التقنية.
تعتمد على التحقق الجغرافي، تحليل السلوك، بصمة الجهاز، الذكاء الاصطناعي، وبنية معيارية جاهزة للتخصيص والتوسيع – مع توثيق ثنائي اللغة لكل وحدة ووظيفة.

---

## 📂 الملفات الأساسية

| الملف المرجعي                 | الاسم التقني         | المسار المرجعي                    | المسار داخل المشروع               | الوصف                           | الوصف التفصيلي                                  |
| ---------------------------- | -------------------- | -------------------------------- | -------------------------------- | ----------------------------- | ---------------------------------------------- |
| main.rs                      | main.rs              | src/main.rs                      | src/main.rs                      | نقطة الدخول الرئيسية للتطبيق  | نقطة الدخول الرئيسية وتهيئة الخادم والوحدات |
| db/models.rs                 | models.rs            | src/db/models.rs                 | src/db/models.rs                 | هياكل بيانات قاعدة البيانات   | نماذج قاعدة البيانات                                      |
| db/crud.rs                   | crud.rs              | src/db/crud.rs                   | src/db/crud.rs                   | دوال قاعدة البيانات (CRUD)    | دوال CRUD لقاعدة البيانات                              |
| db/mod.rs                    | mod.rs               | src/db/mod.rs                    | src/db/mod.rs                    | فهرس وحدة قاعدة البيانات      | فهرس وحدة قاعدة البيانات                                |
| security/ratelimit.rs        | ratelimit.rs         | src/security/ratelimit.rs        | src/security/ratelimit.rs        | وحدة تحديد المعدل (DoS حماية) | وحدة تحديد المعدل والحماية من DoS          |
| security/input_validator.rs  | input_validator.rs   | src/security/input_validator.rs  | src/security/input_validator.rs  | أدوات التحقق للمدخلات         | أدوات التحقق من المدخلات                         |
| security/policy.rs           | policy.rs            | src/security/policy.rs           | src/security/policy.rs           | محرك السياسات الأمنية         | محرك السياسات                                  |
| security/jwt.rs              | jwt.rs               | src/security/jwt.rs              | src/security/jwt.rs              | إدارة رموز JWT               | إدارة JWT                                 |
| security/mod.rs              | mod.rs               | src/security/mod.rs              | src/security/mod.rs              | فهرس وحدة الأمان              | فهرس وحدة الأمان                          |
| core/geo_resolver.rs         | geo_resolver.rs      | src/core/geo_resolver.rs         | src/core/geo_resolver.rs         | محرك الموقع الجغرافي          | محرك تحليل الموقع الجغرافي                    |
| core/behavior_bio.rs         | behavior_bio.rs      | src/core/behavior_bio.rs         | src/core/behavior_bio.rs         | محرك التحليل السلوكي          | محرك التحليل السلوكي                    |
| core/device_fp.rs            | device_fp.rs         | src/core/device_fp.rs            | src/core/device_fp.rs            | بصمة الجهاز                   | توليد بصمة الجهاز                          |
| core/network_analyzer.rs     | network_analyzer.rs  | src/core/network_analyzer.rs     | src/core/network_analyzer.rs     | تحليل الشبكة وكشف التخفي      | تحليل الشبكة وكشف التخفي       |
| core/sensors_analyzer.rs     | sensors_analyzer.rs  | src/core/sensors_analyzer.rs     | src/core/sensors_analyzer.rs     | تحليل بيانات الحساسات         | محرك تحليل بيانات الحساسات                   |
| core/weather_val.rs          | weather_val.rs       | src/core/weather_val.rs          | src/core/weather_val.rs          | تدقيق بيانات الطقس            | محرك تدقيق بيانات الطقس                      |
| core/cross_location.rs       | cross_location.rs    | src/core/cross_location.rs       | src/core/cross_location.rs       | محرك التحقق المتقاطع          | محرك التحقق المتقاطع                        |
| core/history.rs              | history.rs           | src/core/history.rs              | src/core/history.rs              | إدارة وتحليل السجل التاريخي   | إدارة السجل وكشف الشذوذ         |
| core/mod.rs                  | mod.rs               | src/core/mod.rs                  | src/core/mod.rs                  | فهرس وحدة المحرك              | فهرس وحدة المحرك                       |
| api/auth.rs                  | auth.rs              | src/api/auth.rs                  | src/api/auth.rs                  | نقاط نهاية المصادقة           | نقاط نهاية المصادقة                                 |
| api/alerts.rs                | alerts.rs            | src/api/alerts.rs                | src/api/alerts.rs                | نقاط نهاية التنبيهات الأمنية  | نقاط نهاية التنبيهات الأمنية                      |
| api/geo.rs                   | geo.rs               | src/api/geo.rs                   | src/api/geo.rs                   | نقاط نهاية الموقع الجغرافي     | نقاط نهاية الموقع الجغرافي                          |
| api/device.rs                | device.rs            | src/api/device.rs                | src/api/device.rs                | نقاط نهاية الجهاز             | نقاط نهاية الجهاز                               |
| api/behavior.rs              | behavior.rs          | src/api/behavior.rs              | src/api/behavior.rs              | نقاط نهاية التحليل السلوكي     | نقاط نهاية التحليل السلوكي                    |
| api/network.rs               | network.rs           | src/api/network.rs               | src/api/network.rs               | نقاط نهاية تحليل الشبكة        | نقاط نهاية تحليل الشبكة                     |
| api/sensors.rs               | sensors.rs           | src/api/sensors.rs               | src/api/sensors.rs               | نقاط نهاية الحساسات           | نقاط نهاية الحساسات                              |
| api/weather.rs               | weather.rs           | src/api/weather.rs               | src/api/weather.rs               | نقاط نهاية الطقس              | نقاط نهاية الطقس                              |
| api/smart_access.rs          | smart_access.rs      | src/api/smart_access.rs          | src/api/smart_access.rs          | نقطة وصول التحقق الذكي         | نقطة نهاية الوصول الذكي                          |
| api/mod.rs                   | mod.rs               | src/api/mod.rs                   | src/api/mod.rs                   | فهرس وحدة API                 | فهرس وحدة API                               |
| utils/mod.rs                 | mod.rs               | src/utils/mod.rs                 | src/utils/mod.rs                 | فهرس وحدة الأدوات المساعدة     | فهرس وحدة الأدوات المساعدة                             |
| utils/helpers.rs             | helpers.rs           | src/utils/helpers.rs             | src/utils/helpers.rs             | دوال مساعدة عامة              | دوال مساعدة عامة                       |
| utils/logger.rs              | logger.rs            | src/utils/logger.rs              | src/utils/logger.rs              | وحدة التسجيل                  | وحدة التسجيل                                  |
| utils/cache.rs               | cache.rs             | src/utils/cache.rs               | src/utils/cache.rs               | وحدة التخزين المؤقت           | وحدة التخزين المؤقت                                   |
| Cargo.toml                   | Cargo.toml           | Cargo.toml                       | Cargo.toml                       | ملف التبعيات وإعداد المشروع   | ملف إدارة التبعيات                     |

---

## 🧩 الثوابت والدوال العامة

### 🔷 الثوابت

| اسم الثابت               | المعرف البرمجي           | القيمة الافتراضية | القيمة المرجعية | مكان التعريف              | الملف المرجعي |
| ------------------------ | ------------------------ | ----------------- | ------------- | ------------------------- | ---------------- |
| MAX_ACCURACY_THRESHOLD   | MAX_ACCURACY_THRESHOLD   | 50.0              | 50.0          | src/core/geo_resolver.rs  | geo_resolver.rs  |
| MIN_SIGNAL_STRENGTH      | MIN_SIGNAL_STRENGTH      | 30                | 30            | src/core/geo_resolver.rs  | geo_resolver.rs  |
| QUANTUM_SECURITY_LEVEL   | QUANTUM_SECURITY_LEVEL   | 90                | 90            | src/core/geo_resolver.rs  | geo_resolver.rs  |
| MAX_HISTORY_SIZE         | MAX_HISTORY_SIZE         | 100               | 100           | src/core/geo_resolver.rs  | geo_resolver.rs  |

---

### 🔷 الدوال العامة والهياكل

| اسم الدالة/الهيكل         | المعرف البرمجي              | التوقيع البرمجي                                          | مكان التعريف                        | الوصف                               | الشرح التقني                                 |
| ------------------------- | ---------------------------- | -------------------------------------------------------- | ----------------------------------- | ----------------------------------- | ------------------------------------------ |
| get_user_by_id            | get_user_by_id               | async fn get_user_by_id(pool, user_id)                   | src/db/crud.rs                      | جلب مستخدم من قاعدة البيانات        | جلب مستخدم من قاعدة البيانات                          |
| verify_smart_access       | verify_smart_access          | async fn verify_smart_access(...)                        | src/core/composite_verification.rs  | تحقق أمني مركب ذكي                  | تحقق أمني مركب ذكي              |
| process                   | process                      | async fn process(input: BehaviorInput)                   | src/core/behavior_bio.rs            | تحليل سلوك المستخدم/الجهاز          | تحليل سلوك المستخدم/الجهاز                |
| generate_fingerprint      | generate_fingerprint         | async fn generate_fingerprint(os, device, env)           | src/core/device_fp.rs               | توليد بصمة جهاز تكيفية              | توليد بصمة جهاز تكيفية        |
| analyze                   | analyze                      | async fn analyze(provider: &dyn NetworkInfoProvider)      | src/core/network_analyzer.rs        | تحليل الشبكة وكشف أدوات التخفي       | تحليل الشبكة وكشف أدوات التخفي  |
| fetch_and_validate        | fetch_and_validate           | async fn fetch_and_validate(lat, lng)                    | src/core/weather_val.rs             | جلب وتدقيق بيانات الطقس              | جلب وتدقيق بيانات الطقس               |
| validate                  | validate                     | async fn validate(input: CrossValidationInput)            | src/core/cross_location.rs          | تحقق متقاطع شامل                      | تحقق متقاطع شامل                       |
| log_event                 | log_event                    | async fn log_event(event: &HistoryEvent)                  | src/core/history.rs                 | تسجيل حدث تاريخي                      | تسجيل حدث تاريخي                        |
| detect_timeline_anomalies | detect_timeline_anomalies    | async fn detect_timeline_anomalies(entity_id, window)     | src/core/history.rs                 | كشف شذوذ زمني في الأحداث              | كشف شذوذ زمني في الأحداث                   |
| check                     | check                        | async fn check(ip)                                       | src/security/ratelimit.rs           | تحقق من معدل الطلبات                  | تحقق من معدل الطلبات                         |
| sign_location             | sign_location                | fn sign_location(location: &GeoLocation)                 | src/core/geo_resolver.rs            | توقيع بيانات الموقع رقمياً             | توقيع بيانات الموقع رقميا                |
| verify_signature          | verify_signature             | fn verify_signature(location: &GeoLocation)              | src/core/geo_resolver.rs            | تحقق من صحة التوقيع الرقمي              | التحقق من صحة التوقيع الرقمي                    |
| config                    | config                       | fn config(cfg: &mut ServiceConfig)                       | src/api/mod.rs                      | تسجيل جميع مسارات API                  | تسجيل جميع مسارات API                     |

---

### 🖊️ دوال التواقيع

| اسم الدالة                | المعرف البرمجي               | التوقيع البرمجي                                                    | مكان التعريف                        | الوصف                                 | الشرح التقني                                  |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------ | ----------------------------------- | ------------------------------------------- | --------------------------------------------- |
| sign_hmac_sha512          | sign_hmac_sha512             | fn sign_hmac_sha512(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs             | توقيع HMAC-SHA512 لبايتات البيانات          | توقيع HMAC-SHA512 على البيانات الثنائية               |
| verify_hmac_sha512        | verify_hmac_sha512           | fn verify_hmac_sha512(data: &[u8], sig: &[u8], key: &SecureBytes) -> bool            | src/security/signing.rs             | تحقق HMAC-SHA512                             | التحقق من HMAC-SHA512                           |
| sign_hmac_sha384          | sign_hmac_sha384             | fn sign_hmac_sha384(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs             | توقيع HMAC-SHA384                            | توقيع HMAC-SHA384                          |
| verify_hmac_sha384        | verify_hmac_sha384           | fn verify_hmac_sha384(data: &[u8], sig: &[u8], key: &SecureBytes) -> bool            | src/security/signing.rs             | تحقق HMAC-SHA384                             | التحقق من HMAC-SHA384                           |
| sign_struct_excluding_field | sign_struct_excluding_field | fn sign_struct_excluding_field<T: Serialize>(value: &T, exclude_field: &str, key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs | توقيع هيكل متسلسل مع استثناء حقل              | توقيع بنية قابلة للتسلسل مع استثناء حقل   |
| verify_struct_excluding_field | verify_struct_excluding_field | fn verify_struct_excluding_field<T: Serialize>(value: &T, exclude_field: &str, sig: &[u8], key: &SecureBytes) -> bool | src/security/signing.rs | تحقق من هيكل متسلسل مع استثناء حقل            | التحقق من بنية قابلة للتسلسل مع استثناء حقل |

---

### ⏱️ دوال الدقة

| اسم الدالة             | المعرف البرمجي           | التوقيع البرمجي                                                                     | مكان التعريف                   | الوصف                                   | الشرح التقني                                |
| ---------------------- | ------------------------ | ----------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------- | ------------------------------------------------- |
| time_delta_secs        | time_delta_secs          | fn time_delta_secs(start: DateTime<Utc>, end: DateTime<Utc>) -> f64                 | src/utils/precision.rs         | فرق الزمن بالثواني (حماية من القيم السالبة)     | فرق الزمن بالثواني (مع حماية من القيم السالبة)        |
| time_delta_secs_high_res | time_delta_secs_high_res | fn time_delta_secs_high_res(start: DateTime<Utc>, end: DateTime<Utc>) -> f64       | src/utils/precision.rs         | فرق زمن عالي الدقة (ثوانٍ + نانوثوانٍ)         | فرق زمن عالي الدقة (ثوان ونانوثوان)          |
| avg_f32                | avg_f32                  | fn avg_f32(values: &[f32]) -> f32                                                  | src/utils/precision.rs         | متوسط f32 بتجميع داخلي f64                      | متوسط f32 باستخدام تجميع داخلي عبر f64        |
| haversine_km           | haversine_km             | fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64                               | src/utils/precision.rs         | مسافة هافرسين بالكيلومترات                     | مسافة هافرسين بالكيلومترات                   |
| speed_kmh              | speed_kmh                | fn speed_kmh(distance_km: f64, seconds: f64) -> f64                                | src/utils/precision.rs         | سرعة كم/س مع حماية القسمة على صفر               | سرعة كم/س مع حماية من القسمة على صفر           |
| weighted_sum_f64       | weighted_sum_f64         | fn weighted_sum_f64(values: &[f64], weights: &[f64]) -> Option<f64>               | src/utils/precision.rs         | مجموع موزون f64 (يرجع None عند عدم التطابق)    | مجموع موزون f64 ويعيد None عند عدم تطابق الأطوال       |
| rate_of_change_f64     | rate_of_change_f64       | fn rate_of_change_f64(value_delta: f64, seconds: f64) -> f64                       | src/utils/precision.rs         | معدل التغير (قيمة/ثانية) مع حماية القسمة        | معدل التغير في الثانية مع حماية القسمة على صفر |
### 🔷 الواجهات (Traits) الرئيسية

| اسم الواجهة              | المعرف البرمجي للواجهة   | التوقيع البرمجي                            | مكان التعريف                        | الوصف                               | الشرح التقني                                |
| ------------------------ | ------------------------- | ------------------------------------------ | ----------------------------------- | ----------------------------------- | ------------------------------------------ |
| AiModel                  | AiModel                   | trait AiModel: detect_fraud, analyze_movement, ... | src/core/geo_resolver.rs            | واجهة نماذج الذكاء الاصطناعي للموقع    | نماذج ذكاء اصطناعي للتحقق الجغرافي                   |
| Blockchain               | Blockchain                | trait Blockchain: store_location, verify_location, ... | src/core/geo_resolver.rs            | واجهة تكامل البلوكشين                  | تكامل البلوكشين                      |
| BehavioralModel          | BehavioralModel           | trait BehavioralModel: analyze              | src/core/behavior_bio.rs            | واجهة نماذج تحليل السلوك                | نماذج التحليل السلوكي                  |
| AnomalyDetector          | AnomalyDetector           | trait AnomalyDetector: detect               | src/core/behavior_bio.rs            | واجهة كشف الشذوذ السلوكي                | كشف الشذوذ السلوكي                |
| SecurityMonitor          | SecurityMonitor           | trait SecurityMonitor: scan_environment, ... | src/core/device_fp.rs               | مراقبة أمان الجهاز                      | مراقبة أمان الجهاز                  |
| QuantumEngine            | QuantumEngine             | trait QuantumEngine: get_secure_key, ...    | src/core/device_fp.rs               | محرك التشفير ما بعد الكم                | محرك التشفير ما بعد الكم                  |
| AiProcessor              | AiProcessor               | trait AiProcessor: generate_ai_signature    | src/core/device_fp.rs               | معالجة الذكاء الاصطناعي للبصمة          | معالج ذكاء اصطناعي للبصمة             |
| NetworkInfoProvider      | NetworkInfoProvider       | trait NetworkInfoProvider: get_connection_type, ... | src/core/network_analyzer.rs        | مزود معلومات الشبكة                    | مزود معلومات الشبكة                       |
| AiNetworkAnalyzer        | AiNetworkAnalyzer         | trait AiNetworkAnalyzer: analyze            | src/core/network_analyzer.rs        | محلل الشبكة بالذكاء الاصطناعي           | محلل شبكة بالذكاء الاصطناعي                         |
| SensorAnomalyDetector    | SensorAnomalyDetector     | trait SensorAnomalyDetector: analyze        | src/core/sensors_analyzer.rs        | كشف شذوذ بيانات الحساسات                | كشف شذوذ الحساسات                    |
| WeatherProvider          | WeatherProvider           | trait WeatherProvider: get_weather, ...     | src/core/weather_val.rs             | مزود بيانات الطقس                       | مزود بيانات الطقس                       |
| ScoringStrategy          | ScoringStrategy           | trait ScoringStrategy: calculate_score      | src/core/cross_location.rs          | استراتيجية حساب درجة الثقة              | استراتيجية حساب درجة الثقة                      |

---

## 🔑 نقاط النهاية (API) والإعداد

### 🧾 مفاتيح البيئة والإعداد (.env / config)

| اسم المفتاح   | المعرف البرمجي | الدور                  | الغرض                    | مثال                       | ملاحظة |
| ------------- | ------------- | ---------------------- | ----------------------- | -------------------------- | ------- |
| API_KEY      | API_KEY      | مفتاح المصادقة الرئيسي | مفتاح المصادقة الرئيسي | API_KEY=your_secret_key |         |
| JWT_SECRET   | JWT_SECRET   | سر توقيع/تحقق JWT      | سر توقيع/تحقق JWT | JWT_SECRET=32+_chars_secret |         |
| DATABASE_URL | DATABASE_URL | رابط SQLite    | رابط قاعدة البيانات    | DATABASE_URL=sqlite://data/app.db  |         |
| LOG_LEVEL    | LOG_LEVEL    | مستوى السجلات          | مستوى السجلات       | LOG_LEVEL=debug           |         |
| GEO_PROVIDER | GEO_PROVIDER | مزود الموقع (اختياري)  | مزود الموقع الجغرافي    | GEO_PROVIDER=ipapi        |         |

---

### 🌐 نقاط النهاية (API Endpoints)

| المسار              | المسار البرمجي        | نوع الطلب | الطريقة | الدور                          | الوصف                           | مكان التعريف                 |
| ------------------- | --------------------- | --------- | ------ | ----------------------------- | ------------------------------- | ---------------------------- |
| /api/users/{id}     | /api/users/{id}       | GET       | GET    | جلب بيانات مستخدم             | جلب بيانات مستخدم                 | src/api/auth.rs              |
| /api/alerts/trigger | /api/alerts/trigger   | POST      | POST   | إطلاق تنبيه أمني              | إطلاق تنبيه أمني          | src/api/alerts.rs            |
| /api/geo/resolve    | /api/geo/resolve      | POST      | POST   | تحليل الموقع الجغرافي         | تحليل الموقع الجغرافي             | src/api/geo.rs               |
| /api/device/resolve | /api/device/resolve   | POST      | POST   | تحليل/تسجيل الجهاز            | تحليل/تسجيل الجهاز         | src/api/device.rs            |
| /api/behavior/analyze| /api/behavior/analyze| POST      | POST   | تحليل السلوك                   | تحليل السلوك               | src/api/behavior.rs          |
| /api/network/analyze| /api/network/analyze  | POST      | POST   | تحليل الشبكة                   | تحليل الشبكة                | src/api/network.rs           |
| /api/sensors/analyze| /api/sensors/analyze  | POST      | POST   | تحليل بيانات الحساسات          | تحليل بيانات الحساسات           | src/api/sensors.rs           |
| /api/weather/summary| /api/weather/summary  | POST      | POST   | ملخص بيانات الطقس              | ملخص بيانات الطقس                 | src/api/weather.rs           |
| /api/smart_access/verify| /api/smart_access/verify| POST| POST   | تحقق وصول ذكي مركب             | تحقق وصول ذكي مركب    | src/api/smart_access.rs      |

---

## 🧭 البنية المعمارية

```mermaid
graph TD
  A[main.rs 🧩\nنقطة الدخول] --> B[طبقة API 🌐]
  A --> C[محركات النواة 🧠]
  A --> D[طبقة قاعدة البيانات 🗄️]
  B -->|المسارات| E[🔓 /auth, /alerts, /users, ...]
    C --> F[GeoResolver 🌍]
    C --> G[BehaviorEngine 🧠]
    C --> H[DeviceFingerprint 📱]
    C --> I[NetworkAnalyzer 🌐🔍]
    C --> J[SensorsAnalyzer 📡]
    C --> K[WeatherEngine ☁️]
    C --> L[CrossValidator 🔄]
    C --> M[CompositeVerifier 🛡️]
    C --> N[HistoryService 🕓]
    D --> O[CRUD + Models ⚙️]
    B --> P[طبقة الأمان 🔐]
    P --> Q[InputValidator 📥]
    P --> R[JWT Manager 🔑]
    P --> S[Policy Engine ⚖️]
    P --> T[RateLimiter 🚦]
```

> 🎯 **الوصف:**
> يوضح المخطط تداخل الوحدات الرئيسة (API، المحرك الأساسي، قاعدة البيانات، طبقة الأمان) مع إبراز المحركات الجديدة (تحليل الحساسات، الطقس، التحقق المتقاطع، السجل التاريخي) وصولاً لطبقة التحقق الأمني المركب الذكي.
> 
> **الوصف الإنجليزي:**
> The diagram shows the interaction of main units (API, core engine, DB, security layer) highlighting new engines (sensors, weather, cross-validation, history) up to the smart composite security layer.

---

## 🛠️ أمثلة التحقق العملي

### تحقق أمني مركب

```rust
let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
let allowed_hours = Some((6, 18));
let access_granted = composite_verifier.verify_smart_access(
    geo_input, // (Option<IpAddr>, Option<(f64, f64, u8, f64)>)
    behavior_input, // BehaviorInput
    (os, device, env), // (&str, &str, &str)
    &allowed_zones,
    allowed_hours,
).await?;
if !access_granted {
    // رفض الوصول أو تسجيل محاولة مشبوهة | Deny access or log suspicious attempt
}
```

---

### تحقق من الموقع الجغرافي فقط

```rust
let geo_location = geo_resolver.resolve(Some(ip), Some(gps), None, None, None, None, None).await?;
if let Some(city) = &geo_location.city {
    if allowed_zones.contains(city) {
        // تحقق جغرافي ناجح | Geo verification successful
    } else {
        // رفض الوصول بسبب المنطقة | Access denied due to location
    }
}
```

---

### تحقق من السلوك فقط

```rust
let behavior_result = behavior_engine.process(behavior_input).await?;
if behavior_result.risk_level as u8 < 3 {
    // السلوك طبيعي | Low risk behavior
} else {
    // السلوك مشبوه | Medium or high risk behavior
}
```

---

### تحقق من الجهاز فقط

```rust
let device_fp = device_fp_engine.generate_fingerprint(os, device, env).await?;
if device_fp.security_level >= 5 {
    // الجهاز موثوق | Device is trusted
} else {
    // الجهاز غير موثوق | Device is not trusted
}
```

---

### تحقق من الصلاحيات فقط

```rust
use mkt_ksa_geo_sec::security::policy::{Action, PolicyContext, PolicyEngine, Role, UserStatus};
use uuid::Uuid;

let roles = vec![Role::Admin];
let status = UserStatus::Active;
let actor = Uuid::new_v4();
let target = Uuid::new_v4();

let context = PolicyContext {
  user_id: actor,
  roles: &roles,
  status: &status,
  trust_score: 90,
};

if PolicyEngine::can_execute(&context, &Action::ReadUserData { target_user_id: &target }).is_ok() {
  // للمستخدم الصلاحية المطلوبة | User has required role/action permission
} else {
  // ليس لديه الصلاحية | User lacks required role/action permission
}
```

---

## ⚙️ وحدات المحرك الأساسية

### 🕓 وحدة السجل التاريخي

- **الوصف:** إدارة وتخزين وتحليل الأحداث والسلوكيات التاريخية للمستخدمين والأجهزة، مع دعم كشف الشذوذ الزمني والتكامل مع قاعدة البيانات.
- **الوصف التفصيلي:** إدارة وتخزين وتحليل الأحداث والسلوكيات التاريخية للمستخدمين والأجهزة مع دعم كشف الشذوذ والتكامل مع قاعدة البيانات.
- **أهم الدوال:** log_event, get_entity_history, detect_timeline_anomalies

---

### 🔄 وحدة التحقق المتقاطع

- **الوصف:** محرك تنسيق متقدم يجمع نتائج محركات التحقق (الموقع، السلوك، الجهاز...) ليصدر حكمًا نهائيًا موثوقًا وموقعًا رقمياً.
- **الوصف التفصيلي:** منسق متقدم يجمع نتائج محركات التحقق (الموقع، السلوك، الجهاز...) لإصدار قرار نهائي موثوق وموقّع رقميا.
- **أهم الدوال:** validate, sign_verdict

---

### 📡 وحدة تحليل الحساسات

- **الوصف:** تحليل بيانات الحساسات (مثل التسارع، الجيروسكوب) للكشف عن الشذوذ أو التلاعب، مع إصدار شهادة تحليل موقعة رقمياً.
- **الوصف التفصيلي:** تحليل بيانات الحساسات (مثل التسارع والجيروسكوب) لاكتشاف الشذوذ أو التلاعب، مع إصدار شهادة تحليل موقعة رقميا.
- **أهم الدوال:** analyze (SensorsAnalyzerEngine)

---

### ☁️ وحدة الطقس والتحقق

- **الوصف:** تجميع وتدقيق بيانات الطقس من مزودين متعددين، مع مقارنة النتائج وتقديم بيانات موحدة وموثوقة.
- **الوصف التفصيلي:** تجميع وتدقيق بيانات الطقس من مزودين متعددين، مع مقارنة النتائج وتقديم بيانات موحدة وموثوقة.
- **أهم الدوال:** fetch_and_validate (WeatherEngine)

---

## ⚠️ تقرير فحص التبعيات

هذه الحالة تعكس الوضع الحالي الصارم على `main`:

- قاعدة البيانات الأساسية الآن SQLite عبر `tokio-rusqlite` (الميزة الافتراضية `db-sqlite`).
- تم إزالة المسار الانتقالي الضعيف المرتبط بـ MySQL من البروفايل الفعلي؛ `cargo audit --deny warnings` ناجح.
- المسار الافتراضي لا يعتمد على OpenSSL، و`reqwest` يعمل مع `rustls-tls`.
- التغليف يستبعد ملفات الكاش/البيئة الحساسة: `.cargo-home/**`, `target/**`, `.env`, `.env.*`.

أهم التبعيات المباشرة الحالية في `Cargo.toml`:

- Web/runtime: `actix-web`, `actix-rt`, `tokio`
- Security/crypto: `aes-gcm`, `hmac`, `sha2`, `blake3`, `jsonwebtoken`, `secrecy`, `zeroize`, `pqcrypto-mlkem`
- Data/validation: `serde`, `serde_json`, `validator`, `regex`, `chrono`, `uuid`
- Networking/geo: `reqwest` (Rustls), `maxminddb`
- Utilities: `anyhow`, `thiserror`, `rayon`, `lru`, `config`, `futures`, `log`

---

## ✅ نتائج الاختبار

```bash
running 39 tests
... all tests passed ...

test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

* ✅ كل الاختبارات نجحت (39 اختبارًا).

---

## 🔒 استقرار الإصدار الحالي

- **الأداة/البيئة:** Stable Rust toolchain مع `Cargo.lock` محدث وتحقيقات CI صارمة.
- **البناء:** `cargo check` ناجح.
- **الاختبارات:** `cargo test --workspace` ناجحة بالكامل (39/39).
- **التنسيق:** `cargo fmt --check` نظيف.
- **اللينتر:** `cargo clippy --workspace --all-targets -- -D warnings` نظيف.
- **الأمان:** `cargo audit --deny warnings` نظيف.
- **الملاحظة التشغيلية:** يتم قبول `sqlite://` فقط في `DATABASE_URL` ضمن هذا البروفايل الصارم.

---

## ⬆️ خطة ترقية التبعيات بالكامل

### النطاق
- الاستمرار في تحديث التبعيات بشكل دوري مع الحفاظ على التوافق وعدم كسر الواجهات العامة.

### السياسة
- بدون كسر توافق عام: الترقية على مراحل، مع بناء واختبارات و`audit/clippy/fmt` بعد كل مرحلة.
- عدم تغيير واجهات المكتبة العامة في هذا المسار؛ أي تغييرات كاسرة تؤجل لإصدار رئيسي.

### المراحل
1) تحديث `Cargo.lock` ومراجعة فروق الاعتمادات.
2) تطبيق تحديثات patch/minor فقط أولًا.
3) إعادة اختبار واجهات API وFFI بعد كل دفعة تحديث.
4) اعتماد أي تحديث فقط بعد نجاح `fmt`, `clippy -D warnings`, `test`, `audit --deny warnings`.

### ضمانات
- تشغيل CI كامل: `check`, `test`, `fmt`, `clippy`, `audit` في كل مرحلة.
- توثيق نتائج كل مرحلة ضمن ملاحظات الإصدار قبل الدمج.

## ⭐ مزايا المشروع والفئات المستهدفة

### 🎯 هدف المكتبة وقوتها الأمنية

- **هدف المكتبة:**
  - تقديم منصة تحقق أمني ذكية متكاملة للمدن الذكية، الجهات السيادية، المؤسسات المالية، وشركات التقنية، مع دعم كامل للتخصيص والتكامل.
  - تم تصميمها لتكون معيارًا للأمان الجغرافي والسلوكي في البيئات عالية الحساسية، مع قابلية التوسع والدمج في أي نظام حديث.
- **قوة الأمان:**
  - تعتمد المكتبة على بنية معيارية متعددة الطبقات، تجمع بين التحقق الجغرافي، التحليل السلوكي، بصمة الجهاز، تحليل الشبكة، كشف التلاعب، التحقق المتقاطع، وتدقيق الطقس والحساسات.
  - جميع العمليات مدعومة بتشفير متقدم (AES-GCM, HMAC, Post-Quantum)، إدارة أسرار آمنة (secrecy, zeroize)، وتوقيعات رقمية.
  - لا تعتمد على OpenSSL، وتستخدم فقط مكتبات Rust آمنة وحديثة.
  - تدعم سياسات المدن الذكية، كشف أدوات التخفي (VPN/Proxy/Tor)، وتوفر سجل تاريخي وتحليل شذوذ زمني.

---

### 🏆 المزايا الرئيسية

* 🔐 تحقق مركب متعدد المصادر: (جغرافي، سلوكي، جهاز، شبكة، حساسات، طقس).
* 🧠 تكامل AI وتكيف ذكي: دعم الذكاء الاصطناعي وخوارزميات الأمن التكيفية.
* 🛰️ كشف التخفي المتقدم: دعم VPN/Proxy/Tor وطرق كشف متطورة.
* 🏙️ سياسات المدن الذكية والمؤسسات الكبرى: دعم مناطق/أذونات/أوقات متقدمة.
* ⚡ بنية معيارية ومرنة: قابلة للحقن والتخصيص لأي محرك أو منطق أمان.
* 📄 توثيق ثنائي اللغة كامل: كل جزء موثق عربي/إنجليزي.
* 🔑 إدارة أسرار وتشفير ما بعد الكم: دعم secrecy وPost-Quantum crypto.
* 🚦 تحديد معدل الطلبات Rate Limiting: وحدة RateLimiter جاهزة.
* 🔌 سهولة التكامل مع أي تطبيق أو خدمة: REST API أو Rust Traits مباشرة.
* 🕓 سجل تاريخي وتحليل شذوذ زمني: وحدة history متقدمة.
* ☁️ تدقيق بيانات الطقس: وحدة weather للتحقق من الظروف البيئية.
* 📡 تحليل بيانات الحساسات: دعم سيناريوهات الأجهزة الذكية وإنترنت الأشياء.

---

### 👤 الفئات المستهدفة

- **الجهات السيادية والحكومية:**
  - الجهات السيادية، القطاعات الأمنية، مراكز القيادة والتحكم، المدن الذكية، الأمن السيبراني، الجوازات، المرور، الدفاع المدني، البلديات، أنظمة الطوارئ.
- **المؤسسات المالية والمصرفية:**
  - البنوك، شركات التأمين، شركات المدفوعات الرقمية، البورصات.
- **شركات التقنية الكبرى والمتوسطة:**
  - مزودو الخدمات السحابية، شركات الذكاء الاصطناعي، الأمن السيبراني، إنترنت الأشياء (IoT)، حلول المدن الذكية.
- **شركات النقل والخدمات اللوجستية:**
  - شركات التوصيل، النقل الذكي، إدارة الأساطيل، الطيران والمطارات.
- **القطاع الصحي:**
  - المستشفيات، أنظمة الصحة الرقمية، إدارة الطوارئ الطبية.
- **القطاع التعليمي:**
  - الجامعات، المدارس الذكية، أنظمة الاختبارات الرقمية الآمنة.
- **تطبيقات الهوية والصلاحيات:**
  - أنظمة التحكم في الوصول، المصادقة متعددة العوامل (MFA)، حلول الهوية الرقمية.
- **شركات الطاقة والمرافق:**
  - شركات الكهرباء، المياه، النفط والغاز، شبكات البنية التحتية الذكية.
- **القطاع الصناعي والتحكم:**
  - المصانع الذكية، أنظمة SCADA، الروبوتات الصناعية.
- **أي مطور أو مؤسسة تبحث عن حلول أمان حديثة وقابلة للتخصيص والتكامل.**

---

### 💎 نقاط التميز

* **تحقق مركب يجمع بين الموقع والسلوك والجهاز والشبكة في قرار واحد**
* **دعم مصادر جغرافية متعددة (GPS, IP, SIM, Satellite, Indoor, AR)**
* **حقن أي منطق ذكاء اصطناعي أو تعلم آلي بسهولة**
* **كشف متقدم لأدوات التخفي (VPN/Proxy/Tor)**
* **دعم كامل لمدن ومؤسسات كبرى – Plug & Play**
* **توثيق ثنائي اللغة وواجهة برمجية مرنة للمطورين**

---

## 🧠 دليل المطور

### 🚀 خطوات التكامل الأساسي

1. **ضبط متغيرات البيئة الأساسية (.env/config):**

   ```bash
   API_KEY=your_secret_key
   DATABASE_URL=mysql://user:pass@host/db
   ```
2. **تهيئة المحركات الأساسية في تطبيقك:**

   * استدع الدوال العامة مثل:
     `verify_smart_access`, `process`, `generate_fingerprint`
3. **تخصيص المنطق الأمني:**

   * يمكنك حقن نموذج AI أو منطق تحقق خاص بك عبر Traits
   * تخصيص السياسات (مناطق، أوقات، أذونات) بسهولة
4. **استخدام نقاط النهاية (API) أو التكامل المباشر مع Rust:**

   * استدعاء REST API (/users/{id}, /alerts/trigger)
   * أو ربط الدوال مباشرة في الكود

#### مثال ربط سريع (Rust)

```rust
let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
let allowed_hours = Some((6, 18)); // من 6 صباحًا إلى 6 مساءً
let access_granted = composite_verifier.verify_smart_access(
    geo_input,
    behavior_input,
    device_info,
    &allowed_zones,
    allowed_hours,
).await?;
if !access_granted {
    // رفض الوصول أو تسجيل محاولة مشبوهة
}
```

#### 🔌 أعلام الميزات

#### يدعم هذا الصندوق علامات الميزات المتقدمة لتنشيط الإمكانات المتخصصة.
#### يمكنك تمكينها عبر مثل هذا:Cargo.toml

#### [dependencies]
#### MKT_KSA_Geolocation_Security = { version = "1.0.0", features = ["adaptive", "quantum"] }    

| اسم الميزة | الوصف |
| --------------------- | ----- |
| `adaptive`            | تفعيل التحليل السلوكي التكيفي المعتمد على الذكاء الاصطناعي. |
| `ar_integration`      | دمج مصادر الواقع المعزز (AR) لتعزيز دقة التحقق الجغرافي. |
| `autonomous_vehicles` | تفعيل وحدات موجهة للسيارات ذاتية القيادة وأنظمة الأساطيل الذكية. |
| `blockchain`          | دعم المصادقة المرتبطة بالبلوكشين وتثبيت البيانات عليها. |
| `generative_ai`       | استخدام نماذج الذكاء التوليدي لتوليد وتعديل السياسات الأمنية ديناميكيًا. |
| `gpu`                 | تفعيل تسريع GPU للعمليات التحليلية الثقيلة (مثل الحساسات أو الشبكة). |
| `predictive`          | إضافة نماذج تنبؤية وكشف شذوذ قائم على الأنماط السلوكية. |
| `quantum`             | تفعيل مكونات متوافقة مع التشفير ما بعد الكم. |
| `quantum_computing`   | تمكين التكامل مع منصات ومحركات الحوسبة الكمية. |
| `v1_1`                | دعم التوافق مع API الإصدار 1.1 للأنظمة القديمة. |
| `v2_0`                | دعم التوافق مع API الإصدار 2.0 (الإعداد الافتراضي لمعظم الوحدات). |
| `v3_0`                | تفعيل وحدات الجيل القادم الخاصة بـ API الإصدار 3.0. |
| `zkp`                 | إضافة دعم Zero-Knowledge Proofs للتحقق المحافظ على الخصوصية والتحكم بالوصول. |

---

## 📦 استخدام المكتبة من Rust

```toml
[dependencies]
MKT_KSA_Geolocation_Security = "2.0.0" # اسم الاستدعاء داخل الشيفرة: mkt_ksa_geo_sec
# أو من Git:
# MKT_KSA_Geolocation_Security = { git = "https://github.com/mktmansour/MKT-KSA-Geolocation-Security" }
```

```rust
use mkt_ksa_geo_sec::core::geo_resolver::{
    GeoResolver, DefaultAiModel, DefaultBlockchain, GeoReaderEnum, MockGeoReader,
};
use mkt_ksa_geo_sec::security::secret::SecureBytes;
use std::sync::Arc;

let resolver = GeoResolver::new(
    SecureBytes::new(vec![1; 32]),
    Arc::new(DefaultAiModel),
    Arc::new(DefaultBlockchain),
    true,
    false,
    Arc::new(GeoReaderEnum::Mock(MockGeoReader::new())),
);
```

- ملاحظة مهمة: مسار الاستدعاء (import path) في Rust هو `mkt_ksa_geo_sec`.

## 🔗 الربط عبر C-ABI للغات الأخرى

- المكتبة تُبنى كـ `cdylib/staticlib` ويمكن استدعاؤها من C/C++/Python/.NET/Java/Go.
- اسم ملف الترويسة (Header) المُولّد: `mkt_ksa_geo_sec.h`.
- دوال التصدير الحالية:
  - `generate_adaptive_fingerprint(os: *const c_char, device_info: *const c_char, env_data: *const c_char) -> *mut c_char`
  - `free_fingerprint_string(ptr: *mut c_char)`

مثال C مختصر:

```c
// usage (header generated via cbindgen)
char* fp = generate_adaptive_fingerprint("Windows", "LaptopX", "Office");
printf("%s\n", fp);
free_fingerprint_string(fp);
```

## 🌐 دعم جميع اللغات

- **الفكرة**: المكتبة محايدة اللغة وتدعم كل المشاريع عبر 3 مسارات متوازية:
  - **C-ABI**: الربط المباشر باستخدام `mkt_ksa_geo_sec.h` وملفات `cdylib/staticlib` (موصى به للأداء).
  - **REST API**: استدعاء نقاط النهاية عند تفضيل التكامل الشبكي.
  - **أغلفة رسمية قادمة**: Python/Java/.NET/Node/Go (حزم موثقة). حالياً يمكنك الاستدعاء مباشرة عبر C-ABI كما في الأمثلة التالية.

### Python (ctypes)
```python
import ctypes
lib = ctypes.cdll.LoadLibrary("./libmkt_ksa_geo_sec.so")  # أو mkt_ksa_geo_sec.dll / dylib
lib.generate_adaptive_fingerprint.restype = ctypes.c_void_p
fp_ptr = lib.generate_adaptive_fingerprint(b"Windows", b"LaptopX", b"Office")
print(ctypes.cast(fp_ptr, ctypes.c_char_p).value.decode())
lib.free_fingerprint_string(fp_ptr)
```

### Java (JNA)
```java
public interface GeoSec extends com.sun.jna.Library {
  GeoSec INSTANCE = com.sun.jna.Native.load("mkt_ksa_geo_sec", GeoSec.class);
  com.sun.jna.Pointer generate_adaptive_fingerprint(String os, String dev, String env);
  void free_fingerprint_string(com.sun.jna.Pointer p);
}
```

### .NET (P/Invoke)
```csharp
[DllImport("mkt_ksa_geo_sec")]
static extern IntPtr generate_adaptive_fingerprint(string os, string dev, string env);
[DllImport("mkt_ksa_geo_sec")] static extern void free_fingerprint_string(IntPtr p);
```

### Node.js (ffi-napi)
```js
const ffi = require('ffi-napi');
const lib = ffi.Library('mkt_ksa_geo_sec', { 'generate_adaptive_fingerprint': ['pointer',['string','string','string']], 'free_fingerprint_string': ['void',['pointer']] });
```

> ملاحظة: أسماء الملفات والدوال قد تختلف حسب نظام التشغيل وامتداد المكتبة. استخدم الهيدر `mkt_ksa_geo_sec.h` كمرجع نهائي لتواقيع FFI.


#### 💡 نصائح متقدمة

* جميع المحركات قابلة للحقن أو الاستبدال
* حرية تخصيص كاملة (الجلسة/الجهاز/الدور)
* أمثلة ودوال وثوابت كلها موثقة عربي/إن

---

## 📝 ملاحظات الإصدار v2.0.0

- **المستوى:** منخفض إلى متوسط - تحسينات جودة وكود وتنظيف لِنتر دون تغييرات سلوكية عامة.
- **إصلاحات رئيسية:**
  - تطبيق كامل وصارم لـ Clippy مع -D warnings على جميع الأهداف، وتنظيف كل التحذيرات.
  - توحيد أنماط استخراج JWT من الهيدر في طبقة API واستخدام let-else حيث يلزم.
  - إضافة `#[allow(...)]` موضعي فقط حيث قد يؤثر التغيير على واجهات عامة أو منطق استدعاء قائم.
  - توثيق `#Errors` و`#Panics` في الدوال الحرجة.
  - تحسينات Floating-Point وsuboptimal_flops بتمكين/تكميم انتقائي دون تغيير السلوك.
  - إصلاح تحذيرات `unused_async` و`unused_self` في دوال داخلية وتجريبية.
  - ضمان عدم تغيير الواجهات العامة، وعدم حذف أي منطق أو ملفات.
- **الاختبارات:** 39/39 ناجحة.
- **Clippy:** نظيف بالكامل.
- **التبعيات:**
  - لم يتم تغيير نسخ الحزم الإنتاجية.
  - توجد نسخ مزدوجة لبعض الحزم بشكل ترانزيتيف (مثل `base64/http/lru/windows-sys`) وتم إبقاؤها لتجنب كسر التوافق.
  - `cargo audit --deny warnings` نظيف في المسار الأمني الصارم الحالي.

#### 🔄 تغييرات التبعيات (هذه الجلسة)
- **تمت الإزالة:**
  - `once_cell`, `lazy_static`: استُبدلت باستعمال `std::sync::LazyLock`.
  - `serde_derive`: غير لازمة لأن `serde` مفعّل بميزة `derive`.
  - `getrandom` (مباشر): أزيلت كتبعّية مباشرة، والآن نستخدم `rand::rngs::OsRng::try_fill_bytes` لتوليد البايتات العشوائية بشكل قياسي وآمن.
- **تم التحديث:**
  - `reqwest`: 0.12.22 → 0.12.23 (Rustls، تصحيحات طفيفة).
  - `pqcrypto-mlkem`: 0.1.0 → 0.1.1.
  - `secrecy`: 0.8.x → 0.10.3. تم إدخال أغلفة داخلية `security::secret::{SecureString, SecureBytes}` لعزل تغييرات API. تم تحديث جميع مواقع الاستدعاء دون تغيير المنطق أو مستوى الأمان.
- **تعديلات ترانزيتيف:**
  - `async-trait`، `hyper`، `thiserror`، وغيرها تَحدّثت تلقائيًا ضمن القيود.

#### 🆕 ملفات أُنشئت
- `src/security/signing.rs`: وحدة توقيعات/HMAC مركزية عالية الأمان (بدون OpenSSL).
- `src/utils/precision.rs`: وحدة دقة للأزمنة والحسابات العددية/الجغرافية.

### 🔧 تغييرات التواقيع الداخلية (دون تأثير على المنطق/المسارات)

- **طبقة API** (`src/api/*.rs`):
  - اعتماد extractors بدل `HttpRequest`: استخدام `web::Data<AppState>`, `web::Json<...>`, و`BearerToken` لتأمين الـ futures (Send-safe) وتنظيف التواقيع.
- **محرك الجغرافيا** (`src/core/geo_resolver.rs`):
  - الدالة `resolve` تستقبل الآن `ResolveParams` بدل قائمة معاملات طويلة؛ تم تحديث جميع مواقع الاستدعاء.
- **التحليل السلوكي** (`src/core/behavior_bio.rs`):
  - `get_user_profile_data` أصبحت متزامنة (تمت إزالة `async` لعدم وجود `await`)، وتم تحديث الاستدعاء في `src/api/auth.rs` (إزالة `.await`).
- **بصمة الجهاز/FFI** (`src/core/device_fp.rs`):
  - دوال الربط C أصبحت `unsafe extern "C"` مع توثيق `# Safety`، دون تغيير منطق التنفيذ.

#### 📑 مرجع التواقيع الحالية

- **واجهات API**

```rust
pub async fn trigger_alert(
    payload: web::Json<AlertTriggerRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn analyze_behavior(
    app_data: web::Data<AppState>,
    payload: web::Json<BehaviorAnalyzeRequest>,
    bearer: BearerToken,
) -> impl Responder;


pub async fn resolve_device(
    app_data: web::Data<AppState>,
    payload: web::Json<DeviceResolveRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn resolve_geo(
    app_data: web::Data<AppState>,
    payload: web::Json<GeoResolveRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn analyze_network(
    app_data: web::Data<AppState>,
    payload: web::Json<NetworkAnalyzeRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn analyze_sensors(
    app_data: web::Data<AppState>,
    payload: web::Json<SensorsAnalyzeRequest>,
    bearer: BearerToken,
) -> impl Responder;

pub async fn weather_summary(
    _payload: web::Json<WeatherSummaryRequest>,
    bearer: BearerToken,
) -> impl Responder;
```

- **النواة**

```rust
impl GeoResolver {
    pub async fn resolve(
        &self,
        params: ResolveParams,
    ) -> Result<GeoLocation, GeoResolverError>;
}

impl UserService {
    pub fn get_user_profile_data(
        &self,
        _requester_id: Uuid,
        _target_user_id: Uuid,
    ) -> Result<User, BehaviorError>;
}
```

- **سطح FFI (توافق C)**

```rust
pub unsafe extern "C" fn generate_adaptive_fingerprint(
    os: *const c_char,
    device_info: *const c_char,
    env_data: *const c_char,
) -> *mut c_char;

pub unsafe extern "C" fn free_fingerprint_string(ptr: *mut c_char);
```

### 🧹 تنسيق وفحوص إضافية
- تم تطبيق `cargo fmt --all` لتنظيف الفروقات التنسيقية التي أظهرها `--check`.
- نتائج `cargo tree -d` تُظهر ازدواجيات ترانزيتيف مقبولة حالياً: `base64 (0.21/0.22)`, `http (0.2/1.x)`, `lru (0.14/0.16)`, `hashbrown (0.14/0.15)`, `socket2 (0.5/0.6)`, `windows-sys (0.52/0.59)`.

---

```
