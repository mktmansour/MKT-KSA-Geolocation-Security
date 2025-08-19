# 🛡️🌍 MKT_KSA_Geolocation_Security
**مكتبة التحقق الجغرافي والأمني السعودي الذكية – MKT KSA 🇸🇦**
**Smart Saudi Geolocation & Security Library** 
> 🔐 Rust | 🛰️ Smart Security | 🏙️ Smart City Ready | 📄 Apache 2.0 |  Developed by Mansour Bin Khalid (KSA 🇸🇦)

[![Rust](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/rust.yml)      [![Clippy](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml/badge.svg)](https://github.com/mktmansour/MKT-KSA-Geolocation-Security/actions/workflows/clippy.yml)

[![Crates.io](https://img.shields.io/crates/v/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![Docs.rs](https://img.shields.io/docsrs/MKT_KSA_Geolocation_Security?style=for-the-badge)](https://docs.rs/MKT_KSA_Geolocation_Security)
[![Downloads](https://img.shields.io/crates/d/MKT_KSA_Geolocation_Security.svg?style=for-the-badge)](https://crates.io/crates/MKT_KSA_Geolocation_Security)
[![License](https://img.shields.io/crates/l/MKT_KSA_Geolocation_Security?style=for-the-badge)](LICENSE)
![MSRV](https://img.shields.io/badge/MSRV-1.89%2B-informational?style=for-the-badge)
![Audit](https://img.shields.io/badge/audit-clean-success?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/maintenance-actively%20maintained-success?style=for-the-badge)
![Edition](https://img.shields.io/badge/edition-2021-blue?style=for-the-badge)
---
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/ffe24b4e-fc3f-4203-8c4a-08633ae43488" />

## 📘 المحتويات | Table of Contents

* [🗺️ نبذة عن المشروع | Project Overview](#-نبذة-عن-المشروع--project-overview)
* [📂 الملفات الأساسية | Main Files](#-الملفات-الأساسية--main-files)
* [🧩 الثوابت والدوال | Constants & Functions](#-الثوابت-والدوال--constants--functions)
  * [🖊️ دوال التواقيع | Signing Module Functions](#-دوال-التواقيع--signing-module-functions)
  * [⏱️ دوال الدقة | Precision Module Functions](#-دوال-الدقة--precision-module-functions)
* [🔑 المفاتيح ونقاط النهاية | Config & Endpoints](#-المفاتيح-ونقاط-النهاية--config--endpoints)
* [🧭 البنية المعمارية | Architecture](#-البنية-المعمارية--architecture)
* [🛠️ أمثلة التحقق | Verification Examples](#-أمثلة-التحقق--verification-examples)
* [⚙️ وحدات المحرك الأساسية | Core Engine Modules](#-وحدات-المحرك-الأساسية--core-engine-modules)
* [📡 وحدة تحليل الحساسات | Sensors Analyzer](#-وحدة-تحليل-الحساسات--sensors-analyzer)
* [☁️ وحدة الطقس والتحقق | Weather Validation](#-وحدة-الطقس-والتحقق--weather-validation)
* [📜 وحدة السجل التاريخي | History Service](#-وحدة-السجل-التاريخي--history-service)
* [🔄 التحقق المتقاطع | Cross-Validation Engine](#-التحقق-المتقاطع--cross-validation-engine)
* [⚠️ تقرير التبعيات | Dependency Audit](#-تقرير-التبعيات--dependency-audit)
* [✅ نتائج الاختبار | Test Results](#-نتائج-الاختبار--test-results)
* [🔒 استقرار الإصدار الحالي | Current Release Stability](#-استقرار-الإصدار-الحالي--current-release-stability)
* [⬆️ خطة ترقية التبعيات بالكامل | Full Dependency Upgrade Plan](#-خطة-ترقية-التبعيات-بالكامل--full-dependency-upgrade-plan)
* [⭐ مزايا المشروع | Features](#-مزايا-المشروع--features)
* [🧠 دليل المطور | Developer Guide](#-دليل-المطور--developer-guide)
* [📈 ملخص الحالة الفنية | System State](#-ملخص-الحالة-الفنية--system-state)
* [📝 ملاحظات الإصدار v1.0.2 | Release Notes v1.0.2](#-ملاحظات-الإصدار-v102--release-notes-v102)
  * [🔧 تغييرات التواقيع الداخلية | Internal Signature Changes](#-تغييرات-التواقيع-الداخلية-دون-تأثير-على-المنطقمسارات--internal-signature-changes-no-behaviorroute-changes)
  * [📑 مرجع التواقيع الحالية | Current Signatures Reference](#-مرجع-التواقيع-الحالية--current-signatures-reference)
  * [🧹 تنسيق وفحوص إضافية | Formatting and Extra Checks](#-تنسيق-وفحوص-إضافية--formatting-and-extra-checks)
* [📦 استخدام المكتبة من Rust | Using as a Rust library](#-استخدام-المكتبة-من-rust--using-as-a-rust-library)
* [🔗 الربط عبر C-ABI للغات الأخرى | Linking via C-ABI](#-الربط-عبر-c-abi-للغات-الأخرى--linking-via-c-abi)

---

## 🗺️ نبذة عن المشروع | Project Overview

**MKT\_KSA\_Geolocation\_Security**
مكتبة أمنية متقدمة للمدن الذكية، القطاعات السيادية، والشركات والمؤسسات التقنية.
تعتمد على التحقق الجغرافي، تحليل السلوك، بصمة الجهاز، الذكاء الاصطناعي، وبنية معيارية جاهزة للتخصيص والتوسيع – مع توثيق ثنائي اللغة لكل وحدة ووظيفة.

**MKT\_KSA\_Geolocation\_Security**
A smart Rust-based security library for smart cities, enterprises, and critical sectors.
It uses geolocation, behavioral analytics, device fingerprinting, and AI-driven modules, with modular design and bilingual documentation.

---

## 📂 الملفات الأساسية | Main Files

| اسم الملف                    | File Name            | المسار                           | Path                             | الدور (عربي)                  | Role (English)                                 |
| ---------------------------- | -------------------- | -------------------------------- | -------------------------------- | ----------------------------- | ---------------------------------------------- |
| main.rs                      | main.rs              | src/main.rs                      | src/main.rs                      | نقطة الدخول الرئيسية للتطبيق  | Main entry point, initializes server & modules |
| db/models.rs                 | models.rs            | src/db/models.rs                 | src/db/models.rs                 | هياكل بيانات قاعدة البيانات   | DB models                                      |
| db/crud.rs                   | crud.rs              | src/db/crud.rs                   | src/db/crud.rs                   | دوال قاعدة البيانات (CRUD)    | DB CRUD functions                              |
| db/mod.rs                    | mod.rs               | src/db/mod.rs                    | src/db/mod.rs                    | فهرس وحدة قاعدة البيانات      | DB module index                                |
| security/ratelimit.rs        | ratelimit.rs         | src/security/ratelimit.rs        | src/security/ratelimit.rs        | وحدة تحديد المعدل (DoS حماية) | Rate limiting module (DoS protection)          |
| security/input_validator.rs  | input_validator.rs   | src/security/input_validator.rs  | src/security/input_validator.rs  | أدوات التحقق للمدخلات         | Input validation tools                         |
| security/policy.rs           | policy.rs            | src/security/policy.rs           | src/security/policy.rs           | محرك السياسات الأمنية         | Policy engine                                  |
| security/jwt.rs              | jwt.rs               | src/security/jwt.rs              | src/security/jwt.rs              | إدارة رموز JWT               | JWT management                                 |
| security/mod.rs              | mod.rs               | src/security/mod.rs              | src/security/mod.rs              | فهرس وحدة الأمان              | Security module index                          |
| core/geo_resolver.rs         | geo_resolver.rs      | src/core/geo_resolver.rs         | src/core/geo_resolver.rs         | محرك الموقع الجغرافي          | Geolocation resolver engine                    |
| core/behavior_bio.rs         | behavior_bio.rs      | src/core/behavior_bio.rs         | src/core/behavior_bio.rs         | محرك التحليل السلوكي          | Behavioral analytics engine                    |
| core/device_fp.rs            | device_fp.rs         | src/core/device_fp.rs            | src/core/device_fp.rs            | بصمة الجهاز                   | Device fingerprinting                          |
| core/network_analyzer.rs     | network_analyzer.rs  | src/core/network_analyzer.rs     | src/core/network_analyzer.rs     | تحليل الشبكة وكشف التخفي      | Network analysis & concealment detection       |
| core/sensors_analyzer.rs     | sensors_analyzer.rs  | src/core/sensors_analyzer.rs     | src/core/sensors_analyzer.rs     | تحليل بيانات الحساسات         | Sensors data analysis engine                   |
| core/weather_val.rs          | weather_val.rs       | src/core/weather_val.rs          | src/core/weather_val.rs          | تدقيق بيانات الطقس            | Weather validation engine                      |
| core/cross_location.rs       | cross_location.rs    | src/core/cross_location.rs       | src/core/cross_location.rs       | محرك التحقق المتقاطع          | Cross-validation engine                        |
| core/history.rs              | history.rs           | src/core/history.rs              | src/core/history.rs              | إدارة وتحليل السجل التاريخي   | History management & anomaly detection         |
| core/mod.rs                  | mod.rs               | src/core/mod.rs                  | src/core/mod.rs                  | فهرس وحدة المحرك              | Core engine module index                       |
| api/auth.rs                  | auth.rs              | src/api/auth.rs                  | src/api/auth.rs                  | نقاط نهاية المصادقة           | Auth endpoints                                 |
| api/alerts.rs                | alerts.rs            | src/api/alerts.rs                | src/api/alerts.rs                | نقاط نهاية التنبيهات الأمنية  | Security alerts endpoints                      |
| api/geo.rs                   | geo.rs               | src/api/geo.rs                   | src/api/geo.rs                   | نقاط نهاية الموقع الجغرافي     | Geolocation endpoints                          |
| api/device.rs                | device.rs            | src/api/device.rs                | src/api/device.rs                | نقاط نهاية الجهاز             | Device endpoints                               |
| api/behavior.rs              | behavior.rs          | src/api/behavior.rs              | src/api/behavior.rs              | نقاط نهاية التحليل السلوكي     | Behavior analytics endpoints                    |
| api/network.rs               | network.rs           | src/api/network.rs               | src/api/network.rs               | نقاط نهاية تحليل الشبكة        | Network analysis endpoints                     |
| api/sensors.rs               | sensors.rs           | src/api/sensors.rs               | src/api/sensors.rs               | نقاط نهاية الحساسات           | Sensors endpoints                              |
| api/weather.rs               | weather.rs           | src/api/weather.rs               | src/api/weather.rs               | نقاط نهاية الطقس              | Weather endpoints                              |
| api/dashboard.rs             | dashboard.rs         | src/api/dashboard.rs             | src/api/dashboard.rs             | لوحة التحكم                   | Dashboard endpoints                            |
| api/smart_access.rs          | smart_access.rs      | src/api/smart_access.rs          | src/api/smart_access.rs          | نقطة وصول التحقق الذكي         | Smart access endpoint                          |
| api/mod.rs                   | mod.rs               | src/api/mod.rs                   | src/api/mod.rs                   | فهرس وحدة API                 | API module index                               |
| utils/mod.rs                 | mod.rs               | src/utils/mod.rs                 | src/utils/mod.rs                 | فهرس وحدة الأدوات المساعدة     | Utils module index                             |
| utils/helpers.rs             | helpers.rs           | src/utils/helpers.rs             | src/utils/helpers.rs             | دوال مساعدة عامة              | General helper functions                       |
| utils/logger.rs              | logger.rs            | src/utils/logger.rs              | src/utils/logger.rs              | وحدة التسجيل                  | Logger module                                  |
| utils/cache.rs               | cache.rs             | src/utils/cache.rs               | src/utils/cache.rs               | وحدة التخزين المؤقت           | Cache module                                   |
| Cargo.toml                   | Cargo.toml           | Cargo.toml                       | Cargo.toml                       | ملف التبعيات وإعداد المشروع   | Dependency management file                     |

---

## 🧩 الثوابت والدوال العامة | Constants & Public Functions

### 🔷 الثوابت | Constants

| اسم الثابت               | Constant Name            | القيمة الافتراضية | Default Value | مكان التعريف              | Defined In       |
| ------------------------ | ------------------------ | ----------------- | ------------- | ------------------------- | ---------------- |
| MAX_ACCURACY_THRESHOLD   | MAX_ACCURACY_THRESHOLD   | 50.0              | 50.0          | src/core/geo_resolver.rs  | geo_resolver.rs  |
| MIN_SIGNAL_STRENGTH      | MIN_SIGNAL_STRENGTH      | 30                | 30            | src/core/geo_resolver.rs  | geo_resolver.rs  |
| QUANTUM_SECURITY_LEVEL   | QUANTUM_SECURITY_LEVEL   | 90                | 90            | src/core/geo_resolver.rs  | geo_resolver.rs  |
| MAX_HISTORY_SIZE         | MAX_HISTORY_SIZE         | 100               | 100           | src/core/geo_resolver.rs  | geo_resolver.rs  |

---

### 🔷 الدوال العامة والهياكل | Public Functions & Main Structs

| اسم الدالة/الهيكل         | Function/Struct Name         | التوقيع / Signature                                      | مكان التعريف / Defined In           | الوصف (عربي)                       | Description (English)                       |
| ------------------------- | ---------------------------- | -------------------------------------------------------- | ----------------------------------- | ----------------------------------- | ------------------------------------------ |
| get_user_by_id            | get_user_by_id               | async fn get_user_by_id(pool, user_id)                   | src/db/crud.rs                      | جلب مستخدم من قاعدة البيانات        | Fetch user from DB                          |
| verify_smart_access       | verify_smart_access          | async fn verify_smart_access(...)                        | src/core/composite_verification.rs  | تحقق أمني مركب ذكي                  | Smart composite security check              |
| process                   | process                      | async fn process(input: BehaviorInput)                   | src/core/behavior_bio.rs            | تحليل سلوك المستخدم/الجهاز          | Analyze user/device behavior                |
| generate_fingerprint      | generate_fingerprint         | async fn generate_fingerprint(os, device, env)           | src/core/device_fp.rs               | توليد بصمة جهاز تكيفية              | Generate adaptive device fingerprint        |
| analyze                   | analyze                      | async fn analyze(provider: &dyn NetworkInfoProvider)      | src/core/network_analyzer.rs        | تحليل الشبكة وكشف أدوات التخفي       | Analyze network & detect concealment tools  |
| fetch_and_validate        | fetch_and_validate           | async fn fetch_and_validate(lat, lng)                    | src/core/weather_val.rs             | جلب وتدقيق بيانات الطقس              | Fetch & validate weather data               |
| validate                  | validate                     | async fn validate(input: CrossValidationInput)            | src/core/cross_location.rs          | تحقق متقاطع شامل                      | Full cross-validation                       |
| log_event                 | log_event                    | async fn log_event(event: &HistoryEvent)                  | src/core/history.rs                 | تسجيل حدث تاريخي                      | Log historical event                        |
| detect_timeline_anomalies | detect_timeline_anomalies    | async fn detect_timeline_anomalies(entity_id, window)     | src/core/history.rs                 | كشف شذوذ زمني في الأحداث              | Detect timeline anomalies                   |
| check                     | check                        | async fn check(ip)                                       | src/security/ratelimit.rs           | تحقق من معدل الطلبات                  | Rate limiting check                         |
| sign_location             | sign_location                | fn sign_location(location: &GeoLocation)                 | src/core/geo_resolver.rs            | توقيع بيانات الموقع رقمياً             | Digitally sign location data                |
| verify_signature          | verify_signature             | fn verify_signature(location: &GeoLocation)              | src/core/geo_resolver.rs            | تحقق من صحة التوقيع الرقمي              | Verify digital signature                    |
| config                    | config                       | fn config(cfg: &mut ServiceConfig)                       | src/api/mod.rs                      | تسجيل جميع مسارات API                  | Register all API routes                     |

---

### 🖊️ دوال التواقيع | Signing Module Functions

| اسم الدالة                | Function Name                 | التوقيع / Signature                                                | مكان التعريف / Defined In           | الوصف (عربي)                               | Description (English)                          |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------ | ----------------------------------- | ------------------------------------------- | --------------------------------------------- |
| sign_hmac_sha512          | sign_hmac_sha512             | fn sign_hmac_sha512(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs             | توقيع HMAC-SHA512 لبايتات البيانات          | HMAC-SHA512 signature over bytes               |
| verify_hmac_sha512        | verify_hmac_sha512           | fn verify_hmac_sha512(data: &[u8], sig: &[u8], key: &SecureBytes) -> bool            | src/security/signing.rs             | تحقق HMAC-SHA512                             | Verifies HMAC-SHA512                           |
| sign_hmac_sha384          | sign_hmac_sha384             | fn sign_hmac_sha384(data: &[u8], key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs             | توقيع HMAC-SHA384                            | HMAC-SHA384 signature                          |
| verify_hmac_sha384        | verify_hmac_sha384           | fn verify_hmac_sha384(data: &[u8], sig: &[u8], key: &SecureBytes) -> bool            | src/security/signing.rs             | تحقق HMAC-SHA384                             | Verifies HMAC-SHA384                           |
| sign_struct_excluding_field | sign_struct_excluding_field | fn sign_struct_excluding_field<T: Serialize>(value: &T, exclude_field: &str, key: &SecureBytes) -> Result<Vec<u8>, SigningError> | src/security/signing.rs | توقيع هيكل متسلسل مع استثناء حقل              | Sign serializable struct excluding one field   |
| verify_struct_excluding_field | verify_struct_excluding_field | fn verify_struct_excluding_field<T: Serialize>(value: &T, exclude_field: &str, sig: &[u8], key: &SecureBytes) -> bool | src/security/signing.rs | تحقق من هيكل متسلسل مع استثناء حقل            | Verify serializable struct excluding one field |

---

### ⏱️ دوال الدقة | Precision Module Functions

| اسم الدالة             | Function Name             | التوقيع / Signature                                                                 | مكان التعريف / Defined In      | الوصف (عربي)                                   | Description (English)                              |
| ---------------------- | ------------------------ | ----------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------- | ------------------------------------------------- |
| time_delta_secs        | time_delta_secs          | fn time_delta_secs(start: DateTime<Utc>, end: DateTime<Utc>) -> f64                 | src/utils/precision.rs         | فرق الزمن بالثواني (حماية من القيم السالبة)     | Time delta in seconds (with negative guard)        |
| time_delta_secs_high_res | time_delta_secs_high_res | fn time_delta_secs_high_res(start: DateTime<Utc>, end: DateTime<Utc>) -> f64       | src/utils/precision.rs         | فرق زمن عالي الدقة (ثوانٍ + نانوثوانٍ)         | High-resolution time delta (secs + nanos)          |
| avg_f32                | avg_f32                  | fn avg_f32(values: &[f32]) -> f32                                                  | src/utils/precision.rs         | متوسط f32 بتجميع داخلي f64                      | f32 average using internal f64 accumulation        |
| haversine_km           | haversine_km             | fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64                               | src/utils/precision.rs         | مسافة هافرسين بالكيلومترات                     | Haversine distance in kilometers                   |
| speed_kmh              | speed_kmh                | fn speed_kmh(distance_km: f64, seconds: f64) -> f64                                | src/utils/precision.rs         | سرعة كم/س مع حماية القسمة على صفر               | Speed (km/h) with division-by-zero guard           |
| weighted_sum_f64       | weighted_sum_f64         | fn weighted_sum_f64(values: &[f64], weights: &[f64]) -> Option<f64>               | src/utils/precision.rs         | مجموع موزون f64 (يرجع None عند عدم التطابق)    | Weighted sum (f64), None if lengths mismatch       |
| rate_of_change_f64     | rate_of_change_f64       | fn rate_of_change_f64(value_delta: f64, seconds: f64) -> f64                       | src/utils/precision.rs         | معدل التغير (قيمة/ثانية) مع حماية القسمة        | Rate of change per second with zero-division guard |
### 🔷 الواجهات (Traits) الرئيسية | Main Traits

| اسم الواجهة              | Trait Name                | التوقيع / Signature                        | مكان التعريف / Defined In           | الوصف (عربي)                       | Description (English)                       |
| ------------------------ | ------------------------- | ------------------------------------------ | ----------------------------------- | ----------------------------------- | ------------------------------------------ |
| AiModel                  | AiModel                   | trait AiModel: detect_fraud, analyze_movement, ... | src/core/geo_resolver.rs            | واجهة نماذج الذكاء الاصطناعي للموقع    | AI models for geolocation                   |
| Blockchain               | Blockchain                | trait Blockchain: store_location, verify_location, ... | src/core/geo_resolver.rs            | واجهة تكامل البلوكشين                  | Blockchain integration                      |
| BehavioralModel          | BehavioralModel           | trait BehavioralModel: analyze              | src/core/behavior_bio.rs            | واجهة نماذج تحليل السلوك                | Behavioral analysis models                  |
| AnomalyDetector          | AnomalyDetector           | trait AnomalyDetector: detect               | src/core/behavior_bio.rs            | واجهة كشف الشذوذ السلوكي                | Behavioral anomaly detection                |
| SecurityMonitor          | SecurityMonitor           | trait SecurityMonitor: scan_environment, ... | src/core/device_fp.rs               | مراقبة أمان الجهاز                      | Device security monitoring                  |
| QuantumEngine            | QuantumEngine             | trait QuantumEngine: get_secure_key, ...    | src/core/device_fp.rs               | محرك التشفير ما بعد الكم                | Post-quantum crypto engine                  |
| AiProcessor              | AiProcessor               | trait AiProcessor: generate_ai_signature    | src/core/device_fp.rs               | معالجة الذكاء الاصطناعي للبصمة          | AI processor for fingerprinting             |
| NetworkInfoProvider      | NetworkInfoProvider       | trait NetworkInfoProvider: get_connection_type, ... | src/core/network_analyzer.rs        | مزود معلومات الشبكة                    | Network info provider                       |
| AiNetworkAnalyzer        | AiNetworkAnalyzer         | trait AiNetworkAnalyzer: analyze            | src/core/network_analyzer.rs        | محلل الشبكة بالذكاء الاصطناعي           | AI network analyzer                         |
| SensorAnomalyDetector    | SensorAnomalyDetector     | trait SensorAnomalyDetector: analyze        | src/core/sensors_analyzer.rs        | كشف شذوذ بيانات الحساسات                | Sensor anomaly detection                    |
| WeatherProvider          | WeatherProvider           | trait WeatherProvider: get_weather, ...     | src/core/weather_val.rs             | مزود بيانات الطقس                       | Weather data provider                       |
| ScoringStrategy          | ScoringStrategy           | trait ScoringStrategy: calculate_score      | src/core/cross_location.rs          | استراتيجية حساب درجة الثقة              | Trust scoring strategy                      |

---

## 🔑 نقاط النهاية (API) والإعداد | Config & Endpoints

### 🧾 مفاتيح البيئة والإعداد (.env / config)

| اسم المفتاح   | Key Name      | الدور                  | Role                    | مثال                       | Example |
| ------------- | ------------- | ---------------------- | ----------------------- | -------------------------- | ------- |
| API_KEY      | API_KEY      | مفتاح المصادقة الرئيسي | Main authentication key | API_KEY=your_secret_key |         |
| JWT_SECRET   | JWT_SECRET   | سر توقيع/تحقق JWT      | JWT signing/verification secret | JWT_SECRET=32+_chars_secret |         |
| DATABASE_URL | DATABASE_URL | رابط قاعدة البيانات    | DB connection string    | DATABASE_URL=mysql://...  |         |
| LOG_LEVEL    | LOG_LEVEL    | مستوى السجلات          | Logging verbosity       | LOG_LEVEL=debug           |         |
| GEO_PROVIDER | GEO_PROVIDER | مزود الموقع (اختياري)  | Geolocation provider    | GEO_PROVIDER=ipapi        |         |

---

### 🌐 نقاط النهاية (API Endpoints)

| المسار              | Path                  | نوع الطلب | Method | الدور (عربي)                  | Role (English)                  | التعريف / Defined In         |
| ------------------- | --------------------- | --------- | ------ | ----------------------------- | ------------------------------- | ---------------------------- |
| /api/auth/login     | /api/auth/login       | POST      | POST   | تسجيل دخول                    | User login                      | src/api/auth.rs              |
| /api/auth/user      | /api/auth/user        | GET       | GET    | جلب بيانات مستخدم             | Fetch user data                 | src/api/auth.rs              |
| /api/alerts/trigger | /api/alerts/trigger   | POST      | POST   | إطلاق تنبيه أمني              | Trigger security alert          | src/api/alerts.rs            |
| /api/geo/resolve    | /api/geo/resolve      | POST      | POST   | تحليل الموقع الجغرافي         | Geolocation resolve             | src/api/geo.rs               |
| /api/device/resolve | /api/device/resolve   | POST      | POST   | تحليل/تسجيل الجهاز            | Device resolve/register         | src/api/device.rs            |
| /api/behavior/analyze| /api/behavior/analyze| POST      | POST   | تحليل السلوك                   | Behavior analysis               | src/api/behavior.rs          |
| /api/network/analyze| /api/network/analyze  | POST      | POST   | تحليل الشبكة                   | Network analysis                | src/api/network.rs           |
| /api/sensors/analyze| /api/sensors/analyze  | POST      | POST   | تحليل بيانات الحساسات          | Sensors data analysis           | src/api/sensors.rs           |
| /api/weather/summary| /api/weather/summary  | GET       | GET    | ملخص بيانات الطقس              | Weather summary                 | src/api/weather.rs           |
| /api/dashboard      | /api/dashboard        | GET       | GET    | ملخص لوحة التحكم               | Dashboard summary               | src/api/dashboard.rs         |
| /api/smart_access   | /api/smart_access     | POST      | POST   | تحقق وصول ذكي مركب             | Smart composite access check    | src/api/smart_access.rs      |

---

## 🧭 البنية المعمارية | Project Architecture

```mermaid
graph TD
    A[main.rs 🧩\nEntry] --> B[API Layer 🌐]
    A --> C[Core Engines 🧠]
    A --> D[DB Layer 🗄️]
    B -->|Endpoints| E[🔓 /auth, /alerts, /users, ...]
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
    B --> P[Security Layer 🔐]
    P --> Q[InputValidator 📥]
    P --> R[JWT Manager 🔑]
    P --> S[Policy Engine ⚖️]
    P --> T[RateLimiter 🚦]
```

> 🎯 **الوصف:**
> يوضح المخطط تداخل الوحدات الرئيسة (API، المحرك الأساسي، قاعدة البيانات، طبقة الأمان) مع إبراز المحركات الجديدة (تحليل الحساسات، الطقس، التحقق المتقاطع، السجل التاريخي) وصولاً لطبقة التحقق الأمني المركب الذكي.
> 
> **Description:**
> The diagram shows the interaction of main units (API, core engine, DB, security layer) highlighting new engines (sensors, weather, cross-validation, history) up to the smart composite security layer.

---

## 🛠️ أمثلة التحقق العملي | Practical Verification Examples

### تحقق أمني مركب | Full Composite Security Check

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

### تحقق من الموقع الجغرافي فقط | Geo Verification Only

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

### تحقق من السلوك فقط | Behavior Verification Only

```rust
let behavior_result = behavior_engine.process(behavior_input).await?;
if behavior_result.risk_level as u8 < 3 {
    // السلوك طبيعي | Low risk behavior
} else {
    // السلوك مشبوه | Medium or high risk behavior
}
```

---

### تحقق من الجهاز فقط | Device Verification Only

```rust
let device_fp = device_fp_engine.generate_fingerprint(os, device, env).await?;
if device_fp.security_level >= 5 {
    // الجهاز موثوق | Device is trusted
} else {
    // الجهاز غير موثوق | Device is not trusted
}
```

---

### تحقق من الصلاحيات فقط | Role Verification Only

```rust
let role_row: Option<Row> = mysql_async::prelude::Queryable::exec_first(
    &mut conn, "SELECT role FROM user_roles WHERE user_id = ? AND role = ?",
    (user_id.to_string(), "admin"),
).await?;
if role_row.is_some() {
    // للمستخدم الصلاحية المطلوبة | User has required role
} else {
    // ليس لديه الصلاحية | User lacks required role
}
```

---

## ⚙️ وحدات المحرك الأساسية | Core Engine Modules

### 🕓 وحدة السجل التاريخي | History Service

- **الوصف:** إدارة وتخزين وتحليل الأحداث والسلوكيات التاريخية للمستخدمين والأجهزة، مع دعم كشف الشذوذ الزمني والتكامل مع قاعدة البيانات.
- **Description:** Manages, stores, and analyzes historical events and behaviors for users/devices, with anomaly detection and DB integration.
- **أهم الدوال:** log_event, get_entity_history, detect_timeline_anomalies

---

### 🔄 وحدة التحقق المتقاطع | Cross-Validation Engine

- **الوصف:** محرك تنسيق متقدم يجمع نتائج محركات التحقق (الموقع، السلوك، الجهاز...) ليصدر حكمًا نهائيًا موثوقًا وموقعًا رقمياً.
- **Description:** Advanced orchestrator combining results from verification engines (geo, behavior, device, etc.) to issue a final, signed verdict.
- **أهم الدوال:** validate, sign_verdict

---

### 📡 وحدة تحليل الحساسات | Sensors Analyzer

- **الوصف:** تحليل بيانات الحساسات (مثل التسارع، الجيروسكوب) للكشف عن الشذوذ أو التلاعب، مع إصدار شهادة تحليل موقعة رقمياً.
- **Description:** Analyzes sensor data (e.g., accelerometer, gyroscope) for anomalies/tampering, issuing a digitally signed analysis certificate.
- **أهم الدوال:** analyze (SensorsAnalyzerEngine)

---

### ☁️ وحدة الطقس والتحقق | Weather Validation

- **الوصف:** تجميع وتدقيق بيانات الطقس من مزودين متعددين، مع مقارنة النتائج وتقديم بيانات موحدة وموثوقة.
- **Description:** Aggregates and validates weather data from multiple providers, comparing results and providing unified, reliable data.
- **أهم الدوال:** fetch_and_validate (WeatherEngine)

---

## ⚠️ تقرير فحص التبعيات | Dependency Audit

| التبعية              | Dependency         | النوع | Type         | مباشر؟ | Direct? | غير مباشر؟ | Indirect? | ملاحظات أمنية/تصنيف | Security/Category Notes |
|--------------------- |-------------------|-------|--------------|--------|---------|------------|-----------|----------------------|------------------------|
| actix-web            | actix-web         | خارجي | External     | نعم    | Yes     | لا         | No        | إطار ويب رئيسي (Web) | Main web framework     |
| actix-rt             | actix-rt          | خارجي | External     | نعم    | Yes     | لا         | No        | تشغيل غير متزامن     | Async runtime          |
| ammonia              | ammonia           | خارجي | External     | نعم    | Yes     | لا         | No        | تعقيم HTML           | HTML sanitization      |
| anyhow               | anyhow            | خارجي | External     | نعم    | Yes     | لا         | No        | إدارة الأخطاء        | Error handling         |
| async-trait          | async-trait       | خارجي | External     | نعم    | Yes     | لا         | No        | دعم async للـtraits   | Async trait support    |
| config               | config            | خارجي | External     | نعم    | Yes     | لا         | No        | إدارة الإعدادات      | Config management      |
| futures              | futures           | خارجي | External     | نعم    | Yes     | لا         | No        | أدوات البرمجة غير المتزامنة | Async utilities |
| log                  | log               | خارجي | External     | نعم    | Yes     | لا         | No        | تسجيل                | Logging                |
| mysql_async          | mysql_async       | خارجي | External     | نعم    | Yes     | لا         | No        | قاعدة بيانات         | Database (MySQL)       |
| tokio                | tokio             | خارجي | External     | نعم    | Yes     | لا         | No        | تشغيل غير متزامن     | Async runtime          |
| uuid                 | uuid              | خارجي | External     | نعم    | Yes     | لا         | No        | معرفات فريدة         | UUIDs                  |
| aes-gcm              | aes-gcm           | خارجي | External     | نعم    | Yes     | لا         | No        | تشفير متقدم          | Advanced encryption    |
| secrecy              | secrecy           | خارجي | External     | نعم    | Yes     | لا         | No        | إدارة أسرار آمنة     | Secure secret handling |
| zeroize              | zeroize           | خارجي | External     | نعم    | Yes     | لا         | No        | مسح آمن للذاكرة      | Secure memory zeroing  |
| hex                  | hex               | خارجي | External     | نعم    | Yes     | لا         | No        | تحويلات هيكس         | Hex encoding/decoding  |
| hmac                 | hmac              | خارجي | External     | نعم    | Yes     | لا         | No        | توقيع HMAC           | HMAC signatures        |
| sha2                 | sha2              | خارجي | External     | نعم    | Yes     | لا         | No        | تجزئة SHA2           | SHA2 hashing           |
| blake3               | blake3            | خارجي | External     | نعم    | Yes     | لا         | No        | تجزئة BLAKE3         | BLAKE3 hashing         |
| base64               | base64            | خارجي | External     | نعم    | Yes     | لا         | No        | ترميز Base64         | Base64 encoding        |
| jsonwebtoken         | jsonwebtoken      | خارجي | External     | نعم    | Yes     | لا         | No        | JWT                  | JWT tokens             |
| pqcrypto-mlkem       | pqcrypto-mlkem    | خارجي | External     | نعم    | Yes     | لا         | No        | تشفير ما بعد الكم     | Post-quantum crypto    |
| unicode-normalization| unicode-normalization| خارجي| External    | نعم    | Yes     | لا         | No        | تطبيع يونيكود        | Unicode normalization  |
| validator            | validator         | خارجي | External     | نعم    | Yes     | لا         | No        | تحقق من المدخلات      | Input validation       |
| regex                | regex             | خارجي | External     | نعم    | Yes     | لا         | No        | تعبيرات منتظمة        | Regex                  |
| getrandom            | getrandom         | خارجي | External     | لا     | No      | نعم        | Yes       | توليد أرقام عشوائية (عبر rand::OsRng) | Random number generation (via rand::OsRng) |
| lru                  | lru               | خارجي | External     | نعم    | Yes     | لا         | No        | كاش LRU              | LRU cache              |
| rayon                | rayon             | خارجي | External     | نعم    | Yes     | لا         | No        | معالجة متوازية        | Parallel processing    |
| once_cell            | once_cell         | خارجي | External     | نعم    | Yes     | لا         | No        | تهيئة لمرة واحدة      | One-time initialization |
| lazy_static          | lazy_static       | خارجي | External     | نعم    | Yes     | لا         | No        | ثوابت ساكنة          | Static constants       |
| cfg-if               | cfg-if            | خارجي | External     | نعم    | Yes     | لا         | No        | تفعيل مشروط          | Conditional compilation |
| rand                 | rand              | خارجي | External     | نعم    | Yes     | لا         | No        | توليد أرقام عشوائية   | Random number generation|
| chrono               | chrono            | خارجي | External     | نعم    | Yes     | لا         | No        | تواريخ وأوقات         | Date/time handling     |
| serde_json           | serde_json        | خارجي | External     | نعم    | Yes     | لا         | No        | JSON                  | JSON                   |
| reqwest              | reqwest           | خارجي | External     | نعم    | Yes     | لا         | No        | طلبات HTTP            | HTTP requests (Rustls) |
| serde                | serde             | خارجي | External     | نعم    | Yes     | لا         | No        | تسلسل/إلغاء تسلسل     | Serialization          |
| serde_derive         | serde_derive      | خارجي | External     | نعم    | Yes     | لا         | No        | اشتقاق Serde          | Serde derive           |
| thiserror            | thiserror         | خارجي | External     | نعم    | Yes     | لا         | No        | أخطاء مخصصة           | Custom errors          |
| maxminddb            | maxminddb         | خارجي | External     | نعم    | Yes     | لا         | No        | قاعدة بيانات GeoIP     | GeoIP database         |
| pqcrypto-traits      | pqcrypto-traits   | خارجي | External     | نعم    | Yes     | لا         | No        | واجهات تشفير ما بعد الكم| Post-quantum crypto traits |
| proptest             | proptest          | dev   | Dev          | نعم    | Yes     | لا         | No        | اختبارات ملكية        | Property-based testing |
| rstest               | rstest            | dev   | Dev          | نعم    | Yes     | لا         | No        | اختبارات سيناريو      | Scenario-based testing |
| assert-json-diff     | assert-json-diff  | dev   | Dev          | نعم    | Yes     | لا         | No        | مقارنة JSON           | JSON diff assertions   |

**ملاحظات الاستقرار (تحديث):**
- تاريخ التحديث: 14 أغسطس 2025
- تم ضبط تبعية `anyhow` بدقة إلى `1.0.99`.
- ترقية التبعيات: `base64 0.22.1`, `lru 0.16.0`, `maxminddb 0.26.0`, `reqwest 0.12.22`, `thiserror 2.0.12`, `uuid 1.18.0`.
- إضافة `categories` و`keywords` في `Cargo.toml`.
- استخدام `JWT_SECRET` كسرّ JWT بدلاً من قيمة ثابتة.
- لا تغييرات وظيفية؛ جميع الاختبارات ما زالت تمر.

**Security Notes:**
- All dependencies are carefully selected, with no reliance on OpenSSL (all crypto is Rust-native or Rustls).
- It is recommended to run `cargo audit` and `cargo update` regularly.

---

## ✅ نتائج الاختبار | Test Results

```bash
running 35 tests
... all tests passed ...

test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.04s
```

* ✅ كل الاختبارات نجحت (35 اختبارًا).

---

## 🔒 استقرار الإصدار الحالي | Current Release Stability

- **الأداة/البيئة:** Stable Rust 1.89.0 (Windows MSVC)، مع تهيئة `$env:CARGO_HOME` و`$env:RUSTUP_HOME`.
- **البناء:** `cargo check` ناجح.
- **الاختبارات:** `cargo test` ناجحة بالكامل (35/35) بعد جعل اختبار غير حتمي حتمياً عبر طابع زمني ثابت، دون تغيير أي منطق.
- **التنسيق:** `cargo fmt --check` نظيف.
- **اللينتر:** `cargo clippy` يحتوي تحذيرات غير حرجة فقط (imports/variables غير مستخدمة واقتراحات تحسين)، لا تغيّر السلوك.
- **الأمان:** `cargo audit` لا ثغرات معروفة.
- **الملاحظة التشغيلية:** وحدة `RateLimiter` موجودة وغير مفعّلة افتراضياً لحين قرار لاحق.

---

## ⬆️ خطة ترقية التبعيات بالكامل | Full Dependency Upgrade Plan

### النطاق
- التبعيات ذات الإصدارات الأحدث المتاحة: `base64 (0.22)`, `getrandom (0.3)`, `lru (0.16)`, `maxminddb (0.26)`, `rand (0.9)`, `reqwest (0.12)`, `rstest (0.26)`, `secrecy (0.10)`, `thiserror (2)`.

### السياسة
- بدون كسر توافق عام: الترقية على مراحل، مع بناء واختبارات و`audit/clippy/fmt` بعد كل مرحلة.
- عدم تغيير واجهات المكتبة العامة في هذا المسار؛ أي تغييرات كاسرة تؤجل لإصدار رئيسي.

### المراحل
1) thiserror 2 → تحقق وبناء واختبارات.
2) secrecy 0.10 → تحقق تكامل مع `zeroize` وواجهات الأسرار.
3) reqwest 0.12 + rustls متوافق → مراجعة API البسيطة إن وجدت.
4) maxminddb 0.26 → تحديثات API طفيفة إن لزم، مع اختبار GeoIP.
5) rand 0.9 + getrandom 0.3 → مراجعة نقاط التوليد العشوائي.
6) base64 0.22 → تحديث استدعاءات الترميز/الفك إن تغيّر API.
7) lru 0.16 → مراجعة الإنشاء والسمات.
8) rstest 0.26 (dev) → تحديث وسوم الاختبار إن لزم.

### ضمانات
- تشغيل CI كامل: `check`, `test`, `fmt`, `clippy`, `audit` في كل مرحلة.
- توثيق نتائج كل مرحلة ضمن ملاحظات الإصدار قبل الدمج.

## ⭐ مزايا المشروع والفئات المستهدفة | Features & Target Audiences

### 🎯 هدف المكتبة وقوتها الأمنية | Library Purpose & Security Strength

- **هدف المكتبة:**
  - تقديم منصة تحقق أمني ذكية متكاملة للمدن الذكية، الجهات السيادية، المؤسسات المالية، وشركات التقنية، مع دعم كامل للتخصيص والتكامل.
  - تم تصميمها لتكون معيارًا للأمان الجغرافي والسلوكي في البيئات عالية الحساسية، مع قابلية التوسع والدمج في أي نظام حديث.
- **قوة الأمان:**
  - تعتمد المكتبة على بنية معيارية متعددة الطبقات، تجمع بين التحقق الجغرافي، التحليل السلوكي، بصمة الجهاز، تحليل الشبكة، كشف التلاعب، التحقق المتقاطع، وتدقيق الطقس والحساسات.
  - جميع العمليات مدعومة بتشفير متقدم (AES-GCM, HMAC, Post-Quantum)، إدارة أسرار آمنة (secrecy, zeroize)، وتوقيعات رقمية.
  - لا تعتمد على OpenSSL، وتستخدم فقط مكتبات Rust آمنة وحديثة.
  - تدعم سياسات المدن الذكية، كشف أدوات التخفي (VPN/Proxy/Tor)، وتوفر سجل تاريخي وتحليل شذوذ زمني.

---

### 🏆 المزايا الرئيسية | Main Features

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

### 👤 الفئات المستهدفة | Target Audiences

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

### 💎 نقاط التميز | Unique Selling Points

* **تحقق مركب يجمع بين الموقع والسلوك والجهاز والشبكة في قرار واحد**
* **دعم مصادر جغرافية متعددة (GPS, IP, SIM, Satellite, Indoor, AR)**
* **حقن أي منطق ذكاء اصطناعي أو تعلم آلي بسهولة**
* **كشف متقدم لأدوات التخفي (VPN/Proxy/Tor)**
* **دعم كامل لمدن ومؤسسات كبرى – Plug & Play**
* **توثيق ثنائي اللغة وواجهة برمجية مرنة للمطورين**

---

## 🧠 دليل المطور | Developer Guide

### 🚀 خطوات التكامل الأساسي | Basic Integration Steps

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

#### 🔌 أعلام الميزات | Feature Flags

#### يدعم هذا الصندوق علامات الميزات المتقدمة لتنشيط الإمكانات المتخصصة.
#### يمكنك تمكينها عبر مثل هذا:Cargo.toml

#### [dependencies]
#### MKT_KSA_Geolocation_Security = { version = "1.0.0", features = ["adaptive", "quantum"] }    

| Feature Name          | Description                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `adaptive`            | Enables AI-driven adaptive behavior analysis.                                                |
| `ar_integration`      | Integrates Augmented Reality (AR) sources for enhanced location validation.                  |
| `autonomous_vehicles` | Activates modules designed for autonomous cars and smart fleet systems.                      |
| `blockchain`          | Supports blockchain-based authentication and data anchoring.                                 |
| `generative_ai`       | Uses generative AI models to dynamically generate and adjust security policies.              |
| `gpu`                 | Enables GPU acceleration for heavy analysis (e.g. sensor or network data).                   |
| `predictive`          | Adds predictive modeling and anomaly detection based on behavioral patterns.                 |
| `quantum`             | Activates modules compatible with post-quantum cryptography.                                 |
| `quantum_computing`   | Enables integrations with quantum computing backends and processors.                         |
| `v1_1`                | Enables compatibility with API version 1.1 for legacy support.                               |
| `v2_0`                | Enables compatibility with API version 2.0 (default for most modules).                       |
| `v3_0`                | Enables next-gen modules for upcoming API version 3.0.                                       |
| `zkp`                 | Adds support for Zero-Knowledge Proofs for privacy-preserving validation and access control. |

---

## 📦 استخدام المكتبة من Rust | Using as a Rust library

```toml
[dependencies]
MKT_KSA_Geolocation_Security = "1.0.2" # اسم الاستدعاء داخل الشيفرة: mkt_ksa_geo_sec
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

## 🔗 الربط عبر C-ABI للغات الأخرى | Linking via C-ABI

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

#### 💡 نصائح متقدمة | Advanced Tips

* جميع المحركات قابلة للحقن أو الاستبدال
* حرية تخصيص كاملة (الجلسة/الجهاز/الدور)
* أمثلة ودوال وثوابت كلها موثقة عربي/إن

---

## 📝 ملاحظات الإصدار v1.0.2 | Release Notes v1.0.2

- **المستوى/Severity**: منخفض إلى متوسط – تحسينات جودة وكود وتنظيف لِنتر دون تغييرات سلوكية عامة.
- **إصلاحات رئيسية (عربي/English):**
  - تطبيق كامل وصارم لـ Clippy مع -D warnings على جميع الأهداف، وتنظيف كل التحذيرات. | Full, strict Clippy pass with -D warnings; all warnings cleaned.
  - توحيد أنماط استخراج JWT من الهيدر في طبقة API واستخدام let-else حيث يلزم. | Unified JWT extraction patterns in API and used let-else where appropriate.
  - إضافة #[allow(...)] موضعي فقط حيث قد يؤثر التغيير على واجهات عامة أو منطق استدعاء قائم. | Localized #[allow(...)] only where API/behavior preservation is critical.
  - توثيق #Errors/#Panics في دوال نتيجة ومواضع حرجة. | Added #Errors/#Panics docs in critical Result-returning functions.
  - تحسينات Floating-Point وsuboptimal_flops بتمكين/تكميم انتقائي دون تغيير السلوك. | Addressed floating-point hints with targeted allows without behavior changes.
  - إصلاح تحذيرات unused_async/unused_self في دوال داخلية وتجريبية. | Fixed unused_async/unused_self in internal/experimental functions.
  - ضمان عدم تغيير الواجهات العامة، وعدم حذف أي منطق أو ملفات. | Guaranteed no public API changes or logic/file removals.
- **الاختبارات/Tests**: 37/37 ناجحة. | 37/37 tests passing.
- **Clippy**: نظيف بالكامل. | Fully clean.
- **التبعيات/Dependencies**:
  - لم يتم تغيير نسخ الحزم الإنتاجية. | No production dependency versions changed.
  - ملاحظة: توجد نسخ مزدوجة لبعض الحزم بشكل ترانزيتيف (مثل base64/http/lru/windows-sys)، إبقاؤها كان مقصودًا لتجنب كسر التوافق. | Note: some duplicate transitive versions remain; intentionally kept to avoid breaking changes.
  - cargo audit: تحذير مسموح لحزمة `rust-ini` (yanked) عبر `config`؛ لا يؤثر وظيفيًا (اعتماد ترانزيتيف فقط)؛ موثّق للمراجعة اللاحقة. | cargo audit: allowed warning for `rust-ini` (yanked) via `config`; non-functional impact (transitive only); documented for later review.

#### 🔄 تغييرات التبعيات (هذه الجلسة) | Dependency Changes (this session)
- **تمت الإزالة | Removed**:
  - `once_cell`, `lazy_static`: استُبدلت باستعمال `std::sync::LazyLock`. | Replaced by `std::sync::LazyLock`.
  - `serde_derive`: غير لازمة لأن `serde` مفعّل بميزة `derive`. | Redundant since `serde` has `derive` feature enabled.
  - `getrandom` (مباشر): أزيلت كتبعّية مباشرة، والآن نستخدم `rand::rngs::OsRng::try_fill_bytes` لتوليد البايتات العشوائية بشكل قياسي وآمن. | Removed direct `getrandom` dep; switched to `rand::rngs::OsRng::try_fill_bytes`.
- **تم التحديث | Updated**:
  - `reqwest`: 0.12.22 → 0.12.23 (Rustls, تصحيحات طفيفة). | minor patch with Rustls.
  - `pqcrypto-mlkem`: 0.1.0 → 0.1.1.
  - `secrecy`: 0.8.x → 0.10.3. تم إدخال أغلفة داخلية `security::secret::{SecureString, SecureBytes}` لعزل تغييرات API. تم تحديث جميع مواقع الاستدعاء دون تغيير المنطق أو مستوى الأمان.
- **تعديلات ترانزيتيف | Transitive adjustments**:
  - `async-trait`، `hyper`، `thiserror`، وغيرها تَحدّثت تلقائياً ضمن القيود. | auto-updated within constraints.

#### 🆕 ملفات أُنشئت | New Files Created
- `src/security/signing.rs`: وحدة توقيعات/HMAC مركزية عالية الأمان (بدون OpenSSL). | Central high-security HMAC signing module (no OpenSSL).
- `src/utils/precision.rs`: وحدة دقة للأزمنة والحسابات العددية/الجغرافية. | Precision utilities for time/numeric/geo.

### 🔧 تغييرات التواقيع الداخلية (دون تأثير على المنطق/المسارات) | Internal Signature Changes (no behavior/route changes)

- **طبقة API** (`src/api/*.rs`):
  - اعتماد extractors بدل `HttpRequest`: استخدام `web::Data<AppState>`, `web::Json<...>`, و`BearerToken` لتأمين الـ futures (Send-safe) وتنظيف التواقيع.
- **محرك الجغرافيا** (`src/core/geo_resolver.rs`):
  - الدالة `resolve` تستقبل الآن `ResolveParams` بدل قائمة معاملات طويلة؛ تم تحديث جميع مواقع الاستدعاء.
- **التحليل السلوكي** (`src/core/behavior_bio.rs`):
  - `get_user_profile_data` أصبحت متزامنة (تمت إزالة `async` لعدم وجود `await`)، وتم تحديث الاستدعاء في `src/api/auth.rs` (إزالة `.await`).
- **بصمة الجهاز/FFI** (`src/core/device_fp.rs`):
  - دوال الربط C أصبحت `unsafe extern "C"` مع توثيق `# Safety`، دون تغيير منطق التنفيذ.

#### 📑 مرجع التواقيع الحالية | Current Signatures Reference

- **واجهات API | API Handlers**

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

pub async fn dashboard_summary(bearer: BearerToken) -> impl Responder;

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

- **النواة | Core**

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

- **سطح FFI (توافق C) | FFI Surface (C ABI)**

```rust
pub unsafe extern "C" fn generate_adaptive_fingerprint(
    os: *const c_char,
    device_info: *const c_char,
    env_data: *const c_char,
) -> *mut c_char;

pub unsafe extern "C" fn free_fingerprint_string(ptr: *mut c_char);
```

### 🧹 تنسيق وفحوص إضافية | Formatting and Extra Checks
- تم تطبيق `cargo fmt --all` لتنظيف الفروقات التنسيقية التي أظهرها `--check`.
- نتائج `cargo tree -d` تُظهر ازدواجيات ترانزيتيف مقبولة حالياً: `base64 (0.21/0.22)`, `http (0.2/1.x)`, `lru (0.14/0.16)`, `hashbrown (0.14/0.15)`, `socket2 (0.5/0.6)`, `windows-sys (0.52/0.59)`.

---

```
