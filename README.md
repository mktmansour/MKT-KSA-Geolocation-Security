<h1 align="center">
  🛡️🌍 مشروع مكتبة التحقق الجغرافي والأمني السعودي<br>
  <strong>MKT_KSA_Geolocation_Security</strong>
</h1>

<p align="center">
  🛰️ Rust-based | 🇸🇦 Smart Security | 🔐 AI-Driven | 📡 Geolocation Verification | 🏙️ Smart City Ready
</p>

<p align="center">
  📄 رخصة: Apache 2.0 — مفتوح المصدر مع شرط الإسناد | 🧠 المطور: منصور بن خالد
</p>

---

## 📘 المحتويات | Table of Contents

- 📌 [نبذة عن المشروع | Project Overview](#-نبذة-عن-المشروع--project-overview)
- 📂 [الملفات الأساسية | Main Files](#-الملفات-الأساسية--main-files)
- 🧩 [الثوابت والدوال | Constants & Functions](#-الثوابت-والدوال--constants--functions)
- 🔑 [المفاتيح ونقاط النهاية | Config & Endpoints](#-المفاتيح-ونقاط-النهاية--config--endpoints)
- 🧭 [البنية المعمارية | Architecture](#-البنية-المعمارية--architecture)
- 🛠️ [أمثلة التحقق | Verification Examples](#-أمثلة-التحقق--verification-examples)
- ⚠️ [تقرير التبعيات | Dependency Audit](#-تقرير-التبعيات--dependency-audit)
- ✅ [نتائج الاختبار | Test Results](#-نتائج-الاختبار--test-results)
- ⭐ [مزايا المشروع | Features](#-مزايا-المشروع--features)
- 🧠 [دليل المطور | Developer Guide](#-دليل-المطور--developer-guide)
- 📈 [ملخص الحالة الفنية | System State](#-ملخص-الحالة-الفنية--system-state)

---

## 🗺️ نبذة عن المشروع | Project Overview

**MKT_KSA_Geolocation_Security**  
مكتبة أمنية ذكية بلغة Rust للمدن الذكية، المؤسسات، والجهات السيادية.  
تعتمد على التحقق الجغرافي، تحليل السلوك، بصمة الجهاز، والتكامل مع الذكاء الاصطناعي، مع بنية معيارية وتوثيق ثنائي اللغة.

**MKT_KSA_Geolocation_Security**  
is a smart security library in Rust for smart cities, enterprises, and critical sectors.  
It uses geolocation, behavioral analytics, device fingerprinting, and AI-powered modules, with modular design and bilingual documentation.

---

## 📂 الملفات الأساسية | Main Files

| اسم الملف             | File Name         | المسار            | Path                      | الدور (عربي)                               | Role (English)                                 |
|-----------------------|------------------|-------------------|---------------------------|----------------------------------------------|------------------------------------------------|
| main.rs               | main.rs          | src/main.rs       | src/main.rs               | نقطة الدخول الرئيسية للتطبيق                | Main entry point, initializes server & modules |
| db/models.rs          | models.rs        | src/db/models.rs  | src/db/models.rs          | هياكل البيانات (الجداول)                    | DB models                                      |
| db/crud.rs            | crud.rs          | src/db/crud.rs    | src/db/crud.rs            | دوال قاعدة البيانات (CRUD)                  | DB CRUD functions                              |
| security/ratelimit.rs | ratelimit.rs     | src/security/ratelimit.rs | src/security/ratelimit.rs | وحدة تحديد المعدل (DoS حماية)             | Rate limiting module (DoS protection)          |
| core/geo_resolver.rs  | geo_resolver.rs  | src/core/geo_resolver.rs | src/core/geo_resolver.rs  | محرك الموقع الجغرافي                        | Geolocation resolver engine                    |
| core/behavior_bio.rs  | behavior_bio.rs  | src/core/behavior_bio.rs | src/core/behavior_bio.rs  | محرك التحليل السلوكي                        | Behavioral analytics engine                    |
| core/device_fp.rs     | device_fp.rs     | src/core/device_fp.rs    | src/core/device_fp.rs     | بصمة الجهاز                                 | Device fingerprinting                          |
| api/auth.rs           | auth.rs          | src/api/auth.rs   | src/api/auth.rs           | نقاط نهاية المصادقة                         | Auth endpoints                                 |
| ...                   | ...              | ...               | ...                        | ...                                          | ...                                            |

---

## 🧩 الثوابت والدوال | Constants & Functions

### 🔷 الثوابت | Constants

| اسم الثابت               | Constant Name         | القيمة الافتراضية | Default Value | مكان التعريف              | Defined In            |
|--------------------------|----------------------|-------------------|---------------|--------------------------|-----------------------|
| MAX_ACCURACY_THRESHOLD   | MAX_ACCURACY_THRESHOLD | 50.0            | 50.0          | src/core/geo_resolver.rs | geo_resolver.rs       |
| MIN_SIGNAL_STRENGTH      | MIN_SIGNAL_STRENGTH    | 30              | 30            | src/core/geo_resolver.rs | geo_resolver.rs       |
| QUANTUM_SECURITY_LEVEL   | QUANTUM_SECURITY_LEVEL | 90              | 90            | src/core/geo_resolver.rs | geo_resolver.rs       |
| MAX_HISTORY_SIZE         | MAX_HISTORY_SIZE       | 100             | 100           | src/core/geo_resolver.rs | geo_resolver.rs       |

---

### 🔷 الدوال العامة | Public Functions

| اسم الدالة           | Function Name       | التوقيع / Signature                        | مكان التعريف / Defined In          |
|----------------------|--------------------|--------------------------------------------|------------------------------------|
| get_user_by_id       | get_user_by_id     | async fn get_user_by_id(pool, user_id)     | src/db/crud.rs / crud.rs           |
| verify_smart_access  | verify_smart_access| async fn verify_smart_access(...)          | src/core/composite_verification.rs  |
| process              | process            | async fn process(input)                    | src/core/behavior_bio.rs           |
| check                | check              | async fn check(ip)                         | src/security/ratelimit.rs          |

---

## 🔑 المفاتيح ونقاط النهاية | Config & Endpoints

### 🧾 مفاتيح البيئة والإعداد (.env / config)

| اسم المفتاح   | Key Name      | الدور                    | Role                    | مثال                       | Example                        |
|---------------|--------------|--------------------------|-------------------------|-----------------------------|---------------------------------|
| API_KEY       | API_KEY      | مفتاح المصادقة الرئيسي    | Main authentication key | API_KEY=your_secret_key     |
| DATABASE_URL  | DATABASE_URL | رابط قاعدة البيانات      | DB connection string    | DATABASE_URL=mysql://...    |
| LOG_LEVEL     | LOG_LEVEL    | مستوى السجلات            | Logging verbosity       | LOG_LEVEL=debug             |
| GEO_PROVIDER  | GEO_PROVIDER | مزود الموقع (اختياري)    | Geolocation provider    | GEO_PROVIDER=ipapi          |

---

### 🌐 نقاط النهاية (API Endpoints)

| المسار         | Path           | نوع الطلب | Method | الدور (عربي)         | Role (English)           | التعريف / Defined In       |
|----------------|----------------|-----------|--------|----------------------|--------------------------|----------------------------|
| /users/{id}    | /users/{id}    | GET       | get_user | جلب بيانات مستخدم   | Fetch user data          | src/api/auth.rs            |
| /alerts/trigger| /alerts/trigger| POST      | trigger_alert | إطلاق تنبيه أمني | Trigger security alert   | src/api/alerts.rs          |
| /auth/login    | /auth/login    | POST      | login   | تسجيل دخول          | User login               | src/api/auth.rs            |

---

## 🧭 البنية المعمارية | Project Architecture

```mermaid
graph TD
    A[main.rs 🧩\nEntry] --> B[API Layer 🌐]
    A --> C[Core Engines 🧠]
    A --> D[DB Layer 🗄️]
    B -->|Endpoints| E[🔓 /auth, /alerts, /users]
    C --> F[GeoResolver 🌍]
    C --> G[BehaviorEngine 🧠]
    C --> H[DeviceFingerprint 📱]
    C --> I[NetworkAnalyzer 🌐🔍]
    C --> J[SensorsAnalyzer 📡]
    C --> K[WeatherEngine ☁️]
    C --> L[CrossValidator 🔄]
    C --> M[CompositeVerifier 🛡️]
    D --> N[CRUD + Models ⚙️]
    B --> O[Security Layer 🔐]
    O --> P[InputValidator 📥]
    O --> Q[JWT Manager 🔑]
    O --> R[Policy Engine ⚖️]
    O --> S[RateLimiter 🚦]
🎯 الوصف: يوضح المخطط تداخل الوحدات الرئيسة وصولاً لطبقة التحقق الأمني المركب الذكي.

🛠️ أمثلة التحقق العملي | Practical Verification Examples
تحقق أمني مركب | Full Composite Security Check
rust


let allowed_zones = vec!["Riyadh".to_string(), "Jeddah".to_string()];
let allowed_hours = Some((6, 18));
let access_granted = verify_user_full_access(
    &db_pool, &user_id, &device_id, "admin",
    geo_input, behavior_input, &geo_resolver, &behavior_engine,
    &allowed_zones, allowed_hours,
).await?;
if !access_granted {
    // Deny access or log suspicious attempt | رفض الوصول أو تسجيل محاولة مشبوهة
}
تحقق من الموقع الجغرافي فقط | Geo Verification Only
rust


let geo_location = geo_resolver.resolve(Some(ip), Some(gps), None, None, None, None, None).await?;
if let Some(city) = &geo_location.city {
    if allowed_zones.contains(city) {
        // تحقق جغرافي ناجح | Geo verification successful
    } else {
        // رفض الوصول بسبب المنطقة | Access denied due to location
    }
}
تحقق من السلوك فقط | Behavior Verification Only
rust


let behavior_result = behavior_engine.process(behavior_input).await?;
if behavior_result.risk_level as u8 < 3 {
    // السلوك طبيعي | Low risk behavior
} else {
    // السلوك مشبوه | Medium or high risk behavior
}
تحقق من الجهاز فقط | Device Verification Only
rust

let mut conn = db_pool.get_conn().await?;
let device_query = r#"SELECT id FROM devices WHERE id = ? AND user_id = ?"#;
let device_row: Option<Row> = mysql_async::prelude::Queryable::exec_first(
    &mut conn, device_query,
    (device_id.to_string(), user_id.to_string()),
).await?;
if device_row.is_some() {
    // الجهاز مسجل باسم المستخدم | Device recognized
} else {
    // الجهاز غير معروف أو غير مصرح به | Unknown or unauthorized device
}
تحقق من الصلاحيات فقط | Role Verification Only
rust

let mut conn = db_pool.get_conn().await?;
let role_query = r#"SELECT role FROM user_roles WHERE user_id = ? AND role = ?"#;
let role_row: Option<Row> = mysql_async::prelude::Queryable::exec_first(
    &mut conn, role_query,
    (user_id.to_string(), "admin"),
).await?;
if role_row.is_some() {
    // للمستخدم الصلاحية المطلوبة | User has required role
} else {
    // ليس لديه الصلاحية | User lacks required role
}
⚠️ تقرير فحص التبعيات | Dependency Audit
| التبعية | Dependency | النوع | Type | استخدام مباشر؟ | Direct? | استخدام غير مباشر؟ | Indirect? | خطر أو مشكلة؟ | Risk? | الإجراء المطلوب | Action |
|--------------------|------------------|-------|---------|----------------|---------|--------------------|-----------|---------------|--------|
| instant | Std Native | نعم | Yes | لا | No | لا | No | لا شيء | None |
| lexical | External | لا | No | نعم | Yes | لا | No | لا شيء | None |
| lexical-core | External | لا | No | نعم | Yes | لا | No | لا شيء | None |
| proc-macro-error | External | لا | No | نعم | Yes | لا | No | لا شيء | None |

هندسيًا:

✅ كل التبعيات مراجعة ولا توجد حزم غير آمنة.

🔁 تحديث دوري بـ cargo update يوصى به دائمًا.

📌 لا تحذيرات أمان حالية.

✅ نتائج اختبار المشروع | Test Results
bash
نسخ
تحرير
running 35 tests
... all tests passed ...

test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.04s
✅ كل الاختبارات نجحت (35 اختبارًا)

🧠 تأكيد التكامل بين كل الوحدات

⭐ مزايا المشروع والفئات المستهدفة | Features & Target Audiences
المزايا:

🔐 تحقق مركب (جغرافيا، سلوك، جهاز، شبكة، طقس)

🧠 يدعم الذكاء الاصطناعي

🛰️ مصادر متعددة للموقع (GPS/IP/SIM)

🛡️ مقاومة التخفي (VPN/Proxy/Tor)

🏙️ دعم سياسات المدن الذكية

🔁 مرونة plug-and-play

🧾 توثيق ثنائي اللغة جاهز للنشر المؤسسي

الفئات المستهدفة:

الفئة	Audience	الاستخدام	Use Case
الجهات الحكومية	Government	المدن الذكية، الأمن السيبراني	Smart city, cyber security
القطاع المالي	Financial	مكافحة الاحتيال، التحقق من الهوية	Anti-fraud, identity check
شركات التقنية	Tech Firms	حماية API والمنصات	API/platform security
مطورو التطبيقات	Developers	دمج تحقق مرن متقدم	Adaptive smart verification

🧠 دليل المطور | Developer Guide
خطوات الربط:

أضف متغيرات البيئة (.env)

فعّل المحركات الأساسية بالدوال

خصص محركاتك أو دمج أي منطق ذكاء اصطناعي

استخدم REST API أو ادمج داخليًا مع Rust

نصائح متقدمة:

جميع المحركات قابلة للحقن أو الاستبدال.

لا يوجد منطق مفروض — حرية تخصيص كاملة.

تأكد من دمج الجلسة والجهاز والدور في العمليات الحساسة.

راجع أمثلة الأكواد والجداول.

📈 ملخص الحالة الفنية | System State Summary
الوحدة	Module	الحالة	Status
Core Engines	✅	مكتملة ومترابطة بالكامل	Fully implemented & integrated
API Layer	✅	جميع نقاط النهاية مفعلة	All endpoints functional
Security Layer	✅	يشمل JWT/RateLimiter/Policies	JWT, RateLimiter, dynamic policies
DB Layer	✅	CRUD و Models مترابطة آمنة	CRUD/models securely connected
Utils	✅	جاهزة للاستخدام	Ready & modular

✅ كل المحركات متكاملة ولا توجد ثغرات أو مخاطر.

✅ التوثيق ثنائي اللغة + أمثلة عملية كاملة.

✅ جميع الاختبارات ناجحة.

✅ جاهز للنشر أو الدمج المؤسسي.

إعداد وتوثيق: منصور بن خالد (MKT KSA 🇸🇦) — جميع الحقوق محفوظة 2025