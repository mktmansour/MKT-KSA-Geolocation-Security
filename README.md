# 🛡️🌍 MKT\_KSA\_Geolocation\_Security

**مكتبة التحقق الجغرافي والأمني السعودي الذكية – MKT KSA 🇸🇦**
**Smart Saudi Geolocation & Security Library** 
> 🔐 Rust | 🛰️ Smart Security | 🏙️ Smart City Ready | 📄 Apache 2.0 |  Developed by Mansour Bin Khalid (KSA 🇸🇦)
 

---

## 📘 المحتويات | Table of Contents

* [🗺️ نبذة عن المشروع | Project Overview](#-نبذة-عن-المشروع--project-overview)
* [📂 الملفات الأساسية | Main Files](#-الملفات-الأساسية--main-files)
* [🧩 الثوابت والدوال | Constants & Functions](#-الثوابت-والدوال--constants--functions)
* [🔑 المفاتيح ونقاط النهاية | Config & Endpoints](#-المفاتيح-ونقاط-النهاية--config--endpoints)
* [🧭 البنية المعمارية | Architecture](#-البنية-المعمارية--architecture)
* [🛠️ أمثلة التحقق | Verification Examples](#-أمثلة-التحقق--verification-examples)
* [⚠️ تقرير التبعيات | Dependency Audit](#-تقرير-التبعيات--dependency-audit)
* [✅ نتائج الاختبار | Test Results](#-نتائج-الاختبار--test-results)
* [⭐ مزايا المشروع | Features](#-مزايا-المشروع--features)
* [🧠 دليل المطور | Developer Guide](#-دليل-المطور--developer-guide)
* [📈 ملخص الحالة الفنية | System State](#-ملخص-الحالة-الفنية--system-state)

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
| security/input\_validator.rs | input\_validator.rs  | src/security/input\_validator.rs | src/security/input\_validator.rs | أدوات التحقق للمدخلات         | Input validation tools                         |
| security/policy.rs           | policy.rs            | src/security/policy.rs           | src/security/policy.rs           | محرك السياسات الأمنية         | Policy engine                                  |
| core/geo\_resolver.rs        | geo\_resolver.rs     | src/core/geo\_resolver.rs        | src/core/geo\_resolver.rs        | محرك الموقع الجغرافي          | Geolocation resolver engine                    |
| core/behavior\_bio.rs        | behavior\_bio.rs     | src/core/behavior\_bio.rs        | src/core/behavior\_bio.rs        | محرك التحليل السلوكي          | Behavioral analytics engine                    |
| core/device\_fp.rs           | device\_fp.rs        | src/core/device\_fp.rs           | src/core/device\_fp.rs           | بصمة الجهاز                   | Device fingerprinting                          |
| core/network\_analyzer.rs    | network\_analyzer.rs | src/core/network\_analyzer.rs    | src/core/network\_analyzer.rs    | تحليل الشبكة وكشف التخفي      | Network analysis & concealment detection       |
| api/auth.rs                  | auth.rs              | src/api/auth.rs                  | src/api/auth.rs                  | نقاط نهاية المصادقة           | Auth endpoints                                 |
| api/alerts.rs                | alerts.rs            | src/api/alerts.rs                | src/api/alerts.rs                | نقاط نهاية التنبيهات الأمنية  | Security alerts endpoints                      |
| utils/mod.rs                 | mod.rs               | src/utils/mod.rs                 | src/utils/mod.rs                 | أدوات مساعدة عامة             | Utility helpers/cache/logger                   |
| Cargo.toml                   | Cargo.toml           | Cargo.toml                       | Cargo.toml                       | ملف التبعيات وإعداد المشروع   | Dependency management file                     |

---

## 🧩 الثوابت والدوال | Constants & Functions

### 🔷 الثوابت | Constants

| اسم الثابت               | Constant Name            | القيمة الافتراضية | Default Value | مكان التعريف              | Defined In       |
| ------------------------ | ------------------------ | ----------------- | ------------- | ------------------------- | ---------------- |
| MAX\_ACCURACY\_THRESHOLD | MAX\_ACCURACY\_THRESHOLD | 50.0              | 50.0          | src/core/geo\_resolver.rs | geo\_resolver.rs |
| MIN\_SIGNAL\_STRENGTH    | MIN\_SIGNAL\_STRENGTH    | 30                | 30            | src/core/geo\_resolver.rs | geo\_resolver.rs |
| QUANTUM\_SECURITY\_LEVEL | QUANTUM\_SECURITY\_LEVEL | 90                | 90            | src/core/geo\_resolver.rs | geo\_resolver.rs |
| MAX\_HISTORY\_SIZE       | MAX\_HISTORY\_SIZE       | 100               | 100           | src/core/geo\_resolver.rs | geo\_resolver.rs |

---

### 🔷 الدوال العامة | Public Functions

| اسم الدالة            | Function Name         | التوقيع / Signature                        | مكان التعريف / Defined In           |
| --------------------- | --------------------- | ------------------------------------------ | ----------------------------------- |
| get\_user\_by\_id     | get\_user\_by\_id     | async fn get\_user\_by\_id(pool, user\_id) | src/db/crud.rs / crud.rs            |
| verify\_smart\_access | verify\_smart\_access | async fn verify\_smart\_access(...)        | src/core/composite\_verification.rs |
| process               | process               | async fn process(input)                    | src/core/behavior\_bio.rs           |
| check                 | check                 | async fn check(ip)                         | src/security/ratelimit.rs           |

---

## 🔑 المفاتيح ونقاط النهاية | Config & Endpoints

### 🧾 مفاتيح البيئة والإعداد (.env / config)

| اسم المفتاح   | Key Name      | الدور                  | Role                    | مثال                       | Example |
| ------------- | ------------- | ---------------------- | ----------------------- | -------------------------- | ------- |
| API\_KEY      | API\_KEY      | مفتاح المصادقة الرئيسي | Main authentication key | API\_KEY=your\_secret\_key |         |
| DATABASE\_URL | DATABASE\_URL | رابط قاعدة البيانات    | DB connection string    | DATABASE\_URL=mysql://...  |         |
| LOG\_LEVEL    | LOG\_LEVEL    | مستوى السجلات          | Logging verbosity       | LOG\_LEVEL=debug           |         |
| GEO\_PROVIDER | GEO\_PROVIDER | مزود الموقع (اختياري)  | Geolocation provider    | GEO\_PROVIDER=ipapi        |         |

---

### 🌐 نقاط النهاية (API Endpoints)

| المسار          | Path            | نوع الطلب | Method         | الدور (عربي)      | Role (English)         | التعريف / Defined In |
| --------------- | --------------- | --------- | -------------- | ----------------- | ---------------------- | -------------------- |
| /users/{id}     | /users/{id}     | GET       | get\_user      | جلب بيانات مستخدم | Fetch user data        | src/api/auth.rs      |
| /alerts/trigger | /alerts/trigger | POST      | trigger\_alert | إطلاق تنبيه أمني  | Trigger security alert | src/api/alerts.rs    |
| /auth/login     | /auth/login     | POST      | login          | تسجيل دخول        | User login             | src/api/auth.rs      |

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
```

> 🎯 **الوصف:** يوضح المخطط تداخل الوحدات الرئيسة وصولاً لطبقة التحقق الأمني المركب الذكي.

---

## 🛠️ أمثلة التحقق العملي | Practical Verification Examples

### تحقق أمني مركب | Full Composite Security Check

```rust
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
```

---

### تحقق من الصلاحيات فقط | Role Verification Only

```rust
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
```

---

## ⚠️ تقرير فحص التبعيات | Dependency Audit

| Dependency         | Type     | Direct? | Indirect? | Risk? | Action  |
|--------------------|----------|---------|-----------|-------|---------|
| instant            | Std Native | Yes   | No        | None  | None    |
| lexical            | External   | No    | Yes       | None  | None    |
| lexical-core       | External   | No    | Yes       | None  | None    |
| proc-macro-error   | External   | No    | Yes       | None  | None    |


* ✅ جميع التبعيات مراجعة ولا توجد حزم غير آمنة.
* 🔁 تحديث دوري بـ `cargo update` يوصى به دائمًا.
* 📌 لا تحذيرات أمان حالية.

---

## ✅ نتائج الاختبار | Test Results

```bash
running 35 tests
... all tests passed ...

test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.04s
```

* ✅ كل الاختبارات نجحت (35 اختبارًا).

---

## ⭐ مزايا المشروع والفئات المستهدفة | Features & Target Audiences

### 🏆 المزايا الرئيسية | Main Features

* 🔐 **تحقق مركب متعدد المصادر**: (جغرافي، سلوكي، جهاز، شبكة، حساسات، طقس).
* 🧠 **تكامل AI وتكيف ذكي**: دعم الذكاء الاصطناعي وخوارزميات الأمن التكيفية.
* 🛰️ **كشف التخفي المتقدم**: دعم VPN/Proxy/Tor وطرق كشف متطورة.
* 🏙️ **سياسات المدن الذكية والمؤسسات الكبرى**: دعم مناطق/أذونات/أوقات متقدمة.
* ⚡ **بنية معيارية ومرنة**: قابلة للحقن والتخصيص لأي محرك أو منطق أمان.
* 📄 **توثيق ثنائي اللغة كامل**: كل جزء موثق عربي/إنجليزي.
* 🔑 **إدارة أسرار وتشفير ما بعد الكم**: دعم secrecy وPost-Quantum crypto.
* 🚦 **تحديد معدل الطلبات Rate Limiting**: وحدة RateLimiter جاهزة.
* 🔌 **سهولة التكامل مع أي تطبيق أو خدمة**: REST API أو Rust Traits مباشرة.

---

### 👤 الفئات المستهدفة | Target Audiences

* الجهات الحكومية (مدن ذكية، سيبراني، جوازات، مرور)
* البنوك والمؤسسات المالية
* شركات التقنية الكبرى (Cloud, IoT, AI, Security)
* تطبيقات الهوية والصلاحيات (Access Control, MFA)
* أي مطور يبحث عن حلول أمان حديثة وقابلة للتخصيص

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

#### 💡 نصائح متقدمة | Advanced Tips

* جميع المحركات قابلة للحقن أو الاستبدال
* حرية تخصيص كاملة (الجلسة/الجهاز/الدور)
* أمثلة ودوال وثوابت كلها موثقة عربي/إن
