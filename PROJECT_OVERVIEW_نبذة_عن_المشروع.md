/******************************************************************************************
    📚 نبذة عن مشروع منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 جميع الحقوق محفوظة.

    اسم الملف: PROJECT_OVERVIEW_نبذة_عن_المشروع.md
    المسار:    جذر المشروع (root)

    دور الملف:
    هذا الملف يمثل التوثيق المركزي والنبذة الشاملة للمشروع، ويحتوي على:
    - ملخص متسلسل لجميع الملفات الأساسية ودورها (عربي/إنجليزي)
    - استخراج الثوابت والدوال والعناوين والمفاتيح المطلوبة
    - صور توضيحية لبنية المشروع وتدفق التحقق الأمني
    - مزايا المشروع والفئات المستهدفة
    - إرشادات ربط وتخصيص المكتبة للمطورين

    File Name: PROJECT_OVERVIEW_نبذة_عن_المشروع.md
    Path:     Project root

    File Role:
    This file serves as the central documentation and overview for the project, including:
    - A sequential summary of all main files and their roles (Arabic/English)
    - Extraction of constants, functions, endpoints, and required config keys
    - Illustrative diagrams of project architecture and security flow
    - Project features and target audiences
    - Integration and customization guidelines for developers
******************************************************************************************/

# 🗺️ نبذة عن المشروع | Project Overview

---

## 🗂️ قائمة الملفات الأساسية ودورها | Main Files & Their Roles

| اسم الملف | File Name | المسار | Path | الدور (عربي) | Role (English) |
|-----------|-----------|---------|------|---------------|----------------|
| main.rs | main.rs | src/main.rs | src/main.rs | نقطة الدخول الرئيسية للتطبيق، تهيئة الخادم وقاعدة البيانات وتسجيل وحدات المشروع. | Main entry point, initializes server, DB, and registers modules. |
| db/models.rs | models.rs | src/db/models.rs | src/db/models.rs | تعريف هياكل البيانات (الجداول) وربطها مع قاعدة البيانات. | Data model definitions (tables) and DB mapping. |
| db/crud.rs | crud.rs | src/db/crud.rs | src/db/crud.rs | دوال عمليات قاعدة البيانات الأساسية (CRUD) مع أمان الصف. | Core DB CRUD functions with row-level security. |
| db/mod.rs | mod.rs | src/db/mod.rs | src/db/mod.rs | فهرس لوحدة قاعدة البيانات، يعلن عن models وcrud. | Index for DB module, declares models and crud. |
| security/input_validator.rs | input_validator.rs | src/security/input_validator.rs | src/security/input_validator.rs | أدوات التحقق والتعقيم للمدخلات لمنع الهجمات. | Input validation/sanitization tools to prevent attacks. |
| security/policy.rs | policy.rs | src/security/policy.rs | src/security/policy.rs | محرك السياسات الأمنية الديناميكي، يقرر بناءً على السياق. | Dynamic security policy engine, context-based decisions. |
| security/ratelimit.rs | ratelimit.rs | src/security/ratelimit.rs | src/security/ratelimit.rs | وحدة تحديد معدل الطلبات وحماية من هجمات DoS. | Rate limiting module, DoS protection. |
| security/jwt.rs | jwt.rs | src/security/jwt.rs | src/security/jwt.rs | إدارة التوكنات JWT للتحقق من الهوية والصلاحيات. | JWT token management for auth and permissions. |
| security/mod.rs | mod.rs | src/security/mod.rs | src/security/mod.rs | فهرس وحدة الأمان، يعلن عن جميع الوحدات الفرعية. | Security module index, declares all submodules. |
| api/auth.rs | auth.rs | src/api/auth.rs | src/api/auth.rs | نقاط نهاية API للمصادقة وجلب بيانات المستخدم. | API endpoints for authentication and user data. |
| api/alerts.rs | alerts.rs | src/api/alerts.rs | src/api/alerts.rs | نقاط نهاية API لإطلاق التنبيهات الأمنية. | API endpoints for triggering security alerts. |
| api/mod.rs | mod.rs | src/api/mod.rs | src/api/mod.rs | فهرس وحدة API، يعلن عن جميع نقاط النهاية. | API module index, declares all endpoints. |
| core/geo_resolver.rs | geo_resolver.rs | src/core/geo_resolver.rs | src/core/geo_resolver.rs | محرك تحليل الموقع الجغرافي الذكي والآمن. | Smart & secure geolocation resolver engine. |
| core/behavior_bio.rs | behavior_bio.rs | src/core/behavior_bio.rs | src/core/behavior_bio.rs | محرك التحليل السلوكي والبيومتري المرن. | Flexible behavioral & biometric analysis engine. |
| core/device_fp.rs | device_fp.rs | src/core/device_fp.rs | src/core/device_fp.rs | محرك بصمة الأجهزة المتقدم وإدارة الأسرار. | Advanced device fingerprinting & secret management. |
| core/network_analyzer.rs | network_analyzer.rs | src/core/network_analyzer.rs | src/core/network_analyzer.rs | محرك تحليل الشبكة وكشف أدوات التخفي. | Network analysis engine, concealment detection. |
| core/sensors_analyzer.rs | sensors_analyzer.rs | src/core/sensors_analyzer.rs | src/core/sensors_analyzer.rs | محرك تحليل بيانات الحساسات وكشف الشذوذ. | Sensor data analysis & anomaly detection engine. |
| core/weather_val.rs | weather_val.rs | src/core/weather_val.rs | src/core/weather_val.rs | محرك تجميع وتدقيق بيانات الطقس من مصادر متعددة. | Weather data aggregation & validation engine. |
| core/cross_location.rs | cross_location.rs | src/core/cross_location.rs | src/core/cross_location.rs | محرك التحقق المتقاطع (Cross-Validation) النهائي. | Final cross-validation engine (verdict orchestrator). |
| core/composite_verification.rs | composite_verification.rs | src/core/composite_verification.rs | src/core/composite_verification.rs | منطق التحقق الأمني المركب للمدن الذكية. | Composite security verification logic for smart cities. |
| utils/mod.rs | mod.rs | src/utils/mod.rs | src/utils/mod.rs | فهرس وحدة الأدوات المساعدة (helpers/cache/logger). | Utils module index (helpers/cache/logger). |
| Cargo.toml | Cargo.toml | Cargo.toml | Cargo.toml | ملف إدارة التبعيات وإعدادات المشروع. | Dependency management & project config file. |

---

## 🧩 الثوابت والدوال والعناوين والمفاتيح | Constants, Functions, Endpoints, and Config Keys

### 🟦 الثوابت (Constants)
- **عربي:** جميع القيم الثابتة التي تتحكم في منطق الأمان، الحدود، الإعدادات الافتراضية.
- **English:** All constant values controlling security logic, limits, and defaults.

| اسم الثابت | Constant Name | القيمة الافتراضية | Default Value | مكان التعريف | Defined In |
|------------|---------------|-------------------|--------------|--------------|
| MAX_ACCURACY_THRESHOLD | MAX_ACCURACY_THRESHOLD | 50.0 | 50.0 | src/core/geo_resolver.rs |
| MIN_SIGNAL_STRENGTH | MIN_SIGNAL_STRENGTH | 30 | 30 | src/core/geo_resolver.rs |
| QUANTUM_SECURITY_LEVEL | QUANTUM_SECURITY_LEVEL | 90 | 90 | src/core/geo_resolver.rs |
| MAX_HISTORY_SIZE | MAX_HISTORY_SIZE | 100 | 100 | src/core/geo_resolver.rs |
| ... | ... | ... | ... | ... |

### 🟦 الدوال الأساسية (Main Functions)
- **عربي:** الدوال العامة التي توفر واجهات التحقق، CRUD، التهيئة، إلخ.
- **English:** Main public functions for verification, CRUD, initialization, etc.

| اسم الدالة | Function Name | التوقيع | Signature | مكان التعريف | Defined In |
|------------|---------------|---------|-----------|--------------|
| get_user_by_id | get_user_by_id | async fn get_user_by_id(pool, user_id) | src/db/crud.rs |
| get_user_by_username | get_user_by_username | async fn get_user_by_username(pool, username) | src/db/crud.rs |
| get_all_users | get_all_users | async fn get_all_users(pool) | src/db/crud.rs |
| create_user | create_user | async fn create_user(pool, username, password_hash) | src/db/crud.rs |
| verify_smart_access | verify_smart_access | async fn verify_smart_access(...) | src/core/composite_verification.rs |
| process | process | async fn process(input) | src/core/behavior_bio.rs |
| generate_fingerprint | generate_fingerprint | async fn generate_fingerprint(...) | src/core/device_fp.rs |
| analyze | analyze | async fn analyze(...) | src/core/sensors_analyzer.rs |
| check | check | async fn check(ip) | src/security/ratelimit.rs |
| ... | ... | ... | ... | ... |

### 🟦 العناوين (Endpoints & Webhooks)
- **عربي:** جميع نقاط النهاية (API/Webhook) التي توفرها المكتبة.
- **English:** All API/Webhook endpoints provided by the library.

| المسار | Path | نوع الطلب | Method | الدور | Role | مكان التعريف | Defined In |
|--------|------|-----------|--------|-------|------|--------------|
| /users/{id} | /users/{id} | GET | get_user | جلب بيانات مستخدم | Fetch user data | src/api/auth.rs |
| /alerts/trigger | /alerts/trigger | POST | trigger_alert | إطلاق تنبيه أمني | Trigger security alert | src/api/alerts.rs |
| ... | ... | ... | ... | ... | ... | ... |

### 🟦 مفاتيح التهيئة المطلوبة (.env/config)
- **عربي:** جميع المتغيرات التي يجب ضبطها في ملف البيئة أو الإعدادات.
- **English:** All variables that must be set in the environment or config file.

| اسم المفتاح | Key Name | الدور | Role | مثال | Example |
|-------------|----------|-------|------|-------|
| API_KEY | API_KEY | مفتاح المصادقة الرئيسي | Main authentication key | API_KEY=your_secret_key |
| DATABASE_URL | DATABASE_URL | رابط قاعدة البيانات | Database connection string | DATABASE_URL=mysql://user:pass@host/db |
| ... | ... | ... | ... | ... |

---

## 🗺️ بنية المشروع وتدفق التحقق الأمني | Project Architecture & Security Flow

### مخطط بنية المشروع (Mermaid)

```mermaid
graph TD
    A[main.rs<br/>نقطة الدخول<br/>Entry Point] --> B[API Layer<br/>طبقة API]
    A --> C[Core Engines<br/>محركات التحليل]
    A --> D[DB Layer<br/>طبقة قاعدة البيانات]
    B -->|/users/{id}, /alerts/trigger| E[Endpoints<br/>نقاط النهاية]
    C --> F[GeoResolver<br/>محرك الموقع الجغرافي]
    C --> G[BehaviorEngine<br/>محرك السلوك]
    C --> H[DeviceFP<br/>بصمة الجهاز]
    C --> I[NetworkAnalyzer<br/>تحليل الشبكة]
    C --> J[SensorsAnalyzer<br/>تحليل الحساسات]
    C --> K[WeatherEngine<br/>محرك الطقس]
    C --> L[CrossValidation<br/>التحقق المتقاطع]
    C --> M[CompositeVerifier<br/>التحقق المركب]
    D --> N[CRUD/Models<br/>عمليات البيانات]
    B --> O[Security Layer<br/>طبقة الأمان]
    O --> P[InputValidator]
    O --> Q[JWT]
    O --> R[Policy]
    O --> S[RateLimit]
```

- **عربي:** يوضح المخطط كيف تتكامل جميع الوحدات (API, Core, DB, Security) لتحقيق التحقق الأمني المركب.
- **English:** The diagram shows how all modules (API, Core, DB, Security) integrate to achieve composite security verification.

---

## ⭐ مزايا المشروع والفئات المستهدفة | Project Features & Target Audiences

### المزايا الرئيسية | Main Features
- **تحقق أمني مركب متعدد المصادر (جغرافي، سلوكي، جهاز، شبكة، حساسات، طقس).**
- **تكامل مع الذكاء الاصطناعي والتكيف الذكي (Adaptive, AI-driven Security).**
- **كشف أدوات التخفي (VPN/Proxy/Tor) وخوارزميات مقاومة للهجمات الحديثة.**
- **دعم المدن الذكية (Smart City Policies) وسيناريوهات متقدمة (مناطق، أوقات، أذونات).**
- **بنية معيارية مرنة وقابلة للحقن والتخصيص لأي محرك أو منطق أمان.**
- **توثيق ثنائي اللغة (عربي/إنجليزي) كامل لكل جزء.**
- **إدارة أسرار متقدمة (secrecy)، دعم تشفير ما بعد الكم (Post-Quantum).**
- **وحدة تحديد معدل الطلبات (Rate Limiting) مدمجة.**
- **سهولة الربط مع أي تطبيق أو خدمة عبر API أو Rust Traits.**

### الفئات المستهدفة | Target Audiences
- الجهات الحكومية (المدن الذكية، الأمن السيبراني، الجوازات، المرور).
- البنوك والمؤسسات المالية.
- شركات التقنية الكبرى (Cloud, IoT, AI, Security).
- تطبيقات التحقق من الهوية والوصول (Access Control, MFA).
- أي مطور يبحث عن حلول أمان متقدمة وقابلة للتخصيص.

### نقاط التميز مقارنة بالمنافسين | Unique Selling Points
- **تحقق مركب يجمع بين الموقع والسلوك والجهاز والشبكة في قرار واحد.**
- **دعم مصادر جغرافية متعددة (GPS, IP, SIM, Satellite, Indoor, AR).**
- **إمكانية حقن أي منطق ذكاء اصطناعي أو نموذج تعلم آلي بسهولة.**
- **كشف متقدم لأدوات التخفي (VPN/Proxy/Tor) مدمج في المحرك.**
- **دعم كامل للمدن الذكية وسيناريوهات المؤسسات الكبرى.**
- **توثيق ثنائي اللغة وواجهة برمجية مرنة للمطورين.**

---

## 🛠️ إرشادات الربط والتخصيص للمطورين | Integration & Customization Guide

### خطوات الربط الأساسية | Basic Integration Steps
1. **ضبط متغيرات البيئة الأساسية (.env/config):**
   - API_KEY=your_secret_key
   - DATABASE_URL=mysql://user:pass@host/db
2. **تهيئة المحركات الأساسية في تطبيقك:**
   - عبر استدعاء الدوال العامة (مثال: verify_smart_access، process، generate_fingerprint)
3. **تخصيص المنطق الأمني:**
   - يمكنك حقن أي نموذج ذكاء اصطناعي أو منطق تحقق خاص بك عبر Traits.
   - تخصيص السياسات (مناطق، أوقات، أذونات) بسهولة.
4. **استخدام نقاط النهاية (API) أو التكامل المباشر مع Rust:**
   - استدعاء نقاط النهاية الجاهزة (مثال: /users/{id}, /alerts/trigger)
   - أو ربط الدوال مباشرة في تطبيقك.

### مثال ربط سريع (Rust)
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

### نصائح متقدمة | Advanced Tips
- يمكنك استبدال أي محرك (Geo, Behavior, Device, Network) بمنطقك الخاص بسهولة.
- جميع الدوال العامة موثقة وثنائي اللغة.
- راجع جدول الثوابت والمفاتيح للتأكد من ضبط جميع الإعدادات.

---

**تم التوثيق المتسلسل الكامل للمشروع. إذا رغبت في إضافة صور أو أمثلة إضافية أو جدول مقارنة مع المنافسين، أخبرني بذلك.**

---

## 🔗 تحديث حالة الترابط والتكامل بين وحدات المشروع

### الحالة السابقة:
- في الإصدارات الأولى، كان هناك بعض الفجوات في الترابط بين المحركات (Geo, Behavior, Device, Network)، وبعض الدوال لم تكن متاحة بشكل عام أو موثقة.
- بعض التبعيات كانت قديمة أو غير مدعومة، وظهرت تحذيرات أمان في فحص التبعيات.
- لم يكن هناك توثيق مركزي يوضح كيفية التكامل بين جميع الوحدات.

### الحالة الحالية (بعد التحديثات):
- **كل وحدة (Core, API, Security, DB, Utils) موثقة ومترابطة هندسيًا.**
- **جميع المحركات الأساسية مربوطة عبر وحدة التحقق المركب (Composite Verification) وAppState.**
- **أي نقطة نهاية (API) يمكنها استدعاء أي منطق تحقق أو أمان مركب بسهولة.**
- **جميع التبعيات البرمجية حديثة وآمنة، ولا توجد أي مكتبات غير مدعومة أو تحذيرات أمان في كود الإنتاج.**
- **تم حذف جميع التبعيات الخاصة بالاختبارات (wiremock, instant) التي كانت سببًا في التحذيرات.**
- **التوثيق ثنائي اللغة يوضح كيفية الربط والتكامل بين كل جزء، مع أمثلة عملية.**

### ملخص للمطورين:
- المشروع الآن جاهز للنشر، ولا توجد أي ملاحظات أو تحذيرات أمنية أو هندسية.
- لا يحتاج المطور للاطلاع على أي ملاحظة خاصة بعد إزالة واستبدال وتحديث جميع المكتبات.
- جميع الوحدات متكاملة ويمكن ربطها أو تخصيصها بسهولة في أي تطبيق أو خدمة.

---