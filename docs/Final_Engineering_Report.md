******************************************************************************************
التقرير الهندسي النهائي (عربي) – MKT KSA Geolocation Security
******************************************************************************************

ملخص تنفيذي:
- مشروع سيادي (Zero‑Dependency Core) يوفّر أمن جغرافي‑سلوكي، تفتيش صارم للمدخلات/المخرجات، بصمة سلامة، خادم HTTP داخلي، حارس إخراج، تليمترية ذكية، ضغط RLE، تنبيهات مخاطر، وجدولة نسخ احتياطي، وواجهة C‑ABI.
- جميع التحذيرات معاملة كأخطاء أثناء التطوير؛ البناء/Clippy/الاختبارات/الوثائق/ترويسة C نظيفة؛ نواة المشروع اجتازت Miri.
 - حُرّاس ويب‑هوك تكيفيون لكل مسار (Per‑Path Guards) مع توقيع HMAC‑SHA512، مانع إعادة، ونوافذ زمنية قابلة للضبط، وتشديد/ارتخاء تلقائيَين بالذكاء الاصطناعي.
- ملاحظة مهمة: تم إزالة لوحة التحكم (UI) نهائيًا من الإصدار الإنتاجي؛ الواجهة الآن API/Webhook فقط. تبقى ميزات التصدير CSV/NDJSON والربط السحابي متاحة عبر نقاط API آمنة.

1) البنية العامة:
- lib: جذر التصدير وتجميع الوحدات خلف أعلام الميزات (feature flags) لضمان صفر تبعية افتراضيًا.
- core: هياكل أساسية (Digest افتراضي سيادي، واجهات لاحقة للخرائط/التحليل عند تفعيل الميزات الاختيارية).
- security: التفتيش، البصمة، الحراسة على الإخراج، الأسرار، مزوّدات التشفير الذكية (واجهات مجردة بلا تبعيات).
- api/std_http: خادم HTTP/1.1 صفري التبعيات، توجيه بسيط ونقاط القياس والنسخ الاحتياطي والتنبيهات.
- webhook: تعريف نقاط الدخول/العميل، تحليل URL داخلي.
- telemetry: عدادات، أحداث NDJSON، مفاتيح ميزات، خطر متكيف، نسخ احتياطي، قوالب بريد، تنبيهات.
- utils/rle: ضغط/فك ضغط RLE بسيط.
- ffi: واجهة C‑ABI عند التفعيل، مع توليد ترويسة `include/mkt_ksa_geo_sec.h`.

2) الأمان والمنطق:
- التفتيش: التحقق من الطرق والمسارات المسموحة، قوائم منع لمسارات حساسة، Content‑Type allowlist، حدود أحجام للرؤوس والمتن، فحص UTF‑8 وأنماط XSS.
- بصمة السلامة: بصمات للمدخلات والمخرجات مع مقارنة زمن ثابت (ct_eq) لمنع قنوات التوقيت.
- الحراسة على الإخراج: فحص RFC1918/Link‑local/Unix sockets، قوائم السماح/المنع للمضيفين، المنافذ المسموحة، مهلات وحد حجم استجابة.
- خادم HTTP الداخلي: تنفيذ بسيط آمن مع فحص مبدئي، ضغط اختياري، وتليمترية متكاملة.
- تليمترية متكيفة: ضبط حدود التفتيش ديناميكيًا عند ارتفاع الخطر، وجدولة نسخ احتياطي مشروطة بمستوى الخطر وموافقة مطوّر.
- FFI: عمليات unsafe محصورة وموضوعة ضمن حواجز سلامة صريحة، مع نسخ وعدم تعريض ملكية غير آمنة.

3) الذكاء الاصطناعي والتكيّف:
- طبقة خطر متكيّفة عبر `telemetry::set_risk/current_risk` تؤثر على حدود التفتيش (خفض نصف/ثلثي الحدود عند العتبات)، وتضبط إرسال النسخ الاحتياطي والتنبيهات.
- قابلية التوسعة: يمكن لاحقًا إضافة خوارزميات توقيع/تجمييع سلوك/كشف مبكر بدون تبعيات خارجية عبر أعلام ميزات.

4) الأداء والكفاءة:
- نواة خفيفة الذاكرة، جميع المسارات الأساسية عملت بدون تبعيات.
- ضغط RLE اختياري للجسم > 512B مع عدادات comp_in/out.
- خادم std_http بسيط أحادي الخيط للسيناريوهات المحلية/الخلف Proxy آمن.

5) الاختبارات والجودة:
- وحدات: التفتيش، البصمة، RLE، سياسات الإخراج.
- تكامل: /metrics، /backup، /alerts (إرجاع 200 وJSON منطقي).
- شبه‑Fuzz: تغطية مدخلات عشوائية بلا ذعر.
- Miri: نجاح للنواة بدون ميزات.
- Clippy: صارم بلا تحذيرات.
- Doc: تُبنى بلا تبعيات.
- ترويسة C: توليد نظيف مع سطح FFI محدود.

6) الإيجابيات:
- سيادة كاملة للنواة، صفر تبعيات افتراضيًا.
- طبقة تفتيش صلبة وسياسات قابلة للتهيئة.
- تكامل تليمترية وخطر متكيف وتنبيهات ونسخ احتياطي.
- تصميم وحداتي مع أعلام ميزات واضحة.
- تشغيل نظيف (لا تحذيرات) واختبارات ناجحة وMiri ناجح.

7) السلبيات/المخاطر (بعد المعالجة):
- عدم وجود TLS داخليًا (عن قصد): التوصية تشغيل خلف Proxy آمن أو تمكين عميل/خادم اختياري يدعم TLS مستقبلًا.
- Digest الافتراضي ليس تشفيريًا قويًا: التوصية إضافة خوارزميات أقوى عبر أعلام (BLAKE3/HMAC‑SHA2) عند الحاجة.
- الأمثلة/اختبارات لبعض الميزات غير مفعّلة افتراضيًا: تُفعل عند الحاجة مع تحويل unwrap/expect إلى Result في مسارات الإنتاج.
- واجهة FFI محدودة: توسّع تدريجي مع تدقيق مدخلات ورموز أخطاء موحّدة.

8) التطويرات المقترحة القادمة:
- تشفير سيادي اختياري: إضافة BLAKE3/HMAC‑SHA2 ومقارنات زمن ثابت لجميع المسارات الحساسة.
- صرامة أكبر للتفتيش: لوائح Allow/Deny قابلة للتحميل، سياسات Content‑Type أدق، وتغطية رؤوس إضافية.
- اختبارات تحميل فعلية: محاكاة 100–1000 اتصال متوازٍ باستخدام مشغّل داخلي خفيف أو تشغيل خلف Proxy.
- تعزيز egress: صرامة DNS (عدم تتبّع CNAME للداخلي)، كبح IPv6 Local‑Link، ومراقبة إعادة التوجيه.
- FFI: توسيع API بتوقيعات واضحة وثابتة، وثبات ABI عبر إصدارات.
- مراقبة أمنية: زيادة قواعد الإنذار المبكر وربطها بمستوى المخاطر.

9) توصيات تشغيلية:
- في الإنتاج، شغّل خلف Proxy عتيد مع TLS وجدار ناري.
- فعّل ميزات التشفير عند لزوم سلامة أقوى.
- استخدم النسخ الاحتياطي بموافقة ورقابة خطر مناسبة.
- راقب /metrics و/alerts وقم بضبط عتبات المخاطر دوريًا.

10) الخلاصة:
- المشروع حقق أهداف السيادة، الصرامة الأمنية الأساسية، القابلية للتكيّف، والمرونة، مع تصميم نظيف وقابل للتوسعة بلا تبعيات افتراضيًا.
******************************************************************************************

------------------------------------------------------------------------------------------
خريطة المجلدات والملفات التفصيلية (Arabic Only)
------------------------------------------------------------------------------------------

ملخص عددي:
- عدد المجلدات المهمة: 14
  1) src/api
  2) src/security
  3) src/core
  4) src/utils
  5) src/telemetry
  6) src/webhook
  7) src/ffi
  8) src/log/ledger
  9) src/db
  10) src/crypto
  11) src/bin
  12) tests
  13) docs
  14) include
- عدد الملفات الأساسية المذكورة أدناه: 23

تفصيل المجلدات ودور كل ملف رئيسي:

1) src/lib.rs (جذر المكتبة)
- الدور: تعريف السطح العام وتنظيم الوحدات مع أعلام الميزات للحفاظ على صفر تبعيات افتراضيًا.
- التكامل: يربط security، api، telemetry، utils، core، webhook، ffi حسب الميزات.

2) src/api/
- mod.rs: فهرس لوحدات API (تجميعي).
- std_http.rs: خادم HTTP/1.1 صفري التبعيات؛ توجيه /metrics, /events.ndjson, /toggle, /risk, /backup/*, /alerts/*؛ يستخدم التفتيش، البصمة، التليمترية، وRLE اختياريًا.
- ملفات API إضافية (alerts.rs, auth.rs, behavior.rs, device.rs, geo.rs, network.rs, sensors.rs, smart_access.rs, weather.rs): هياكل/واجهات قابلة للتوسيع لطبقات API المستقبلية، غير مطلوبة لتشغيل النواة الصفريّة؛ تُستخدم عند تفعيل ميزات متقدمة.
- src/bin/std_dashboard_demo.rs: مثال تنفيذي محلي للتجارب فقط (بدون لوحة تحكم إنتاجية).

3) src/security/
- inspection.rs: تفتيش صارم للمدخلات/المخرجات (XSS/UTF‑8/حدود الحجم) وحساب بصمة الإدخال؛ أساس الأمان.
- inspection_policy.rs: سياسة تفتيش قابلة للتهيئة (allowed_methods/paths, denied_paths, Content‑Type allowlist) مع تكييف الحدود ديناميكيًا حسب المخاطر.
- fingerprint.rs: توليد بصمة سلامة مستقرة وخالية من التبعيات.
- signing.rs: واجهة توقيع عامة (اختيارية مستقبلًا)؛ تبقى صفر تبعيات افتراضيًا.
- secret.rs: حاويات بيانات حساسة (إخفاء/صفرية اختيارية).
- crypto_provider.rs وcrypto_smart/*: تعريف واجهات تشفير ذكية محايدة للتبعيات، قابلة للتفعيل عند الحاجة.
- egress_guard/:
  - mod.rs: فهرس الحارس.
  - policy.rs: سياسة السماح/المنع والمنافذ وحدود الاستجابة والمهلة.
  - resolver.rs: فحص RFC1918/Link‑local/Unix sockets، وتحقق allow/deny للمضيفين.
  - parser.rs: تحليل عناوين HTTP البسيطة للخروج.
  - http_client.rs: عميل HTTP صفري للتجارب عند التفعيل.
  - errors.rs: أخطاء الحارس.
- jws/* وjwt.rs وpolicy.rs وinput_validator.rs وratelimit.rs: وحدات أمنية اختيارية (ليست مطلوبة للنواة الصفريّة) قابلة للتفعيل مستقبلًا.

4) src/core/
- digest.rs: واجهة تجزئة قياسية سيادية (بدون تبعيات) مستخدمة للبصمة.
- mod.rs: تجميع وحدات core.
- geo_resolver.rs, geo_db.rs, sensors_analyzer.rs, cross_location.rs, network_analyzer.rs, device_fp.rs, weather_val.rs, composite_verification.rs, behavior_bio.rs, history.rs: قدرات تحليل/تحقق متقدمة اختيارية، تُفعل عبر أعلام (مثل core_full) وليست مطلوبة لتشغيل النواة الصفريّة.

5) src/utils/
- helpers.rs: أدوات مساعدة عامة، تتضمن مقارنة زمن ثابت ct_eq.
- rle.rs: ضغط/فك ضغط RLE صفري.
- precision.rs, logger.rs, cache.rs, mod.rs: أدوات/فهرس مساعدة.

6) src/telemetry/
- mod.rs: عدادات، أحداث NDJSON، مفاتيح ميزة، مستوى خطر current_risk، جدولة النسخ الاحتياطي، قوالب البريد، تنبيهات المخاطر.

7) src/webhook/
- mod.rs: تعاريف WebhookEndpoint/WebhookClient، ووظيفة parse_http_url للاستخدام الداخلي.

8) src/ffi/
- mod.rs: واجهة C‑ABI (عند تفعيل ffi_c) مع حواجز unsafe محكومة.

9) src/log/ledger/
- entry.rs, writer.rs, verify.rs, digest.rs, anchor.rs, errors.rs, mod.rs: سجل سلسلة أحداث (Ledger) اختياري، يستخدم عند تفعيل مسارات التدقيق.

10) src/db/
- mod.rs, models.rs, crud.rs: طبقة بيانات اختيارية (ليست ضمن النواة الصفريّة)، أمثلة بنيويّة لقابلية التوسعة.

11) src/crypto/
- traits.rs, selector.rs, policy.rs, keystore.rs, envelope.rs, device_binding.rs, ai.rs, aad.rs, mod.rs: بنية تشفير/تغليف/سياسات اختيارية للتوسعة المستقبلية بدون تبعيات افتراضية.

12) tests/
- http_integration.rs: اختبار تكامل لخادم std_http و/metrics.
- fuzz_like.rs: اختبار شبه‑Fuzz للتفتيش بمُدخلات عشوائية.

13) docs/
- Final_Engineering_Report.md: هذا التقرير.
- Test_Plan.md: خطة الاختبار ثنائية اللغة.
- AI_Chat_Briefing.md: سجل موجز لأعمال AI.
- ملفات أخرى (اختيارية) للتوثيق الداخلي.

14) include/
- mkt_ksa_geo_sec.h: ترويسة C‑ABI المولّدة تلقائيًا.

15) ملفات ضبط الجذر
- Cargo.toml: تعريف الميزات بدون تبعيات افتراضيًا.
- cbindgen.toml: ضبط توليد الترويسة مع تقليل السطح المعرّض.
- rust-toolchain.toml: تحديد toolchain عند الحاجة (مثلاً لاستخدام ميري).

الترابط والتكامل:
- خادم std_http يستدعي التفتيش والبصمة والتليمترية، ويستخدم RLE اختياريًا؛ ويتكامل مع webhook وegress_guard لواجهات الإرسال/النسخ الاحتياطي والتنبيهات.
- التفتيش يتكامل مع التليمترية عبر current_risk لتكييف حدود الأحجام.
- البصمة تعتمد على core::digest السيادي.
- egress_guard يُستخدم انتقائيًا من التليمترية (النسخ الاحتياطي والتنبيهات) عند تفعيل ميزات الإخراج.
- واجهة C‑ABI تعرّض وظائف محددة بإحكام دون كشف تفاصيل داخلية.

------------------------------------------------------------------------------------------
جدول موجز للوظائف العامة حسب الوحدة (Arabic Only)
------------------------------------------------------------------------------------------

1) api/std_http
- run(addr, handler): تشغيل خادم HTTP صفري التبعيات بشكل مستمر.
- run_once(addr, handler): تشغيل طلب واحد (للاختبارات/التكامل).
- run_with_policy(addr, policy, handler): تشغيل الخادم مع سياسة تفتيش مبدئية.
- set_webhook_endpoint(ep): ربط منفذ Webhook داخلي لمعالجة POST /webhook/in.
- Response::json(status, body_str): إنشاء استجابة JSON موحّدة.
- smtp_send_simple(to, subject, body) [عند تفعيل smtp_std]: إرسال بريد بسيط عبر TCP دون TLS (للديمو فقط).

2) telemetry
- set_compression_enabled(on): تفعيل/تعطيل ضغط RLE الصادر.
- compression_enabled(): الاستعلام عن حالة الضغط.
- inc_inspected/block/…: عدادات عمليات الفحص/الحجب/الضغط/الويب هوك.
- record_event(kind, detail): تسجيل حدث كسطر NDJSON.
- metrics_json(): إرجاع قياسات العدادات بصيغة JSON.
- events_ndjson(): إرجاع سجل الأحداث بصيغة NDJSON.
- set_risk(v) / current_risk(): ضبط/قراءة مستوى الخطر (0..100) للتكيّف الأمني.
- export_events_ndjson(): استخراج الأحداث كبايتات.
- set_backup_consent(token)/clear_backup_consent(): إدارة موافقة النسخ الاحتياطي.
- has_consent(token): التحقق من الموافقة.
- configure_backup(interval, url, email, risk_threshold): إعداد الجدولة الآمنة للنسخ الاحتياطي.
- disable_backup(): تعطيل الجدولة.
- set_template(lang, subject, body): ضبط قوالب البريد (AR/EN).
- set_default_lang(lang): تحديد اللغة الافتراضية للتراسل.
- compose_backup_email(lang_opt, data): تركيب بريد النسخ الاحتياطي.
- set_alert_config(risk, email_opt, url_opt, cooldown): إعداد تنبيهات المخاطر.
- disable_alerts(): تعطيل التنبيهات.

3) security/inspection
- inspect_and_fingerprint(digest, limits, headers_raw, body_raw): تفتيش صارم مع حساب بصمة الإدخال.
- Limits::default(): حدود افتراضية للرؤوس/المتن.

4) security/inspection_policy
- InboundPolicy { allowed_methods, allowed_path_prefixes, denied_path_prefixes, allowed_content_types, limits }: سياسة تفتيش قابلة للتخصيص.
- InboundPolicy::default(): سياسة افتراضية آمنة مع مسارات حساسة ممنوعة.
- evaluate_request(method, path, headers_raw, body_raw): تقييم الطلب وإرجاع قرار وبصمة.

5) security/fingerprint
- fingerprint_payload(digest, headers_hint, body): حساب بصمة سلامة ثابتة للإخراج.

6) security/egress_guard
- policy::EgressPolicy { allowlist, denylist, allowed_ports, … }: سياسة الإخراج.
- resolver::preflight(policy, url): فحص مسبق للأمان قبل الخروج (مضيف، منفذ، عنوان IP عام).
- parser::parse(url): تحليل عنوان HTTP بسيط.

7) webhook
- parse_http_url(url): تحليل URL إلى (host, port, path) للاستخدام الداخلي.
- WebhookEndpoint/WebhookClient (traits): واجهات استقبال/إرسال ويب هوك (تطبيقات اختيارية).

8) utils
- helpers::ct_eq(a, b): مقارنة زمن ثابت لشرائح بايت لمنع قنوات التوقيت.
- helpers::calculate_distance(..): حسبة مسافة (تنفيذ بسيط قابل للاستبدال).
- helpers::aes_encrypt(data, key): دالة وهمية للتوسعة المستقبلية (تُعيد البيانات كما هي حاليًا).
- rle::rle_compress(buf) / rle::rle_decompress(buf): ضغط/فك ضغط بسيط عند تفعيل compress_rle.

9) ffi (عند تفعيل ffi_c)
- mkt_hmac_sha512(data_ptr, data_len, key_ptr, key_len, out_ptr): مثال توقيع/تجزئة على C‑ABI (مغلف آمن للحدود والنسخ).
- generate_adaptive_fingerprint(os, device_info, env_data) / free_fingerprint_string(ptr): مثال واجهة بصمة جهاز/بيئة عبر C.

ملاحظات:
- كل الوظائف الحساسة مغطاة بتليمترية وعدّادات لتتبع الأثر.
- المقارنات الأمنية للبصمات/التواقيع يُفضّل تنفيذها عبر ct_eq لمنع قنوات التوقيت.
- أي توسيع تشفيري (BLAKE3/HMAC‑SHA2) يُدمج خلف أعلام ميزات دون تبعيات خارجية.

------------------------------------------------------------------------------------------
جدول أعلام الميزات (Feature Flags) – وصف شامل (Arabic Only)
------------------------------------------------------------------------------------------
- default: لا ميزات مفعّلة افتراضيًا للحفاظ على صفر تبعيات.
- api_std_http: تفعيل خادم HTTP/1.1 الداخلي الصفري للتعامل مع /metrics و/backup و/alerts و/toggle و/risk.
- egress: تمكين طبقة الحراسة على الإخراج (سياسات المضيف/المنفذ والتحقق من العناوين العامة).
- egress_http_std (يعتمد على egress): عميل HTTP صفري بسيط لطلبات الخروج (POST/GET) دون TLS.
- compress_rle: تمكين ضغط/فك ضغط RLE تلقائيًا للأجسام الكبيرة واستصدار العدادات المصاحبة.
- smtp_std: مكوّن SMTP بسيط عبر TCP دون TLS (للعروض/الاختبارات فقط، خلف Proxy/Relay آمن بالإنتاج).
- ffi_c: تمكين واجهة C‑ABI وتوليد الترويسة `include/mkt_ksa_geo_sec.h` مع سطح API محدود.
- sign_hmac: تمكين واجهات توقيع HMAC (تشفير اختياري سيادي عند الطلب فقط).
- ledger_blake3: تمكين سجل أحداث مبني على BLAKE3 (اختياري للتدقيق).
- core_utils: أدوات نواة مساعدة (صفر تبعيات).
- input_validation: تمكين طبقات تحقق إدخال إضافية.
- config_loader: تحميل إعدادات (للاستخدام في الأمثلة/البيئة، اختياري).
- الأسماء التاريخية المُعرفة فارغًا لإسكات تحذيرات cfg (لا تفعّل تبعيات):
  db_mysql, core_full, api_actix, jwt, validation, jws, serde, secure_secrecy,
  webhook_out, egress_url, egress_reqwest, rt_tokio, geo_maxminddb, uuid_fmt,
  parallel, crypto_aesgcm, webhook_in.

ملاحظات تشغيلية:
- الإصدارات الإنتاجية يُوصى بتفعيل ما يلزم فقط (مبدأ أقل امتياز)، وتشغيل الخادم خلف Proxy آمن عند الحاجة إلى TLS.
- عند الحاجة لسلامة تشفيرية أعلى، يُفعّل sign_hmac/ledger_blake3 مستقبلًا مع مقارنات زمن ثابت.

------------------------------------------------------------------------------------------
جدول الثوابت/الثوابت الساكنة (Public/Internal Constants) – وصف موجز
------------------------------------------------------------------------------------------
- utils::precision::EPS_F32 / EPS_F64: حدود دقة عددية عائمة للتعامل الحذر مع المقارنات.
- utils::precision::EARTH_RADIUS_KM = 6371.0: نصف قطر الأرض التقريبي بالكيلومتر (للحسابات الجغرافية).
- core::geo_resolver::{MAX_ACCURACY_THRESHOLD, MIN_SIGNAL_STRENGTH, MAX_HISTORY_SIZE, QUANTUM_SECURITY_LEVEL}:
  ثوابت ضبط لمنطق دقة المواقع/الإشارات والتاريخ (مسارات اختيارية، غير مطلوبة للنواة الصفريّة).
- api::std_http::WEBHOOK_ENDPOINT: نقطة Webhook داخلية (OnceLock) تُضبط عند الحاجة.
- telemetry::{TELEMETRY, SCHED_STARTED, ALERT_STARTED}: مكونات OnceLock لإدارة حالة التليمترية والمهام الدورية والتنبيهات (داخلية).
- ffi::VERSION_STR: سلسلة الإصدار الثابتة للـ C‑ABI، تُسترجع عبر mkt_version_string().
- security::input_validator::{PHONE_RE, USERNAME_BLACKLIST}: موارد مهيّأة كسولًا للتحقق من المدخلات (داخلية).
- core::device_fp::{ENGINE, MOCK_KEY}: موارد كسولة التجهيز لمسارات بصمة الجهاز (اختيارية/داخلية).

تنبيه:
- بعض العناصر داخليّة (ليست pub) ومذكورة لأغراض التدقيق والفهم المعماري؛ السطح العام الموثّق متركّز في وحدات: api/std_http، security::{inspection, fingerprint, egress_guard}، telemetry، utils::{helpers,rle}، وواجهة ffi عند تفعيلها.

------------------------------------------------------------------------------------------
تفصيل الملفات المهمة داخل كل مجلد (Arabic Only)
------------------------------------------------------------------------------------------

src/api/
- mod.rs: فهرس وحدات API، لا منطق.
- std_http.rs: الخادم الداخلي الصفري، توجيه ونقاط القياس/النسخ/التنبيهات، تكامل التفتيش والتليمترية وRLE.
- alerts.rs: نقاط API للتنبيهات (قابلة للتوسعة، غير مطلوبة للنواة).
- auth.rs: هيكل مصادقة اختياري (placeholder للتوسعة).
- behavior.rs: واجهات تحليل سلوكي عليا (اختيارية).
- dashboard.rs: واجهة لوحة معلومات (اختيارية، لعرض المقاييس مستقبلًا).
- device.rs: واجهات أجهزة/بصمات (اختيارية).
- geo.rs: واجهات الجغرافيا (اختيارية).
- network.rs: واجهات الشبكة الوافدة/الخارجة (اختيارية).
- sensors.rs: واجهات حساسات (اختيارية).
- smart_access.rs: وصول ذكي (اختياري).
- weather.rs: واجهات طقس (اختيارية).
- ../bin/std_dashboard_demo.rs: مثال تشغيل للخادم القياسي وعرض القياسات.

src/security/
- mod.rs: فهرس الأمن.
- inspection.rs: تفتيش صارم للمدخلات/المخرجات وحساب بصمة الإدخال.
- inspection_policy.rs: سياسات allow/deny للمسارات وContent‑Type وحدود متكيفة مع الخطر.
- fingerprint.rs: بصمة سلامة مستقرة للإخراج.
- signing.rs: واجهة توقيع مجردة (اختيارية مستقبلًا).
- secret.rs: مخازن آمنة للسلاسل/البايتات مع إخفاء/صفرية اختيارية.
- crypto_provider.rs: واجهة موحّدة للتشفير/التوقيع/العشوائية بلا تبعيات.
- crypto_smart/{traits.rs, keystore.rs, envelope.rs, aad.rs, mod.rs}: إطار تشفير متقدم اختياري.
- egress_guard/mod.rs: تجميع حارس الإخراج.
- egress_guard/policy.rs: سياسة السماح/المنع والمنافذ والحدود/المهلات.
- egress_guard/resolver.rs: فحوص RFC1918/Link‑local/Unix sockets والتحقق من المضيفين والمنافذ.
- egress_guard/parser.rs: تحليل URL بسيط للإخراج.
- egress_guard/http_client.rs: عميل HTTP صفري بسيط (اختياري للتجارب).
- egress_guard/errors.rs: أخطاء الحارس.
- jws/{mod.rs, key.rs, errors.rs, canonicalize.rs}: JWS اختياري للتواقيع.
- jwt.rs: JWT اختياري (غير مفعّل افتراضيًا للحفاظ على السيادة).
- policy.rs: سياسات عامة للأدوار (اختياري).
- input_validator.rs: محقق إدخال (Regexات مهيّأة كسولًا) اختياري.
- ratelimit.rs: مقيّد معدّل اختياري.

src/core/
- mod.rs: فهرس النواة.
- digest.rs: تجزئة سيادية بسيطة مستخدمة في البصمات.
- geo_resolver.rs / geo_db.rs: قدرات جغرافيا اختيارية (مصادر وهمية/اختبارية).
- sensors_analyzer.rs / network_analyzer.rs: محللات سلوك/شبكة اختيارية.
- cross_location.rs: توحيد نتائج متعددة مواقع (اختياري).
- device_fp.rs: بصمة جهاز (اختياري مع FFI أمثلة).
- weather_val.rs: موفّر طقس وهمي/اختباري (اختياري).
- composite_verification.rs: تحقق مركب متعدد المصادر (اختياري).
- behavior_bio.rs: تحليل سلوكي حيوي (اختياري).
- history.rs: تواريخ وأحداث سلوكية (اختياري).

src/utils/
- mod.rs: فهرس الأدوات.
- helpers.rs: أدوات مساعدة عامة، تشمل ct_eq (مقارنة زمن ثابت) وواجهات مساعدة أخرى.
- rle.rs: ضغط/فك ضغط RLE.
- precision.rs: ثوابت دقة عددية.
- logger.rs: هيكل تسجيل بسيط (اختياري).
- cache.rs: تخزين مؤقت بسيط (اختياري).

src/telemetry/
- mod.rs: عدادات، أحداث NDJSON، مفاتيح تفعيل، مخاطرة متكيفة، نسخ احتياطي، قوالب بريد، تنبيهات.

src/webhook/
- mod.rs: واجهات WebhookEndpoint/WebhookClient وتحليل URL للاستخدام الداخلي.

src/webhook/guards/ — تفاصيل الحُرّاس لكل مسار (Arabic)
- ملاحظات عامة: جميع الحُرّاس تستخدم HMAC‑SHA512 افتراضيًا مع `anti_replay_on=true` ونافذة زمنية مبدئية 300000ms (5 دقائق). يتم التشديد تلقائيًا حسب العائلة:
  - حسّاسة جدًا: `/keys/*`, `/policy/*`, `/anti_replay/*`, `/memory/*` → `required=true`, `ts_window_ms≤120000`.
  - نسخ احتياطي/تنبيهات: `/backup/*`, `/alerts/*` → `required=true`, `ts_window_ms≤180000`.
  - ذكاء اصطناعي: `/ai/*` → `key_id=auth_hmac`, `ts_window_ms≤180000`.
  - شركاء: `/partner/*` → `key_id=partner_hmac`, `ts_window_ms≤300000`.
  - طقس: `/weather/*` → `key_id=weather_hmac`, `ts_window_ms≤180000`.
  - سحابة/تصدير: `/cloud/*`, `/export/*` → `required=true`, `ts_window_ms≤300000`.

- ai_ingest.rs → `/ai/ingest`: استقبال بيانات ذكاء اصطناعي خارجية للتحليل. افتراضيًا required=true، key_id=auth_hmac.
- ai_model_update.rs → `/ai/model/update`: تحديث نموذج AI من مصدر موثوق. required=true، key_id=auth_hmac.
- ai_feedback.rs → `/ai/feedback`: تلقي تغذية راجعة لتحسين النماذج. required=true، key_id=auth_hmac.
- weather_hook.rs → `/weather/hook`: استقبال بيانات طقس من مزوّد خارجي. required=true، key_id=weather_hmac.
- weather_alerts.rs → `/weather/alerts`: تنبيهات طقس سياقية. required=true، key_id=weather_hmac.
- alerts_in.rs → `/alerts/in`: تنبيهات أمنية خارجية. required=true.
- partner_events.rs → `/partner/events`: أحداث شريك خارجي. required=true، key_id=partner_hmac.
- partner_telemetry.rs → `/partner/telemetry`: تليمترية شريك. required=true، key_id=partner_hmac.
- geo_satellite.rs → `/geo/satellite`: بيانات أقمار صناعية. required=true.
- geo_maplayer.rs → `/geo/maplayer`: طبقات خرائط وقيود مناطق. required=true.
- webhook_in.rs → `/webhook/in`: استقبال داخلي عام. baseline: required=true.
- metrics.rs → `/metrics`: عرض مؤشرات خام. baseline: required=false (قابل للتشديد).
- events_ndjson.rs → `/events.ndjson`: بث أحداث NDJSON. baseline: required=false.
- fw_metrics.rs → `/fw/metrics`: مؤشرات الجدار الناري. baseline: required=false.
- fw_open.rs → `/fw/open`: فتح قاطع الدارة يدويًا. required=true (أمر حساس).
- fw_close.rs → `/fw/close`: إغلاق القاطع واستعادة الخدمة. required=true.
- backup_download.rs → `/backup/download`: تنزيل السجل. required=true.
- backup_send.rs → `/backup/send`: إرسال نسخة للخارج (محمي بـ Egress Guard). required=true.
- backup_consent.rs → `/backup/consent`: تعيين رمز موافقة للإجراءات الحساسة. required=true.
- backup_schedule.rs → `/backup/schedule`: جدولة نسخ احتياطي دوري. required=true.
- backup_schedule_disable.rs → `/backup/schedule/disable`: إلغاء الجدولة. required=true.
- backup_email.rs → `/backup/email`: إرسال نسخة عبر البريد (ميزة اختيارية). required=true.
- templates_set.rs → `/templates/set`: ضبط قوالب البريد. baseline: required=false.
- templates_default.rs → `/templates/default`: تعيين القالب الافتراضي. baseline: required=false.
- toggle.rs → `/toggle`: تبديل خصائص عرض/ضغط. baseline: required=false.
- dashboard.rs → `/dashboard`: لوحة HTML/JSON. baseline: required=false (مراقبة).
- export_csv.rs → `/export/csv`: تصدير CSV متوافق مع Excel. required=true.
- cloud_push.rs → `/cloud/push`: دفع مقاييس/بيانات إلى وجهة خارجية. required=true.
- webhook_guard_list.rs → `/webhook/guard/list`: سرد الحُرّاس المسجّلين. baseline: required=false.
- webhook_guard_set.rs → `/webhook/guard/set`: ضبط حارس لمسار. required=true.
- webhook_guard_disable.rs → `/webhook/guard/disable`: تعطيل حارس لمسار. required=true.
- webhook_guard_stats.rs → `/webhook/guard/stats`: إحصاءات التوقيع لكل مسار. baseline: required=false.
- keys_auto_config.rs → `/keys/auto/config`: إعداد تدوير المفاتيح التلقائي. required=true.
- keys_auto_disable.rs → `/keys/auto/disable`: تعطيل التدوير التلقائي. required=true.
- keys_create.rs → `/keys/create`: إنشاء مفتاح. required=true.
- keys_rotate.rs → `/keys/rotate`: تدوير مفتاح. required=true.
- keys_meta.rs → `/keys/meta`: عرض ميتاداتا المفاتيح. required=true.
- keys_export_hex.rs → `/keys/export_hex`: تصدير مواد المفاتيح (يتطلب consent). required=true.
- policy_get.rs → `/policy/get`: إرجاع السياسة الحية. required=true.
- policy_set.rs → `/policy/set`: تطبيق سياسة JSON وقت التشغيل. required=true.
- policy_set_dsl.rs → `/policy/set_dsl`: تطبيق سياسة DSL نصّية وقت التشغيل. required=true.
- alerts_set.rs → `/alerts/set`: ضبط نظام التنبيهات. required=true.
- alerts_disable.rs → `/alerts/disable`: تعطيل التنبيهات. required=true.
- anti_replay_purge_config.rs → `/anti_replay/purge/config`: تهيئة مسح مانع الإعادة. required=true.
- anti_replay_purge_disable.rs → `/anti_replay/purge/disable`: تعطيل المسح. required=true.
- anti_replay_purge_run.rs → `/anti_replay/purge/run`: تشغيل المسح فورًا. required=true.
- anti_replay_purge_status.rs → `/anti_replay/purge/status`: حالة المسح. baseline: required=false.
- memory_config.rs → `/memory/config`: ضبط حد/تفعيل الحارس الذاكري. required=true.
- memory_purge.rs → `/memory/purge`: تفريغ ذاكرة الأحداث. required=true.
- memory_status.rs → `/memory/status`: حالة الذاكرة. baseline: required=false.

src/ffi/
- mod.rs: واجهة C‑ABI (عند تفعيل ffi_c)، وظائف آمنة عبر حواجز unsafe محدودة.

src/log/ledger/
- mod.rs: فهرس سجل السلسلة.
- entry.rs: تمثيل إدخال سجل.
- writer.rs: إضافة إدخالات وحساب سلاسل التجزئة.
- verify.rs: تحقق من سلسلة السجل.
- digest.rs: تكامل مع BLAKE3 عند التفعيل (اختياري).
- anchor.rs: ارتساء checkpoint.
- errors.rs: أخطاء السجل.

src/db/
- mod.rs: فهرس طبقة البيانات (اختيارية).
- models.rs: نماذج بيانات.
- crud.rs: عمليات CRUD أمثلة (اختيارية، غير مفعلة افتراضيًا).

tests/
- http_integration.rs: اختبار تكامل /metrics وتشغيل run_once.
- fuzz_like.rs: اختبار شبه‑Fuzz للتفتيش بمدخلات عشوائية.

docs/
- Final_Engineering_Report.md: التقرير الهندسي الكامل.
- Test_Plan.md: خطة الاختبار ثنائية اللغة.
- AI_Chat_Briefing.md: سجل موجز.

include/
- mkt_ksa_geo_sec.h: ترويسة C‑ABI المولدة تلقائيًا (سطح محدود).

الجذر
- Cargo.toml: تعريف الحزمة وأعلام الميزات بدون تبعيات افتراضيًا.
- cbindgen.toml: ضبط توليد الترويسة.
- rust-toolchain.toml: toolchain (للـ nightly/Miri عند الحاجة).
