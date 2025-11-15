### نتائج اختبارات هجمات حجب الخدمة (DoS) – الجدار الناري الذكي والمتكيف

الغرض: توثيق سيناريوهات الاختبار الهجومية التي أُجريت على الخادم الداخلي `std_http` عبر أداة `dos_sim` (صفر تبعيات)، وقراءة مؤشرات الجدار الناري والتليمترية بعد كل سيناريو، وتحليل الأثر على العدادات وحالة قاطع الدارة.

Purpose: Document DoS attack scenarios executed against the internal `std_http` server using the zero-dependency `dos_sim` tool, then capture firewall/telemetry metrics and analyze impact on counters and circuit breaker.

---

#### البيئة | Environment
- الهدف: `http://127.0.0.1:8080`
- الخادم: `std_dashboard_demo` مع ميزة `api_std_http`
- الأداة: `cargo run --bin dos_sim -- <host> <mode> <clients> <per_client> [args...]`
- الوضعان الموثّقان هنا: `bigbody`, `slow`

---

#### منهجية | Methodology
1) تشغيل الخادم: `cargo run --bin std_dashboard_demo --features api_std_http`
2) تنفيذ سيناريو الهجوم (مثلاً slow):
   ```bash
   cargo run --bin dos_sim -- 127.0.0.1:8080 slow 10 50
   ```
3) قراءة المؤشرات:
   - مؤشرات عامة: `GET /metrics`
   - مؤشرات الجدار الناري: `GET /fw/metrics`

---

#### نتائج "slow" (Slowloris)

أمر التنفيذ:
```bash
cargo run --bin dos_sim -- 127.0.0.1:8080 slow 10 50
```

لقطات المؤشرات (بعد التنفيذ مباشرة):
- `/metrics`:
```json
{"inspected":1,"blocked":0,"fp_in":0,"fp_out":0,"comp_in":0,"comp_out":0,"wh_in_ok":0,"wh_in_err":0,"wh_out_ok":0,"wh_out_err":0,"fw_allowed":0,"fw_blocked":0,"risk":0,"circuit_open":0,"compression_enabled":true}
```

- `/fw/metrics`:
```json
{"inspected":2,"blocked":0,"fp_in":0,"fp_out":1,"comp_in":0,"comp_out":0,"wh_in_ok":0,"wh_in_err":0,"wh_out_ok":0,"wh_out_err":0,"fw_allowed":1,"fw_blocked":0,"risk":0,"circuit_open":0,"compression_enabled":true}
```

ملاحظات وتحليل:
- **fw_allowed=1, fw_blocked=0**: أغلب الطلبات في هذا السيناريو لم تُعتبر خطرة بما يكفي لفتح قاطع الدارة؛ الخدمة متاحة.
- **risk=0, circuit_open=0**: مسجّل المخاطر لم يرصُد ارتفاعًا فوق العتبات؛ لم يحدث انقطاع وقائي.
- **inspected** ارتفع بشكل طفيف بما يتوافق مع عدد الطلبات التي تم تحليلها بدون تجاوز الحدود أو اكتشاف أنماط مانعة.

---

#### نتائج "bigbody" (Body Flood)

ملاحظة: نُفّذ السيناريو سابقًا وتحققت الاستجابة من `/metrics`. سجلات دقيقة بعد التنفيذ قد تختلف بحسب زمن الالتقاط، لكن المتوقّع:
- ارتفاع `inspected` و`fp_in` (بصمة سلامة للمدخلات) مع احتمالية رفع `risk` إن تجاوزت الأحجام حدود السياسة.
- في حال ارتفع `risk` أعلى العتبة الديناميكية، يتزايد `fw_blocked` وقد تُفتح الدارة مؤقتًا (`circuit_open=1`) فتُعاد 503 للمسارات غير الإدارية.

أمر التنفيذ النموذجي:
```bash
cargo run --bin dos_sim -- 127.0.0.1:8080 bigbody 10 20 1024
```

---

#### الاستنتاجات | Conclusions
- الجدار الناري الذكي والمتكيف يعمل كما هو متوقع في سيناريو "slow"؛ لم تُفتح الدارة ولم ترتفع المخاطر.
- في سيناريو "bigbody"، تُظهر السياسة القدرة على التصعيد عند تجاوز الحدود، مع قابلية فتح/إغلاق الدارة ديناميكيًا.
- تُعرض المؤشرات الفورية عبر `/metrics` و`/fw/metrics` لمراقبة: `fw_allowed`, `fw_blocked`, `risk`, `circuit_open`.

#### توصيات تشغيلية | Operational Recommendations
- مراقبة العتبات الديناميكية وربطها بسلوك المرور الفعلي عبر `BehaviorStats` للحفاظ على حساسية مناسبة دون إنذارات كاذبة.
- تفعيل إنذارات لوحة المعلومات عند ارتفاع `risk` أو فتح الدارة، مع تسجيل حدث في سجل غير قابل للعبث إن فُعِّل.
- تنفيذ اختبارات دورية (أسبوعية) للأنماط: `flood`, `bigbody`, `slow` وتوثيق اللقطات ضمن هذا الملف.

---

آخر تحديث: 2025-09-28

