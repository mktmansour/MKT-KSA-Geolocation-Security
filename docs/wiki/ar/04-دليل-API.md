# 04. دليل API

تقدم هذه الصفحة مرجعًا عمليًا لاستهلاك API والتكامل معها.

## 1. أساس عقد الطلب

الرؤوس الموصى بها:

- X-API-Key
- Authorization: Bearer <token>
- X-Request-ID
- Content-Type: application/json

## 2. مجموعات المسارات

| المجال | مثال مسار | الهدف |
|---|---|---|
| المستخدم/التفويض | /api/users/{id} | جلب المستخدم والتحقق من الصلاحية |
| جغرافي | /api/verify_geo | اتساق الموقع والثقة |
| الجهاز | /api/verify_device | ثقة بصمة الجهاز |
| السلوك | /api/analyze_behavior | تحليل الشذوذ السلوكي |
| الشبكة | /api/analyze_network | مخاطر VPN/Proxy |
| الحساسات | /api/analyze_sensors | شذوذ سلامة الإشارات |
| الطقس | /api/verify_weather | اتساق السياق |
| الوصول الذكي | /api/smart_access_verify | قرار ثقة مركب |
| التنبيهات | /api/alerts/trigger | دورة التنبيه الأمني |

## 3. نموذج الأخطاء

تعيد API استجابات منظمة لمسارات المصادقة والتفويض والمنع المرتبط بالمخاطر.

ممارسات مهمة:

- اعتمد على error codes ثابتة في العميل.
- انشر request id عبر كل الطبقات.
- تعامل مع retry guidance كإشارة سياسة.

## 4. مثال استدعاء API

تم حذف رؤوس المصادقة عمدًا من هذا المثال العام، ويجب حقنها من إعداد عميل آمن داخل بيئة التشغيل.

```bash
curl -sS -X POST http://127.0.0.1:8080/api/alerts/trigger \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: wiki-alert-001" \
  -d '{"entity_id":"00000000-0000-0000-0000-000000000000","entity_type":"user","alert_type":"intrusion","severity":"high","details":{"source":"wiki"}}'
```

## 5. إرشادات التكامل

- أنشئ wrapper مركزي لاستدعاءات HTTP.
- خزّن status code و error code و request id.
- أضف retry policy فقط في المسارات المسموح بها.
- راقب latency ومعدلات المنع لكل endpoint.

## 6. الخطوة التالية

انتقل إلى [05. النشر والتشغيل](05-النشر-والتشغيل.md).

## كلمات بحث

مرجع API أمني Rust، واجهات تحقق جغرافي، API الوصول الذكي، رؤوس أمان Actix Web.
