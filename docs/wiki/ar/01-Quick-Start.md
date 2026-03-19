# 01. البدء السريع

هذه الصفحة تنقلك من بيئة فارغة إلى خدمة آمنة تعمل فعليًا.

## 1. المتطلبات

- أداة Rust متوافقة مع ملف القفل في المشروع.
- بيئة Linux أو حاوية تطوير.
- متغيرات بيئة إلزامية للتشغيل الآمن.

## 2. الاستنساخ والبناء

```bash
git clone https://github.com/mktmansour/MKT-KSA-Geolocation-Security.git
cd MKT-KSA-Geolocation-Security
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## 3. تشغيل الخدمة

```bash
API_KEY=change_me \
JWT_SECRET=replace_with_a_long_secret_32_chars_min \
DATABASE_URL=sqlite://data/app.db \
SECURITY_PROFILE=strict \
cargo run
```

## 4. أول نداء تحقق

```bash
curl -sS http://127.0.0.1:8080/api/users/00000000-0000-0000-0000-000000000000 \
  -H "X-API-Key: change_me" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "X-Request-ID: quickstart-001"
```

السلوك المتوقع:

- استجابة JSON منظّمة وواضحة.
- أخطاء أمنية ثابتة عند إدخال غير صحيح.
- تتبع طلب عبر request id.

## 5. التكامل السريع كمكتبة

```rust
use mkt_ksa_geo_sec::core::device_fp::DeviceFingerprint;

fn main() {
    let fp = DeviceFingerprint::new();
    let out = fp.generate_adaptive_fingerprint("device123", "user1");
    println!("{}", out);
}
```

## 6. الخطوة التالية

انتقل إلى [02. المعمارية](02-Architecture.md) لفهم تدفق النظام الكامل.

## كلمات بحث

بدء سريع Rust أمان API، تشغيل Actix Web، إعداد محرك التحقق الجغرافي، تكامل مكتبة Rust الأمنية.
