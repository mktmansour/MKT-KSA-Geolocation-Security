/******************************************************************************************
    Arabic: طبقة تغليف للأسرار لتثبيت الواجهة داخليًا.
    English: Secret abstraction layer to stabilize internal interface.

    - الهدف: عدم ربط بقية المشروع مباشرة بأنواع crate `secrecy` حتى نتمكن من
      ترقية الإصدار لاحقًا (مثل 0.10.x) دون تغيير المنطق في بقية الشيفرة.
    - الهدف الأمني: الإبقاء على إخفاء Debug/Display ومسح الذاكرة عبر zeroize،
      مع سهولة الاستبدال لاحقًا.
******************************************************************************************/

use secrecy::ExposeSecret;
use secrecy::SecretBox;

/// Arabic: مغلف لمفتاحٍ كسلسلة
/// English: Wrapper for string-based secret
pub struct SecureString(SecretBox<String>);

impl SecureString {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Arabic: مغلف لمفتاحٍ كبايتات
/// English: Wrapper for byte-based secret
pub struct SecureBytes(SecretBox<Vec<u8>>);

impl SecureBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

// Arabic: تحويلات مساعدة للاستخدام التدريجي
// English: Helper conversions for gradual adoption
// no cross-version conversions exposed intentionally
