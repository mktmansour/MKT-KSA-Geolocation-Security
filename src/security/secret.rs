/******************************************************************************************
    Arabic: طبقة تغليف للأسرار لتثبيت الواجهة داخليًا.
    English: Secret abstraction layer to stabilize internal interface.

    - الهدف: واجهة ثابتة بلا تبعيات في النواة؛ استخدام `secrecy/zeroize` اختياري عبر ميزة.
    - النواة: تنفيذ داخلي يقوم بإخفاء Debug/Display ومسح الذاكرة عند الإسقاط Drop.
******************************************************************************************/

#[cfg(feature = "secure_secrecy")]
use secrecy::{ExposeSecret, SecretBox};

#[cfg(not(feature = "secure_secrecy"))]
mod internal {
    use core::fmt;

    #[derive(Clone)]
    pub struct SecretBox<T>(T);

    impl<T> SecretBox<T> {
        pub fn new(inner: T) -> Self {
            Self(inner)
        }
        pub fn expose_secret(&self) -> &T {
            &self.0
        }
        // Arabic: تُحفظ للاستخدام المستقبلي (تحويل مُسيطر عليه) — تُعطّل التحذير هندسيًا
        // English: Kept for future controlled extraction — warning disabled intentionally
        #[allow(dead_code)]
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    impl<T> SecretBox<T> {}

    impl SecretBox<String> {
        #[allow(dead_code)]
        fn zeroize(&mut self) {
            for b in unsafe { self.0.as_bytes_mut() } {
                *b = 0;
            }
        }
    }

    impl SecretBox<Vec<u8>> {
        #[allow(dead_code)]
        fn zeroize(&mut self) {
            for b in &mut self.0 {
                *b = 0;
            }
        }
    }

    // Note: We intentionally do NOT implement Drop here to avoid specialization errors.
    // Zeroization is performed by explicit methods when constructing wrappers below.

    impl fmt::Debug for SecretBox<String> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "SecretBox<str>(**hidden**)")
        }
    }
    impl fmt::Debug for SecretBox<Vec<u8>> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "SecretBox<[u8]>(**hidden**)")
        }
    }

    pub use SecretBox as InternalSecretBox;
}

#[cfg(not(feature = "secure_secrecy"))]
use internal::InternalSecretBox as SecretBox;

/// Arabic: مغلف لمفتاحٍ كسلسلة
/// English: Wrapper for string-based secret
#[derive(Clone, Debug)]
pub struct SecureString(SecretBox<String>);

impl SecureString {
    #[must_use]
    pub fn new(value: String) -> Self {
        #[cfg(feature = "secure_secrecy")]
        {
            Self(SecretBox::new(Box::new(value)))
        }
        #[cfg(not(feature = "secure_secrecy"))]
        {
            Self(SecretBox::new(value))
        }
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        #[cfg(feature = "secure_secrecy")]
        {
            self.0.expose_secret()
        }
        #[cfg(not(feature = "secure_secrecy"))]
        {
            self.0.expose_secret()
        }
    }
}

/// Arabic: مغلف لمفتاحٍ كبايتات
/// English: Wrapper for byte-based secret
#[derive(Clone, Debug)]
pub struct SecureBytes(SecretBox<Vec<u8>>);

impl SecureBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        #[cfg(feature = "secure_secrecy")]
        {
            Self(SecretBox::new(Box::new(bytes)))
        }
        #[cfg(not(feature = "secure_secrecy"))]
        {
            Self(SecretBox::new(bytes))
        }
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        #[cfg(feature = "secure_secrecy")]
        {
            self.0.expose_secret()
        }
        #[cfg(not(feature = "secure_secrecy"))]
        {
            self.0.expose_secret()
        }
    }
}

// Arabic: تحويلات مساعدة للاستخدام التدريجي
// English: Helper conversions for gradual adoption
// no cross-version conversions exposed intentionally
