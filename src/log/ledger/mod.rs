/*! 
Arabic: سجل غير قابل للعبث (نواة صفر تبعيات) — append-only مع Digest قابل للاستبدال.
English: Tamper‑evident log (zero‑deps core) — append‑only with pluggable Digest.

الملفات | Files:
- `entry.rs`: نموذج الإدخال (نص بسيط بلا Serde).
- `digest.rs`: واجهة Digest وتنفيذ BLAKE3 اختياري (يمكن استبداله بتنفيذ داخلي لاحقًا).
- `writer.rs`: إضافة إدخالات بكتابة ذرّية مبسطة.
- `errors.rs`: أخطاء داخلية بلا thiserror.
- `verify.rs`: التحقق من سلسلة التجزئة للملف بالكامل.
- `anchor.rs` (اختياري عبر `jws`): مراسي يومية موقّعة، لا تُعد جزءًا من النواة.
*/

pub mod entry;
pub mod digest;
pub mod writer;
pub mod errors;
pub mod verify;
#[cfg(feature = "jws")]
pub mod anchor;

pub use entry::LedgerEntry;
pub use errors::LedgerError;

