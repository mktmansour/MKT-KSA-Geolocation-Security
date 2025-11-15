/*!
Arabic: حارس الخروج (Egress/SSRF) — واجهة صفر تبعيات مع تنفيذات اختيارية.
English: Egress/SSRF guard — zero‑deps trait API with optional implementations.

الملفات | Files:
- `policy.rs`: سياسة allowlist/ports/redirects/limits.
- `resolver.rs`: فحص المضيف وIPs العامة (Resolve‑then‑Connect).
- `http_client.rs`: Trait عميل HTTP مع تنفيذ اختياري `reqwest` خلف ميزة `egress_reqwest`.
- `errors.rs`: تعريف الأخطاء.
*/

pub mod errors;
pub mod http_client;
pub mod parser;
pub mod policy;
pub mod resolver;

pub use errors::EgressError;
pub use policy::EgressPolicy;
pub use resolver::preflight;
