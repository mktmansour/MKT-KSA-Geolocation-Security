/*!
Arabic: الواجهة العامة لمكتبة `MKT_KSA_Geolocation_Security`

توفر هذه المكتبة واجهات معيارية لاستخدام المحركات الأساسية (Core)، ووحدات الأمان (Security)،
ووحدات الأدوات (Utils)، وقاعدة البيانات (DB)، وطبقة الـ API (اختياري).

تدعم أنماط الربط التالية:
- rlib: للاستخدام من صناديق Rust الأخرى.
- cdylib/staticlib: للربط عبر C-ABI من لغات أخرى (C/C++/Python/.NET/Java...)

English: Public library surface for `MKT_KSA_Geolocation_Security`

This crate exposes modular interfaces for the core engines, security modules,
utilities, database layer, and (optionally) the API layer.

Supported crate types:
- rlib: to be used as a normal Rust library.
- cdylib/staticlib: to be linked via C-ABI from other languages.
*/

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod api;
pub mod core;
pub mod crypto;
// Database module removed - using webhook architecture instead
pub mod oauth2;
pub mod security;
pub mod utils;
pub mod webhook;
#[cfg(feature = "compress_rle")]
pub mod utils_rle_alias {
    pub use crate::utils::rle::*;
}
#[cfg(feature = "ffi_c")]
pub mod ffi;
pub mod telemetry;

// Re-export AppState to make API handlers importable from the lib root when needed
#[cfg(feature = "core_full")]
pub mod app_state;
#[cfg(feature = "core_full")]
pub use app_state::AppState;

// Re-exports of commonly used items for ergonomic public API
#[cfg(feature = "core_full")]
pub use crate::core::geo_resolver::{GeoLocation, GeoResolver};
pub use crate::security::signing;
pub use crate::utils::precision;
