#![allow(clippy::missing_safety_doc)]

use core::ptr;
use std::os::raw::c_char;

use crate::security::secret::SecureBytes;
use crate::security::signing;

// Arabic: سلسلة نسخة ثابتة بصيغة C
// English: Static C string for crate version
static VERSION_STR: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// Arabic: يعيد مؤشر إلى سلسلة نسخة ثابتة (UTF-8, NUL-terminated). لا تتطلب تحرير.
/// English: Returns pointer to static version string (UTF-8, NUL-terminated). Do NOT free.
#[no_mangle]
pub extern "C" fn mkt_version_string() -> *const c_char {
    VERSION_STR.as_ptr() as *const c_char
}

/// Arabic: إصدار ABI ثابت (للتوافق الثنائي بين الإصدارات)
/// English: Stable ABI version for binary compatibility across releases
#[no_mangle]
pub extern "C" fn mkt_abi_version() -> u32 {
    1
}

/// Arabic: سلسلة SemVer الحالية (NUL-terminated)
/// English: Current SemVer string (NUL-terminated)
#[no_mangle]
pub extern "C" fn mkt_semver_string() -> *const c_char {
    VERSION_STR.as_ptr() as *const c_char
}

/// Arabic: يحسب HMAC-SHA512 على بيانات الإدخال ويكتب الناتج (64 بايت) في out_ptr.
/// - إرجاع 0 عند النجاح، أو رمز خطأ سلبي.
/// English: Computes HMAC-SHA512 over input and writes 64-byte tag to out_ptr.
/// - Returns 0 on success, negative error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn mkt_hmac_sha512(
    data_ptr: *const u8,
    data_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    if data_ptr.is_null() || key_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    if out_len < 64 {
        return -2;
    }

    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };
    let key = unsafe { core::slice::from_raw_parts(key_ptr, key_len) };
    let key = SecureBytes::new(key.to_vec());

    match signing::sign_hmac_sha512(data, &key) {
        Ok(tag) => {
            // write first 64 bytes (tag is 64 bytes)
            unsafe { ptr::copy_nonoverlapping(tag.as_ptr(), out_ptr, 64) };
            0
        }
        Err(_) => -3,
    }
}
