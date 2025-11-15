/******************************************************************************************
        📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: digest.rs
    المسار: src/core/digest.rs

    وظيفة الملف:
    واجهة هضم عامة (Digest) للنواة صفر التبعيات مع تنفيذ افتراضي باستخدام
    `std::collections::hash_map::DefaultHasher` كـ Fallback بسيط. الهدف توحيد
    الاستدعاءات بحيث يمكن استبدال التنفيذ لاحقًا بتجزئة أقوى (مثل BLAKE3)
    خلف ميزات دون كسر المنطق الأساسي.

    File Name: digest.rs
    Path:     src/core/digest.rs

    File Role:
    Generic digest trait for the zero‑dependency core with a default fallback
    implementation using the standard library hasher. Strong digests (e.g.,
    BLAKE3) can be plugged in behind features without breaking core logic.
******************************************************************************************/

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Arabic: واجهة هضم عامة مبسطة.
/// English: Minimal generic digest interface.
pub trait CoreDigest {
    fn hash_bytes(&mut self, bytes: &[u8]);
    fn finalize_u64(self) -> u64;

    fn finalize_hex(self) -> String
    where
        Self: Sized,
    {
        format!("{:016x}", self.finalize_u64())
    }
}

/// Arabic: تنفيذ افتراضي باستخدام DefaultHasher من المعياري.
/// English: Default fallback digest using std's DefaultHasher.
#[derive(Default)]
pub struct StdHasherDigest(DefaultHasher);

impl CoreDigest for StdHasherDigest {
    fn hash_bytes(&mut self, bytes: &[u8]) {
        bytes.hash(&mut self.0);
    }

    fn finalize_u64(self) -> u64 {
        self.0.finish()
    }
}
