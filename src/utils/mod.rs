/******************************************************************************************

* 📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
*
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

اسم الملف: mod.rs
    المسار: src/utils/mod.rs

    وظيفة الملف:
    هذا الملف يعمل كفهرس (index) لوحدة الأدوات المساعدة. يقوم بتجميع والإعلان عن جميع الوحدات
    الفرعية المتعلقة بالأدوات المساعدة (التخزين المؤقت، الدوال المساعدة، التسجيل)،
    مما يسمح لباقي أجزاء المشروع باستخدامها بسهولة.

    File Name: mod.rs
    Path:     src/utils/mod.rs

    File Role:
    This file serves as the index for the utils module. It aggregates and declares
    all utility-related sub-modules (cache, helpers, logger), allowing other parts of the project to use them easily.
******************************************************************************************/

// Arabic: وحدة التخزين المؤقت (Cache)
// English: Cache module
pub mod cache;

// Arabic: وحدة الدوال المساعدة العامة
// English: General helpers module
pub mod helpers;

// Arabic: وحدة التسجيل (Logging)
// English: Logger module
pub mod logger;

// Arabic: وحدة الدقة والحسابات الرقمية والجغرافية
// English: Precision and numeric/geo utilities module
pub mod precision;

// Arabic: وحدة ضغط RLE اختيارية — لا تُضمّن إلا مع ميزة compress_rle
// English: Optional RLE compression module — compiled only with feature compress_rle
#[cfg(feature = "compress_rle")]
pub mod rle;
