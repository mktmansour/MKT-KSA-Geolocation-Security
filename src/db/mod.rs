/******************************************************************************************
          📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    File Name: mod.rs
    Path:     src/db/mod.rs


    File Role:
    يعمل هذا الملف كـ "فهرس" لوحدة قاعدة البيانات. يقوم بتجميع والإعلان عن جميع الوحدات
    الفرعية المتعلقة بقاعدة البيانات، مما يسمح للمكونات الأخرى في التطبيق
    باستخدامها بسهولة.

    Main Tasks:
    1. الإعلان عن وحدات `models` (نماذج البيانات).
    2. الإعلان عن وحدات `crud` (عمليات قاعدة البيانات).

    --------------------------------------------------------------

    File Name: mod.rs
    Path:     src/db/mod.rs


    File Role:
    This file serves as the index for the database module. It aggregates and declares
    all database-related sub-modules, allowing other components in the application
    to use them easily.

    Main Tasks:
    1. Declare the `models` (data models) sub-module.
    2. Declare the `crud` (database operations) sub-module.
******************************************************************************************/

// Arabic: الإعلان عن الوحدات الفرعية لوحدة قاعدة البيانات
// English: Declare the sub-modules for the database module
pub mod crud;
pub mod migrations;
pub mod models;

// SQLite is the primary hardened backend in the current profile.
