/******************************************************************************************
        📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: geo_db.rs
    المسار: src/core/geo_db.rs

    وظيفة الملف:
    تعريف واجهة قاعدة بيانات جغرافية (GeoDb) للنواة صفر التبعيات مع تنفيذ افتراضي
    NoGeoDb يعيد "غير متاح". يمكن تقديم تنفيذ MaxMindDB لاحقًا خلف ميزة `geo_maxminddb`.

    File Name: geo_db.rs
    Path:     src/core/geo_db.rs

    File Role:
    Defines a zero‑dependency GeoDb trait with a default NoGeoDb implementation.
    A real MaxMindDB-backed implementation can be provided behind `geo_maxminddb`.
******************************************************************************************/

use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoDbError {
    NotAvailable,
}

impl Display for GeoDbError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "geo database not available")
    }
}
impl Error for GeoDbError {}

#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
}

pub trait GeoDb {
    fn lookup_ip(&self, ip: &str) -> Result<GeoInfo, GeoDbError>;
}

#[derive(Default, Debug, Clone, Copy)]
pub struct NoGeoDb;

impl GeoDb for NoGeoDb {
    fn lookup_ip(&self, _ip: &str) -> Result<GeoInfo, GeoDbError> {
        Err(GeoDbError::NotAvailable)
    }
}
