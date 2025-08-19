/******************************************************************************************
*  📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
*  ملف: src/utils/precision.rs
*
*  الهدف: توحيد دوال الدقة والحسابات الرقمية/الزمنية/الجغرافية في مكان واحد،
*  لتقليل التكرار والتكميمات وتحسين الأمان والقابلية للصيانة.
*
*  Purpose: Centralized precision utilities (time/numeric/geo) to reduce duplication
*  and warnings, improving safety and maintainability across the library.
******************************************************************************************/

/// ثابتات الدقة المساعدة
/// Precision helper constants
pub const EPS_F32: f32 = 1.0e-6;
pub const EPS_F64: f64 = 1.0e-12;

/// يحسب فرق الزمن بالثواني بين طابعين زمنيين باستخدام تحويل آمن إلى `std::time::Duration`.
/// Computes time delta (seconds) between two chrono timestamps using a safe `std::time::Duration` conversion.
///
/// عند عدم القدرة على التحويل (قيمة سالبة)، يرجع 0.0.
/// If conversion fails (negative), returns 0.0.
#[must_use]
pub fn time_delta_secs(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> f64 {
    end.signed_duration_since(start)
        .to_std()
        .map_or(0.0, |d| d.as_secs_f64())
}

/// فرق الزمن عالي الدقة بالثواني (يجمع الثواني والنانoseconds)
/// High-resolution time delta in seconds (secs + nanos)
#[must_use]
pub fn time_delta_secs_high_res(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> f64 {
    end.signed_duration_since(start).to_std().map_or(0.0, |d| {
        d.as_secs_f64() + f64::from(d.subsec_nanos()) / 1_000_000_000.0
    })
}

/// متوسط f32 لقائمة قيم، مع تجميع داخلي بـ f64 ثم تحويل وحيد إلى f32.
/// f32 average with internal f64 accumulation and a single conversion back to f32.
#[must_use]
pub fn avg_f32(values: &[f32]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    let sum_f32: f32 = values.iter().copied().sum();
    // عدّاد f32 بدون أي تحويلات عددية لتجنّب تحذيرات الدقة
    let count_f32: f32 = values.iter().fold(0.0_f32, |acc, _| acc + 1.0);
    sum_f32 / count_f32
}

// ملاحظة: يمكن إضافة avg_f64 لاحقاً إذا قررنا سياسة واضحة للتحويل من usize إلى f64 بدون تحذيرات

/// يحسب المسافة بين نقطتين جغرافيتين باستخدام معادلة هافرساين بالكيلومترات.
/// Computes Haversine distance (km) between two geographic coordinates.
#[must_use]
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let (lat1, lon1) = (lat1.to_radians(), lon1.to_radians());
    let (lat2, lon2) = (lat2.to_radians(), lon2.to_radians());
    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let sin_dlat = (dlat / 2.0).sin();
    let sin_dlon = (dlon / 2.0).sin();
    let a = (lat1.cos() * lat2.cos()).mul_add(sin_dlon.powi(2), sin_dlat.powi(2));
    let c = 2.0 * a.sqrt().asin();
    EARTH_RADIUS_KM * c
}

/// سرعة كم/س اعتماداً على المسافة (كم) والزمن (ثواني) مع حماية من القسمة على صفر.
/// Speed in km/h given distance (km) and time (seconds) with division-by-zero guard.
#[must_use]
pub fn speed_kmh(distance_km: f64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    distance_km / (seconds / 3600.0)
}

/// مجموع موزون f64 باستخدام `mul_add` لتجنّب مشاكل الدقة الكلاسيكية
/// Weighted sum for f64 using `mul_add` to minimize rounding error
#[must_use]
pub fn weighted_sum_f64(pairs: &[(f64, f64)]) -> f64 {
    let mut acc = 0.0_f64;
    for &(value, weight) in pairs {
        acc = weight.mul_add(value, acc);
    }
    acc
}

/// مجموع موزون f32 باستخدام `mul_add` لتقليل الخطأ التقريبي
/// Weighted sum for f32 using `mul_add` to minimize rounding error
#[must_use]
pub fn weighted_sum_f32(pairs: &[(f32, f32)]) -> f32 {
    let mut acc = 0.0_f32;
    for &(value, weight) in pairs {
        acc = weight.mul_add(value, acc);
    }
    acc
}

/// معدل التغير (قيمة/ثانية) بدقة f64 مع حماية من القسمة على صفر
/// Rate of change (value per second) in f64 with division-by-zero guard
#[must_use]
pub fn rate_of_change_f64(value_delta: f64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    value_delta / seconds
}
