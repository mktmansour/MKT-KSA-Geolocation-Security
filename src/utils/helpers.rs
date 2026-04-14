/******************************************************************************************
    📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: helpers.rs
    المسار:    src/utils/helpers.rs

    دور الملف:
    يحتوي هذا الملف على دوال وأدوات مساعدة عامة تُستخدم في أجزاء متعددة من المشروع (مثل التشفير، حساب المسافة، إلخ).
    الهدف هو تجميع الوظائف المساعدة المتكررة في مكان واحد لسهولة الصيانة وإعادة الاستخدام.

    File Name: helpers.rs
    Path:     src/utils/helpers.rs

    File Role:
    This file contains general helper functions and utilities used across the project (e.g., encryption, distance calculation, etc.).
    The goal is to centralize common helper logic for easier maintenance and reuse.
******************************************************************************************/
use aes_gcm::aead::Aead;
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::Error;
use rand_core::OsRng;
use rand_core::RngCore;

/// Arabic: يقوم بتشفير البيانات باستخدام مفتاح مشترك. هذا تنفيذ وهمي.
///
/// # Errors
/// قد يعيد خطأً في حال فشل التشفير (حالياً لا يفشل لأنه وهمي).
///
/// English: Encrypts data using a shared key. This is a dummy implementation.
///
/// # Errors
/// Returns an error if encryption fails (currently never fails as it's a stub).
pub fn aes_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    if key.is_empty() {
        return Err(anyhow::anyhow!("encryption key must not be empty"));
    }

    // Normalize arbitrary key material into a fixed-size AES-256 key.
    let key_hash = blake3::hash(key);
    let cipher = Aes256Gcm::new_from_slice(key_hash.as_bytes())
        .map_err(|_| anyhow::anyhow!("failed to initialize AES-256-GCM"))?;

    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut output = Vec::with_capacity(12 + data.len() + 16);
    output.extend_from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))?;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Arabic: يحسب المسافة بالكيلومترات بين نقطتي خط عرض وخط طول (صيغة هافرساين).
/// هذا تنفيذ وهمي حاليًا.
///
/// English: Calculates the distance in kilometers between two lat/lon points (Haversine formula).
/// This is currently a dummy implementation.
#[must_use]
pub fn calculate_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;

    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    EARTH_RADIUS_KM * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_encrypt_returns_non_plaintext_with_nonce_prefix() {
        let key = b"this-is-a-very-strong-test-key-material";
        let data = b"sensitive-payload";

        let encrypted = aes_encrypt(data, key).expect("encryption should succeed");

        assert!(encrypted.len() > data.len());
        assert_ne!(&encrypted[12..], data);
    }

    #[test]
    fn haversine_distance_is_reasonable() {
        // Riyadh to Jeddah is approximately 847 km by great-circle distance.
        let distance = calculate_distance(24.7136, 46.6753, 21.4858, 39.1925);
        assert!((distance - 847.0).abs() < 25.0);
    }
}
