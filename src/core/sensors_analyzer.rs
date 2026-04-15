/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: sensors_analyzer.rs
    المسار:    src/core/sensors_analyzer.rs
    دور الملف:
    محرك تحليل بيانات الحساسات، مصمم كمكون خفيف، سريع، ومركّز.
    يقوم بالتحقق من صحة بيانات الحساسات، تحليلها للكشف عن الشذوذ،
    وإصدار "شهادة" موثوقة وموقعة رقميًا.
    المهام الأساسية:
    1.  توفير محرك تحليل مركّز (`SensorsAnalyzerEngine`).
    2.  استخدام `Trait` لحقن نماذج كشف الشذوذ (`SensorAnomalyDetector`).
    3.  الفصل التام بين منطق التحليل وإدارة الحالة (التاريخ يُمرر كمدخل).
    4.  ضمان عدم التلاعب بالنتائج عبر التوقيع الرقمي (HMAC-SHA384).
    5.  تقديم تطبيقات افتراضية ذكية كنقطة بداية للتحليل.
    --------------------------------------------------------------
    File Name: sensors_analyzer.rs
    Path:     src/core/sensors_analyzer.rs
    File Role:
    A lightweight, fast, and focused sensor data analysis engine. It validates
    sensor data, analyzes it for anomalies, and issues a trusted,
    digitally signed "certificate" of the analysis.

    Main Tasks:
    1.  Provide a focused analysis engine (`SensorsAnalyzerEngine`).
    2.  Use a `Trait` to inject anomaly detection models (`SensorAnomalyDetector`).
    3.  Completely separate analysis logic from state management (history is an input).
    4.  Ensure result integrity via digital signatures (HMAC-SHA384).
    5.  Provide smart default implementations as a starting point for analysis.
******************************************************************************************/

use crate::security::secret::SecureBytes;
use crate::security::signing::sign_hmac_sha384;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

// ================================================================
// الأخطاء المخصصة للوحدة
// Custom Module Errors
// ================================================================
#[derive(Debug, Error)]
pub enum SensorError {
    #[error("Invalid sensor data provided: {0}")]
    InvalidData(String),
    #[error("Anomaly detector failed: {0}")]
    DetectorFailed(String),
    #[error("Failed to generate or verify signature: {0}")]
    SignatureError(String),
    #[error("Invalid secret key for signing")]
    InvalidKey,
}

// ================================================================
// نماذج البيانات الأساسية
// Core Data Models
// ================================================================

/// يمثل قراءة واحدة من حساس.
/// Represents a single reading from a sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReading {
    pub sensor_type: String, // e.g., "AccelerometerX", "GyroscopeY"
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}

/// يمثل "شهادة" التحليل النهائية الموقعة.
/// Represents the final, signed "certificate" of analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorAnalysisResult {
    pub reading: SensorReading,
    pub anomaly_score: f32, // 0.0 (Normal) to 1.0 (Highly Anomalous)
    pub is_tampered: bool,  // A flag indicating likely tampering
    pub reasoning: String,
    pub signature: String,
}

// ================================================================
// واجهة (Trait) لكاشف الشذوذ في بيانات الحساسات
// Trait for the Sensor Data Anomaly Detector
// ================================================================
#[async_trait]
pub trait SensorAnomalyDetector: Send + Sync {
    /// يحلل القراءة الحالية مقارنة بالبيانات التاريخية.
    /// Analyzes the current reading against historical data.
    async fn analyze(
        &self,
        current: &SensorReading,
        history: &[SensorReading],
    ) -> Result<(f32, String), SensorError>;
}

// ================================================================
// محرك تحليل الحساسات (SensorsAnalyzerEngine)
// The Sensor Analysis Engine
// ================================================================
pub struct SensorsAnalyzerEngine {
    signing_key: SecureBytes,
    detector: Arc<dyn SensorAnomalyDetector>,
}

impl SensorsAnalyzerEngine {
    /// إنشاء محرك جديد مع حقن التبعيات.
    /// Creates a new engine with dependency injection.
    pub fn new(signing_key: SecureBytes, detector: Arc<dyn SensorAnomalyDetector>) -> Self {
        Self {
            signing_key,
            detector,
        }
    }

    /// تنفيذ تحليل كامل لقراءة حساس واحدة.
    /// Executes a full analysis for a single sensor reading.
    ///
    /// # Errors
    /// Returns `SensorError` if input is invalid, detector fails, or signature generation fails.
    pub async fn analyze(
        &self,
        reading: SensorReading,
        history: &[SensorReading],
    ) -> Result<SensorAnalysisResult, SensorError> {
        // 1. التحقق من صحة المدخلات
        // 1. Validate the input
        Self::validate_reading(&reading)?;

        // 2. تحليل الشذوذ باستخدام الكاشف المحقون
        // 2. Analyze for anomalies using the injected detector
        let (anomaly_score, reasoning) = self.detector.analyze(&reading, history).await?;

        // 3. بناء "شهادة" التحليل
        // 3. Construct the analysis "certificate"
        let mut result = SensorAnalysisResult {
            reading,
            anomaly_score,
            is_tampered: anomaly_score > 0.8, // عتبة تلاعب قابلة للتكوين
            reasoning,
            signature: String::new(), // سيتم ملؤها لاحقًا
        };

        // 4. توقيع الشهادة لضمان عدم التلاعب بها
        // 4. Sign the certificate to ensure its integrity
        let signature = self.sign_result(&result)?;
        result.signature = signature;

        Ok(result)
    }

    /// يتحقق من منطقية بيانات القراءة.
    /// Validates the logical sanity of the reading data.
    fn validate_reading(reading: &SensorReading) -> Result<(), SensorError> {
        if reading.sensor_type.trim().is_empty() {
            return Err(SensorError::InvalidData(
                "Sensor type cannot be empty.".to_string(),
            ));
        }
        if !reading.value.is_finite() {
            return Err(SensorError::InvalidData(
                "Sensor value must be a finite number.".to_string(),
            ));
        }
        Ok(())
    }

    /// يوقع على نتيجة التحليل باستخدام مفتاح HMAC-SHA384.
    /// Signs the analysis result using an HMAC-SHA384 key.
    fn sign_result(&self, result: &SensorAnalysisResult) -> Result<String, SensorError> {
        let mut result_to_sign = result.clone();
        result_to_sign.signature = String::new();
        let serialized = serde_json::to_vec(&result_to_sign)
            .map_err(|e| SensorError::SignatureError(e.to_string()))?;
        let sig = sign_hmac_sha384(&serialized, &self.signing_key)
            .map_err(|_| SensorError::InvalidKey)?;
        Ok(hex::encode(sig))
    }
}

// ================================================================
// التطبيق الافتراضي لكاشف الشذوذ
// Default Implementation for the Anomaly Detector
// ================================================================
pub struct DefaultSensorAnomalyDetector {
    /// الحد الأقصى لمعدل التغير المسموح به لكل نوع حساس.
    /// Maximum allowed rate of change per sensor type.
    pub rate_change_thresholds: HashMap<String, f64>,
}

impl Default for DefaultSensorAnomalyDetector {
    fn default() -> Self {
        let mut thresholds = HashMap::new();
        thresholds.insert("Accelerometer".to_string(), 10.0);
        thresholds.insert("Gyroscope".to_string(), 360.0);
        Self {
            rate_change_thresholds: thresholds,
        }
    }
}

impl DefaultSensorAnomalyDetector {
    /// إنشاء كاشف افتراضي جديد مع عتبات محددة.
    /// Creates a new default detector with specific thresholds.
    #[must_use]
    pub const fn create(thresholds: HashMap<String, f64>) -> Self {
        Self {
            rate_change_thresholds: thresholds,
        }
    }
}

#[async_trait]
impl SensorAnomalyDetector for DefaultSensorAnomalyDetector {
    async fn analyze(
        &self,
        current: &SensorReading,
        history: &[SensorReading],
    ) -> Result<(f32, String), SensorError> {
        // البحث عن آخر قراءة من نفس نوع الحساس في التاريخ
        // Find the last reading of the same sensor type in history
        let last_reading = history
            .iter()
            .rev()
            .find(|r| r.sensor_type == current.sensor_type);

        let (mut score, mut reasoning) = (0.05, "Normal fluctuation.".to_string());

        if let Some(last) = last_reading {
            let duration = (current.timestamp - last.timestamp)
                .to_std()
                .unwrap_or_else(|_| std::time::Duration::from_secs(0));
            let time_delta = duration.as_secs_f64();
            if time_delta > 0.001 {
                // تجنب القسمة على صفر
                let value_delta = (current.value - last.value).abs();
                let rate_of_change = value_delta / time_delta;

                // الحصول على العتبة المخصصة لهذا الحساس، أو استخدام قيمة افتراضية عالية
                // Get the threshold for this sensor, or use a high default
                let threshold = self
                    .rate_change_thresholds
                    .get(&current.sensor_type)
                    .copied()
                    .unwrap_or(1000.0);

                if rate_of_change > threshold {
                    score = 0.9;
                    reasoning = format!(
                        "Anomaly: Unrealistic rate of change detected ({rate_of_change:.2} units/sec)."
                    );
                }
            }
        }

        Ok((score, reasoning))
    }
}

// ================================================================
// اختبارات شاملة (محدثة بالكامل)
// Comprehensive Tests (Fully Updated)
// ================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha384;
    use std::time::Duration;

    // --- Mock detector for precise testing ---
    struct MockTamperDetector;
    #[async_trait]
    impl SensorAnomalyDetector for MockTamperDetector {
        async fn analyze(
            &self,
            _: &SensorReading,
            _: &[SensorReading],
        ) -> Result<(f32, String), SensorError> {
            Ok((0.95, "Tampering detected by mock!".to_string()))
        }
    }

    fn setup_test_engine(detector: Arc<dyn SensorAnomalyDetector>) -> SensorsAnalyzerEngine {
        let key = crate::security::secret::SecureBytes::new(vec![42; 48]); // 48 bytes for HMAC-SHA384
        SensorsAnalyzerEngine::new(key, detector)
    }

    fn create_reading(sensor_type: &str, value: f64) -> SensorReading {
        SensorReading {
            sensor_type: sensor_type.to_string(),
            value,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_normal_reading_with_default_detector() {
        let engine = setup_test_engine(Arc::new(DefaultSensorAnomalyDetector::create(
            HashMap::new(),
        )));
        let reading = create_reading("Accelerometer", 1.5);

        let result = engine.analyze(reading, &[]).await.unwrap();

        assert!(result.anomaly_score < 0.1);
        assert!(!result.is_tampered);
        assert!(result.reasoning.contains("Normal"));
    }

    #[tokio::test]
    async fn test_mock_detector_always_finds_tampering() {
        let engine = setup_test_engine(Arc::new(MockTamperDetector));
        let reading = create_reading("Gyroscope", 10.0);

        let result = engine.analyze(reading, &[]).await.unwrap();

        assert!((result.anomaly_score - 0.95).abs() < f32::EPSILON);
        assert!(result.is_tampered);
        assert!(result.reasoning.contains("mock"));
    }

    #[tokio::test]
    async fn test_default_detector_finds_unrealistic_change() {
        let engine = setup_test_engine(Arc::new(DefaultSensorAnomalyDetector::create(
            HashMap::new(),
        )));

        let mut history = vec![];

        // 1. Initial reading
        let reading1 = create_reading("Accelerometer", 0.0);
        history.push(reading1.clone());
        tokio::time::sleep(Duration::from_millis(10)).await;

        // 2. Second reading, huge jump in value over a short time
        let reading2 = create_reading("Accelerometer", 50.0);

        let result = engine.analyze(reading2, &history).await.unwrap();

        assert!(result.anomaly_score > 0.8);
        assert!(result.is_tampered);
        assert!(result.reasoning.contains("Unrealistic rate of change"));
    }

    #[tokio::test]
    async fn test_signature_verification_roundtrip() {
        let engine = setup_test_engine(Arc::new(DefaultSensorAnomalyDetector::create(
            HashMap::new(),
        )));
        let reading = create_reading("Test", 1.0);

        // 1. Get the signed result
        let result = engine.analyze(reading, &[]).await.unwrap();

        // 2. Verify the signature
        let mut mac = Hmac::<Sha384>::new_from_slice(engine.signing_key.expose()).unwrap();
        let mut result_to_verify = result.clone();
        result_to_verify.signature = String::new();
        let serialized = serde_json::to_vec(&result_to_verify).unwrap();
        mac.update(&serialized);

        let decoded_signature = hex::decode(result.signature).unwrap();
        assert!(mac.verify_slice(&decoded_signature).is_ok());
    }
}
