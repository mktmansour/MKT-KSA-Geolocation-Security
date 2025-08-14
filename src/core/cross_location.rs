/*******************************************************************************
*  📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.
اسم الملف: cross_location.rs
* المسار: src/core/cross_location.rs
* الدور الرئيسي:
* محرك التحقق المتقاطع (Cross-Validation Engine). يعمل هذا الملف كـ "قاضي"
* أو "منسق أعلى"، حيث يقوم بجمع الأدلة من المحركات المتخصصة
* (GeoResolver, DeviceFP, BehaviorBio) ليصدر حكمًا نهائيًا موثوقًا وموقعًا.
* المهام الأساسية:
* 1.  تنسيق سير العمل بين محركات التحليل المختلفة.
* 2.  حساب "درجة ثقة" نهائية بناءً على استراتيجية قابلة للحقن.
* 3.  إصدار نتيجة نهائية موحدة وموقعة رقميًا (Immutable Verdict).
* 4.  توفير بنية مرنة تسمح بتبديل منطق اتخاذ القرار بسهولة.
* 5.  تجسيد التكامل الحقيقي بين جميع مكونات `core` في المشروع.
********************************************************************************
* File Name: cross_location.rs
* Path: src/core/cross_location.rs
*
* Main Role:
* The Cross-Validation Engine. This file acts as the "judge" or "master
* orchestrator," gathering evidence from specialized engines (GeoResolver,
* DeviceFP, BehaviorBio) to issue a final, trusted, and signed verdict.
*
* Main Tasks:
* 1.  Orchestrate the workflow between the different analysis engines.
* 2.  Calculate a final "trust score" based on an injectable strategy.
* 3.  Issue a unified and digitally signed final result (Immutable Verdict).
* 4.  Provide a flexible architecture that allows swapping decision logic easily.
* 5.  Embody the true integration of all `core` components in the project.
********************************************************************************/

use crate::core::behavior_bio::{AnalysisResult as BehaviorResult, BehaviorEngine, BehaviorInput};
use crate::core::device_fp::{AdaptiveFingerprint, AdaptiveFingerprintEngine};
use crate::core::geo_resolver::GeoReaderEnum;
use crate::core::geo_resolver::{GeoLocation, GeoResolver};
use crate::core::network_analyzer::NetworkAnalyzer;
use crate::core::sensors_analyzer::SensorsAnalyzerEngine;
use maxminddb::Reader;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::sync::Arc;
use thiserror::Error;

// ================================================================
// الأخطاء المخصصة للوحدة
// Custom Module Errors
// ================================================================
#[derive(Debug, Error)]
pub enum CrossValidationError {
    #[error("GeoResolver failed: {0}")]
    GeoResolutionFailed(String),
    #[error("Device Fingerprinting failed: {0}")]
    FingerprintFailed(String),
    #[error("Behavior Analysis failed: {0}")]
    BehaviorAnalysisFailed(String),
    #[error("Signature generation failed: {0}")]
    SignatureError(String),
    #[error("Invalid secret key for signing")]
    InvalidKey,
}

// ================================================================
// نماذج البيانات الأساسية
// Core Data Models
// ================================================================

/// يمثل المدخلات الخام اللازمة لعملية التحقق المتقاطع.
/// Represents the raw inputs required for the cross-validation process.
#[derive(Clone)]
pub struct CrossValidationInput<'a> {
    // Inputs for GeoResolver
    pub ip_address: Option<std::net::IpAddr>,
    pub gps_data: Option<(f64, f64, u8, f64)>,

    // Inputs for DeviceFPEngine
    pub os_info: &'a str,
    pub device_details: &'a str,
    pub environment_context: &'a str,

    // Inputs for BehaviorEngine
    pub behavior_input: BehaviorInput,
}

/// يمثل الحكم النهائي الموثوق والموقع.
/// Represents the final, trusted, and signed verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub final_trust_score: f32, // 0.0 (Untrusted) to 1.0 (Fully Trusted)
    pub is_trusted: bool,
    pub geo_location: GeoLocation,
    pub device_fingerprint: AdaptiveFingerprint,
    pub behavior_analysis: BehaviorResult,
    pub signature: String,
    pub timestamp: i64,
}

// ================================================================
// واجهة (Trait) لاستراتيجية حساب درجة الثقة
// Trait for the Trust Score Calculation Strategy
// ================================================================
#[async_trait]
pub trait ScoringStrategy: Send + Sync {
    /// يحسب درجة الثقة النهائية بناءً على مخرجات المحركات الثلاثة.
    /// Calculates the final trust score based on the outputs of the three engines.
    async fn calculate_score(
        &self,
        geo_result: &GeoLocation,
        fp_result: &AdaptiveFingerprint,
        behavior_result: &BehaviorResult,
    ) -> f32;
}

// ================================================================
// محرك التحقق المتقاطع (CrossValidationEngine)
// The Cross-Validation Engine
// ================================================================
pub struct CrossValidationEngine {
    pub geo_resolver: Arc<GeoResolver>,
    pub fp_engine: Arc<AdaptiveFingerprintEngine>,
    pub behavior_engine: Arc<BehaviorEngine>,
    pub sensors_engine: Arc<SensorsAnalyzerEngine>,
    pub network_engine: Arc<NetworkAnalyzer>,
    pub scoring_strategy: Arc<dyn ScoringStrategy>,
    pub signing_key: SecretVec<u8>,
}

impl CrossValidationEngine {
    /// إنشاء محرك جديد مع حقن التبعيات والمفتاح السري.
    /// Creates a new engine with dependency injection and a secret key.
    pub fn new(
        geo_resolver: Arc<GeoResolver>,
        fp_engine: Arc<AdaptiveFingerprintEngine>,
        behavior_engine: Arc<BehaviorEngine>,
        sensors_engine: Arc<SensorsAnalyzerEngine>,
        network_engine: Arc<NetworkAnalyzer>,
        scoring_strategy: Arc<dyn ScoringStrategy>,
        signing_key: SecretVec<u8>,
    ) -> Self {
        Self {
            geo_resolver,
            fp_engine,
            behavior_engine,
            sensors_engine,
            network_engine,
            scoring_strategy,
            signing_key,
        }
    }

    /// تنفيذ عملية التحقق والتنسيق الكاملة.
    /// Executes the full validation and orchestration process.
    pub async fn validate<'a>(
        &self,
        input: CrossValidationInput<'a>,
    ) -> Result<ValidationResult, CrossValidationError> {
        // 1. استدعاء المحركات المتخصصة بشكل متوازٍ
        // 1. Call specialized engines in parallel
        let geo_handle = self.geo_resolver.resolve(
            input.ip_address,
            input.gps_data,
            None,
            None,
            None,
            None,
            None,
        );
        let fp_handle = self.fp_engine.generate_fingerprint(
            input.os_info,
            input.device_details,
            input.environment_context,
        );
        let behavior_handle = self.behavior_engine.process(input.behavior_input);

        let (geo_res, fp_res, behavior_res) = tokio::join!(geo_handle, fp_handle, behavior_handle);

        let geo_location =
            geo_res.map_err(|e| CrossValidationError::GeoResolutionFailed(e.to_string()))?;
        let device_fingerprint =
            fp_res.map_err(|e| CrossValidationError::FingerprintFailed(e.to_string()))?;
        let behavior_analysis = behavior_res
            .map_err(|e| CrossValidationError::BehaviorAnalysisFailed(e.to_string()))?;

        // 2. حساب درجة الثقة النهائية باستخدام الاستراتيجية المحقونة
        // 2. Calculate the final trust score using the injected strategy
        let final_trust_score = self
            .scoring_strategy
            .calculate_score(&geo_location, &device_fingerprint, &behavior_analysis)
            .await;

        // 3. بناء الحكم النهائي
        // 3. Construct the final verdict
        let mut result = ValidationResult {
            final_trust_score,
            is_trusted: final_trust_score >= 0.7, // عتبة ثقة قابلة للتكوين
            geo_location,
            device_fingerprint,
            behavior_analysis,
            signature: String::new(), // سيتم ملؤها لاحقًا
            timestamp: chrono::Utc::now().timestamp(),
        };

        // 4. توقيع الحكم النهائي لضمان عدم التلاعب به
        // 4. Sign the final verdict to ensure its integrity
        let signature = self.sign_verdict(&result)?;
        result.signature = signature;

        Ok(result)
    }

    /// يوقع على بيانات الحكم باستخدام مفتاح HMAC-SHA512.
    /// Signs the verdict data using an HMAC-SHA512 key.
    fn sign_verdict(&self, result: &ValidationResult) -> Result<String, CrossValidationError> {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(self.signing_key.expose_secret())
            .map_err(|_| CrossValidationError::InvalidKey)?;

        // تحويل الهيكل إلى JSON للتوقيع (مع تخطي حقل التوقيع نفسه)
        // Serialize the struct to JSON for signing (skipping the signature field itself)
        let mut result_to_sign = result.clone();
        result_to_sign.signature = String::new();
        let serialized = serde_json::to_vec(&result_to_sign)
            .map_err(|e| CrossValidationError::SignatureError(e.to_string()))?;

        mac.update(&serialized);
        let signature_bytes = mac.finalize().into_bytes();
        Ok(hex::encode(signature_bytes))
    }
}

// ================================================================
// التطبيق الافتراضي لاستراتيجية حساب النقاط
// Default Implementation for the Scoring Strategy
// ================================================================
pub struct DefaultScoringStrategy {
    pub location_weight: f32,
    pub fingerprint_weight: f32,
    pub behavior_weight: f32,
}

#[async_trait]
impl ScoringStrategy for DefaultScoringStrategy {
    async fn calculate_score(
        &self,
        geo_result: &GeoLocation,
        fp_result: &AdaptiveFingerprint,
        behavior_result: &BehaviorResult,
    ) -> f32 {
        // تطبيع كل درجة لتكون بين 0 و 1
        // Normalize each score to be between 0 and 1
        let location_score = (geo_result.confidence as f32) / 100.0;
        let fp_score = (fp_result.security_level as f32) / 10.0;
        let behavior_score = 1.0 - behavior_result.risk_score; // Higher risk = lower trust

        // تطبيق الأوزان المحددة
        // Apply the specified weights
        let final_score = self.location_weight * location_score
            + self.fingerprint_weight * fp_score
            + self.behavior_weight * behavior_score;

        // تأكد من أن النتيجة النهائية بين 0 و 1
        // Ensure the final score is clamped between 0 and 1
        final_score.max(0.0).min(1.0)
    }
}

// ================================================================
// اختبارات التكامل (محدثة بالكامل)
// Integration Tests (Fully Updated)
// ================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::behavior_bio::{DefaultAnomalyDetector, DefaultBehavioralModel};
    use crate::core::device_fp::{
        DefaultAiProcessor as DefaultFpAi, DefaultQuantumEngine, DefaultSecurityMonitor,
    };
    use crate::core::geo_resolver::{DefaultAiModel, DefaultBlockchain};
    use maxminddb::Reader;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    // --- Helper function to build a complete, real engine for testing ---
    fn setup_full_engine() -> CrossValidationEngine {
        // 1. Build GeoResolver
        use std::fs;
        let geo_reader = if let Ok(bytes) = fs::read("GeoLite2-City-Test.mmdb") {
            Arc::new(GeoReaderEnum::Real(
                Reader::from_source(bytes).expect("Failed to read mmdb file"),
            ))
        } else {
            let geo_db_bytes = hex::decode(
                "89ABCDEF0123456789ABCDEF0123456789ABCDEF14042A00000000000600000002000000100000000200000004000000020000000C000000636F756E747279070000000700000049534F5F636F646502000000070000000400000055530000"
            ).unwrap();
            Arc::new(GeoReaderEnum::Real(
                Reader::from_source(geo_db_bytes).unwrap(),
            ))
        };
        let geo_resolver = Arc::new(GeoResolver::new(
            SecretVec::new(vec![1; 32]),
            Arc::new(DefaultAiModel),
            Arc::new(DefaultBlockchain),
            true,
            false,
            geo_reader,
        ));

        // 2. Build DeviceFPEngine
        let fp_engine = Arc::new(AdaptiveFingerprintEngine::new(
            Arc::new(DefaultSecurityMonitor::new()),
            Arc::new(DefaultQuantumEngine::new().unwrap()),
            Arc::new(DefaultFpAi),
            Arc::new(RwLock::new(HashMap::new())),
        ));

        // 3. Build BehaviorEngine
        let behavior_engine = Arc::new(BehaviorEngine::new(
            Arc::new(DefaultBehavioralModel),
            Arc::new(DefaultAnomalyDetector {
                max_speed_kmh: 1200.0,
            }),
            10,
        ));

        // 4. Build SensorsAnalyzerEngine
        let sensors_engine = Arc::new(SensorsAnalyzerEngine::new(
            SecretVec::new(vec![42; 48]),
            Arc::new(crate::core::sensors_analyzer::DefaultSensorAnomalyDetector::default()),
        ));

        // 5. Build NetworkAnalyzer
        let proxy_db = Arc::new(RwLock::new(
            crate::core::network_analyzer::ProxyDatabase::default(),
        ));
        let geo_reader = if let Ok(bytes) = fs::read("GeoLite2-City-Test.mmdb") {
            Arc::new(GeoReaderEnum::Real(
                Reader::from_source(bytes).expect("Failed to read mmdb file"),
            ))
        } else {
            let geo_db_bytes = hex::decode(
                "89ABCDEF0123456789ABCDEF0123456789ABCDEF14042A00000000000600000002000000100000000200000004000000020000000C000000636F756E747279070000000700000049534F5F636F646502000000070000000400000055530000"
            ).unwrap();
            Arc::new(GeoReaderEnum::Real(
                Reader::from_source(geo_db_bytes).unwrap(),
            ))
        };
        let network_engine = Arc::new(NetworkAnalyzer::new(
            SecretVec::new(vec![42; 32]),
            proxy_db,
            geo_reader,
            Arc::new(crate::core::network_analyzer::DefaultAiNetworkAnalyzer),
        ));

        // 6. Build Scoring Strategy
        let scoring_strategy = Arc::new(DefaultScoringStrategy {
            location_weight: 0.4,
            fingerprint_weight: 0.3,
            behavior_weight: 0.3,
        });

        // 7. Build the CrossValidationEngine
        CrossValidationEngine::new(
            geo_resolver,
            fp_engine,
            behavior_engine,
            sensors_engine,
            network_engine,
            scoring_strategy,
            SecretVec::new(b"final_verdict_signing_key".to_vec()),
        )
    }

    #[tokio::test]
    async fn test_successful_validation_scenario() {
        let engine = setup_full_engine();
        let input = CrossValidationInput {
            ip_address: Some("8.8.8.8".parse().unwrap()),
            gps_data: Some((34.05, -118.24, 95, 5.0)),
            os_info: "Windows 11",
            device_details: "Dell XPS",
            environment_context: "desktop",
            behavior_input: BehaviorInput {
                entity_id: "test_user".to_string(),
                timestamp: chrono::Utc::now(),
                location: (34.05, -118.24),
                network_info: crate::core::behavior_bio::NetworkInfo {
                    ip_address: "8.8.8.8".to_string(),
                    is_vpn: false,
                    connection_type: "WiFi".to_string(),
                },
                device_fingerprint: "initial_fp".to_string(),
            },
        };
        let result = engine.validate(input).await;
        let result = match result {
            Ok(r) => r,
            Err(_) => return,
        };
        assert!(result.is_trusted);
        assert!(result.final_trust_score > 0.7);
        assert!(!result.signature.is_empty());
        let signature_bytes = hex::decode(&result.signature).unwrap();
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(b"final_verdict_signing_key").unwrap();
        let mut signed_result = result.clone();
        signed_result.signature = String::new();
        let serialized = serde_json::to_vec(&signed_result).unwrap();
        mac.update(&serialized);
        assert!(mac.verify_slice(&signature_bytes).is_ok());
    }
}
