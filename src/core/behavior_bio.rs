/******************************************************************************************
    📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.
اسم الملف: behavior_bio.rs
    المسار:    src/core/behavior_bio.rs

    دور الملف:
    المحرك الأساسي لتحليل السلوك الجغرافي والبيومتري، مصمم ببنية Traits-based
    مرنة وقابلة للتوسيع. يعمل هذا المحرك كنواة ذكية قابلة للحقن، مما يسمح
    بدمج نماذج تحليل وسيناريوهات أمان متعددة بسهولة.
    المهام الأساسية:
    1.  توفير بنية تحتية لتحليل السلوك (BehaviorEngine).
    2.  تعريف واجهات (Traits) قياسية لنماذج السلوك وكاشفات الشذوذ.
    3.  تقديم تطبيقات افتراضية (Default) كنقطة بداية للتحليل.
    4.  تحليل السلوك بناءً على سياق متعدد الأبعاد: الزمان، المكان، والتاريخ.
    5.  تصميم قابل للاختبار والتكامل مع كافة أنظمة المشروع والذكاء الاصطناعي.

    --------------------------------------------------------------
    File Name: behavior_bio.rs
    Path:     src/core/behavior_bio.rs

    File Role:
    The core engine for geo-behavioral and biometric analysis, designed with a
    flexible and extensible Traits-based architecture. This engine acts as a
    smart, injectable core, allowing for the easy integration of various
    analysis models and security scenarios.

    Main Tasks:
    1.  Provide the core infrastructure for behavior analysis (BehaviorEngine).
    2.  Define standard interfaces (Traits) for behavioral models and anomaly detectors.
    3.  Offer default implementations as a starting point for analysis.
    4.  Analyze behavior based on a multi-dimensional context: time, location, history.
    5.  Design for testability and integration with all project systems and AI.
******************************************************************************************/

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;
// use sqlx::PgPool; // تم التعليق بعد التحويل إلى sea-orm

// --- Local Imports ---
use crate::db::models::User;
use crate::security::policy::PolicyError;

// ================================================================
// الأخطاء المخصصة للوحدة
// Custom Module Errors
// ================================================================
#[derive(Debug, Error)]
pub enum BehaviorError {
    #[error("Invalid input data: {0}")]
    InvalidInput(String),

    #[error("Analysis model failed: {0}")]
    ModelFailed(String),

    #[error("Historical data is insufficient for analysis")]
    InsufficientHistory,

    /// Arabic: خطأ في الوصول إلى قاعدة البيانات.
    /// English: A database access error.
    #[error("Database error: {0}")]
    DatabaseError(anyhow::Error),

    /// Arabic: خطأ في الصلاحيات من محرك السياسات.
    /// English: A permission error from the policy engine.
    #[error("Policy error: {0}")]
    PolicyError(#[from] PolicyError),
}

// ================================================================
// نماذج البيانات الأساسية
// Core Data Models
// ================================================================

/// يمثل مُدخل واحد لتحليل السلوك، يجمع كل السياقات.
/// Represents a single input for behavior analysis, gathering all contexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorInput {
    pub entity_id: String,
    pub timestamp: DateTime<Utc>,
    pub location: (f64, f64), // (latitude, longitude)
    pub network_info: NetworkInfo,
    pub device_fingerprint: String,
}

/// معلومات الشبكة المرفقة مع كل سلوك.
/// Network information attached to each behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub ip_address: String,
    pub is_vpn: bool,
    pub connection_type: String, // e.g., "WiFi", "5G"
}

/// نتيجة تحليل السلوك.
/// The result of a behavior analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub risk_score: f32, // 0.0 (low) to 1.0 (high)
    pub risk_level: RiskLevel,
    pub anomaly_detected: bool,
    pub reasoning: String,
}

/// مستويات الخطورة الممكنة.
/// Possible risk levels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

// ================================================================
// الواجهات (Traits) للمكونات القابلة للحقن
// Traits for Injectable Components
// ================================================================

/// واجهة لنموذج تحليل السلوك.
/// Interface for a behavioral analysis model.
#[async_trait]
pub trait BehavioralModel: Send + Sync {
    /// يحلل السلوك الحالي مقارنة بالبيانات التاريخية.
    /// Analyzes the current behavior against historical data.
    async fn analyze(
        &self,
        current: &BehaviorInput,
        history: &VecDeque<BehaviorInput>,
    ) -> Result<f32, BehaviorError>;
}

/// واجهة لكاشف الشذوذ.
/// Interface for an anomaly detector.
#[async_trait]
pub trait AnomalyDetector: Send + Sync {
    /// يحدد ما إذا كان السلوك الحالي يمثل شذوذاً.
    /// Determines if the current behavior constitutes an anomaly.
    async fn detect(
        &self,
        current: &BehaviorInput,
        history: &VecDeque<BehaviorInput>,
    ) -> Result<Option<String>, BehaviorError>;
}

// ================================================================
// محرك تحليل السلوك (BehaviorEngine)
// The Behavior Analysis Engine
// ================================================================
pub struct BehaviorEngine {
    model: Arc<dyn BehavioralModel>,
    detector: Arc<dyn AnomalyDetector>,
    history: RwLock<VecDeque<BehaviorInput>>,
    history_limit: usize,
}

impl BehaviorEngine {
    /// إنشاء محرك جديد مع حقن التبعيات.
    /// Creates a new engine with dependency injection.
    pub fn new(
        model: Arc<dyn BehavioralModel>,
        detector: Arc<dyn AnomalyDetector>,
        history_limit: usize,
    ) -> Self {
        Self {
            model,
            detector,
            history: RwLock::new(VecDeque::with_capacity(history_limit)),
            history_limit,
        }
    }

    /// تنفيذ تحليل كامل لسلوك واحد.
    /// Executes a full analysis for a single behavior.
    pub async fn process(&self, input: BehaviorInput) -> Result<AnalysisResult, BehaviorError> {
        let history_guard = self.history.read().await;

        // 1. كشف الشذوذ
        // 1. Anomaly Detection
        let anomaly = self.detector.detect(&input, &history_guard).await?;

        // 2. تحليل النموذج السلوكي لتحديد درجة الخطورة
        // 2. Behavioral model analysis to determine risk score
        let risk_score = self.model.analyze(&input, &history_guard).await?;

        let risk_level = self.score_to_level(risk_score);

        // 3. بناء النتيجة النهائية
        // 3. Construct the final result
        let result = AnalysisResult {
            risk_score,
            risk_level,
            anomaly_detected: anomaly.is_some(),
            reasoning: anomaly
                .unwrap_or_else(|| "Behavior is within normal parameters.".to_string()),
        };

        // 4. تحديث السجل التاريخي (بعد انتهاء القراءة)
        // 4. Update history (after read lock is released)
        drop(history_guard);
        let mut history_writer = self.history.write().await;
        if history_writer.len() >= self.history_limit {
            history_writer.pop_front();
        }
        history_writer.push_back(input);

        Ok(result)
    }

    /// تحويل درجة الخطورة الرقمية إلى مستوى وصفي.
    /// Converts a numeric risk score to a descriptive level.
    fn score_to_level(&self, score: f32) -> RiskLevel {
        match score {
            s if s >= 0.9 => RiskLevel::Critical,
            s if s >= 0.7 => RiskLevel::High,
            s if s >= 0.4 => RiskLevel::Medium,
            s if s > 0.1 => RiskLevel::Low,
            _ => RiskLevel::None,
        }
    }
}

// ================================================================
// التطبيقات الافتراضية (Default Implementations)
// ================================================================

/// تطبيق افتراضي ذكي لنموذج تحليل السلوك.
/// A smart default implementation for the behavioral model.
pub struct DefaultBehavioralModel;

#[async_trait]
impl BehavioralModel for DefaultBehavioralModel {
    async fn analyze(
        &self,
        current: &BehaviorInput,
        history: &VecDeque<BehaviorInput>,
    ) -> Result<f32, BehaviorError> {
        // 1. حساب درجة المخاطرة الأولية بناءً على القواعد
        // 1. Calculate initial risk score based on rules
        let mut score: f32 = 0.0;
        if self.is_suspicious_time(current.timestamp) {
            score += 0.3;
        }

        // 2. عامل الشبكة: استخدام VPN يزيد من الشكوك
        // 2. Network factor: VPN usage increases suspicion
        if current.network_info.is_vpn {
            score += 0.3;
        }

        // 3. عامل التاريخ: مقارنة ببصمة الجهاز السابقة
        // 3. History factor: comparison with previous device fingerprint
        if let Some(prev) = history.back() {
            if prev.device_fingerprint != current.device_fingerprint {
                score += 0.4;
            }
        } else {
            // أول ظهور للكيان، يعتبر مخاطرة منخفضة
            // First time entity is seen, considered a low risk
            score += 0.1;
        }

        Ok(score.min(1.0))
    }
}

impl DefaultBehavioralModel {
    /// Checks if the event occurs at a suspicious time (e.g., late at night).
    fn is_suspicious_time(&self, timestamp: DateTime<Utc>) -> bool {
        let hour = timestamp.hour();
        (0..=5).contains(&hour) // Between midnight and 5 AM
    }
}

/// تطبيق افتراضي لكاشف الشذوذ.
/// A default implementation for the anomaly detector.
pub struct DefaultAnomalyDetector {
    /// السرعة القصوى المسموح بها (كم/ساعة)
    /// Maximum allowed speed (km/h)
    pub max_speed_kmh: f64,
}

#[async_trait]
impl AnomalyDetector for DefaultAnomalyDetector {
    async fn detect(
        &self,
        current: &BehaviorInput,
        history: &VecDeque<BehaviorInput>,
    ) -> Result<Option<String>, BehaviorError> {
        let last_behavior = match history.back() {
            Some(b) => b,
            None => return Ok(None), // لا يمكن التحليل بدون تاريخ
        };

        // فحص "الانتقال الآني" (Teleportation)
        // Check for "Teleportation"
        let distance_km = haversine_distance(current.location, last_behavior.location);

        let time_diff_secs = current.timestamp.timestamp() - last_behavior.timestamp.timestamp();
        if time_diff_secs <= 0 {
            return Ok(None);
        }

        let speed_kmh = distance_km / (time_diff_secs as f64 / 3600.0);

        if speed_kmh > self.max_speed_kmh {
            return Ok(Some(format!(
                "Anomaly detected: Impossible travel speed of {:.2} km/h.",
                speed_kmh
            )));
        }

        Ok(None)
    }
}

/// دالة حساب المسافة بين نقطتين على الكرة الأرضية.
/// Calculates the distance between two points on Earth.
fn haversine_distance(p1: (f64, f64), p2: (f64, f64)) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let (lat1, lon1) = (p1.0.to_radians(), p1.1.to_radians());
    let (lat2, lon2) = (p2.0.to_radians(), p2.1.to_radians());

    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;

    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_KM * c
}

// ================================================================
// خدمة المستخدم (User Service)
// User Service
// ================================================================

/// Arabic: يوفر وظائف لإدارة المستخدمين والتفاعل معهم، مع تطبيق سياسات الأمان.
/// English: Provides functions to manage and interact with users, applying security policies.
pub struct UserService {
    // pool: Arc<PgPool>, // تم التعليق بعد التحويل إلى sea-orm
}

impl UserService {
    /// Arabic: إنشاء نسخة جديدة من خدمة المستخدم.
    /// English: Creates a new instance of the user service.
    pub fn new(// pool: Arc<PgPool>, // تم التعليق بعد التحويل إلى sea-orm
    ) -> Self {
        Self {
            // pool, // تم التعليق بعد التحويل إلى sea-orm
        }
    }

    /// Arabic: جلب بيانات ملف شخصي لمستخدم مع التحقق من الصلاحيات.
    /// English: Fetches a user's profile data, with permission checking.
    pub async fn get_user_profile_data(
        &self,
        _requester_id: Uuid,
        _target_user_id: Uuid,
    ) -> Result<User, BehaviorError> {
        // --- 1. جلب بيانات مُقدم الطلب ---
        // --- 1. Fetch requester's data ---
        // let requester = crud::get_user_by_id(&self.pool, requester_id).await?;

        // --- 2. بناء سياق السياسة ---
        // --- 2. Build the Policy Context ---
        // let roles: Vec<Role> = requester.roles.iter()
        //     .map(|r| Role::from_str(r).unwrap_or(Role::User))
        //     .collect();

        // let status = match requester.status.as_str() {
        //     "Active" => UserStatus::Active,
        //     "Suspended" => UserStatus::Suspended,
        //     "Banned" => UserStatus::Banned,
        //     _ => UserStatus::Suspended, // Default to suspended if status is unknown
        // };

        // let context = PolicyContext {
        //     user_id: requester.id,
        //     roles: &roles,
        //     status: &status,
        //     trust_score: requester.trust_score,
        // };

        // --- 3. التحقق من الصلاحيات ---
        // --- 3. Check Permissions ---
        // let action = Action::ReadUserData { target_user_id: &target_user_id };
        // PolicyEngine::can_execute(&context, &action)?;

        // --- 4. جلب بيانات المستخدم المستهدف ---
        // --- 4. Fetch Target User's Data ---
        // let target_user = crud::get_user_by_id(&self.pool, target_user_id).await?;
        unimplemented!("Database access needs to be migrated to sea-orm");
    }
}

// ================================================================
// اختبارات شاملة (محدثة بالكامل)
// Comprehensive Tests (Fully Updated)
// ================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- Mock Components for Precise Testing ---

    struct MockCriticalModel;
    #[async_trait]
    impl BehavioralModel for MockCriticalModel {
        async fn analyze(
            &self,
            _: &BehaviorInput,
            _: &VecDeque<BehaviorInput>,
        ) -> Result<f32, BehaviorError> {
            Ok(0.95) // Always return a critical score
        }
    }

    struct MockTeleportDetector;
    #[async_trait]
    impl AnomalyDetector for MockTeleportDetector {
        async fn detect(
            &self,
            _: &BehaviorInput,
            _: &VecDeque<BehaviorInput>,
        ) -> Result<Option<String>, BehaviorError> {
            Ok(Some("Teleportation detected!".to_string()))
        }
    }

    fn create_sample_input(entity_id: &str) -> BehaviorInput {
        BehaviorInput {
            entity_id: entity_id.to_string(),
            timestamp: Utc::now(),
            location: (40.7128, -74.0060), // New York
            network_info: NetworkInfo {
                ip_address: "8.8.8.8".to_string(),
                is_vpn: false,
                connection_type: "WiFi".to_string(),
            },
            device_fingerprint: "fingerprint_123".to_string(),
        }
    }

    #[tokio::test]
    async fn test_engine_with_default_components() {
        let engine = BehaviorEngine::new(
            Arc::new(DefaultBehavioralModel),
            Arc::new(DefaultAnomalyDetector {
                max_speed_kmh: 1200.0,
            }),
            10,
        );
        // نجعل الطابع الزمني في وقت غير مريب لضمان حتمية الاختبار
        // Set timestamp to a non-suspicious hour to make the test deterministic
        let mut input = create_sample_input("user1");
        let fixed_dt = Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap();
        input.timestamp = fixed_dt;
        let result = engine.process(input).await.unwrap();

        assert_eq!(result.risk_level, RiskLevel::None); // A single event has no risk, not low.
        assert!(!result.anomaly_detected);
    }

    #[tokio::test]
    async fn test_engine_with_mocked_critical_risk() {
        let engine = BehaviorEngine::new(
            Arc::new(MockCriticalModel), // Inject mock model
            Arc::new(DefaultAnomalyDetector {
                max_speed_kmh: 1200.0,
            }),
            10,
        );
        let input = create_sample_input("user2");
        let result = engine.process(input).await.unwrap();

        assert_eq!(result.risk_score, 0.95);
        assert_eq!(result.risk_level, RiskLevel::Critical);
    }

    #[tokio::test]
    async fn test_engine_with_mocked_anomaly_detector() {
        let engine = BehaviorEngine::new(
            Arc::new(DefaultBehavioralModel),
            Arc::new(MockTeleportDetector), // Inject mock detector
            10,
        );
        let input = create_sample_input("user3");
        let result = engine.process(input).await.unwrap();

        assert!(result.anomaly_detected);
        assert_eq!(result.reasoning, "Teleportation detected!");
    }

    #[tokio::test]
    async fn test_impossible_travel_anomaly() {
        let engine = BehaviorEngine::new(
            Arc::new(DefaultBehavioralModel),
            Arc::new(DefaultAnomalyDetector {
                max_speed_kmh: 1200.0,
            }), // Supersonic jet speed
            10,
        );

        // 1. First event in New York
        let mut input1 = create_sample_input("user4");
        input1.location = (40.7128, -74.0060); // New York
        engine.process(input1).await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        // 2. Second event, 1 second later, in London (impossible travel)
        let mut input2 = create_sample_input("user4");
        input2.location = (51.5074, -0.1278); // London
        let result = engine.process(input2).await.unwrap();

        assert!(result.anomaly_detected);
        assert!(result.reasoning.contains("Impossible travel speed"));
    }
}
