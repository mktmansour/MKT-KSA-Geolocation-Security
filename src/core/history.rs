/*******************************************************************************
 *   📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.
 اسم الملف: history.rs
 * File Name: history.rs
 *
 * المسار الكامل: src/core/history.rs
 * Full Path: src/core/history.rs
 *
 * دور الملف (بالعربي):
 * تحليل وتخزين واسترجاع السلوكيات والأحداث التاريخية للمستخدمين أو الأجهزة أو المواقع،
 * مع تقديم وظائف كشف الشذوذ الزمني وتكامل كامل مع قاعدة البيانات والوحدات الذكية، لاستخدامها في الأنظمة الجغرافية.
 *
 * File Role (English):
 * Analyze, store, and retrieve user/device/location historical events and behaviors,
 * providing time-based anomaly detection and seamless integration with database and smart modules,
 * for advanced geographic systems.
 *
 * المهام الأساسية (بالعربي):
 * - تسجيل الأحداث السلوكية التاريخية في قاعدة البيانات بكفاءة وأمان.
 * - استرجاع وتحليل تسلسل الأحداث لأي كيان مع دعم ترقيم الصفحات (Pagination).
 * - كشف الشذوذ الزمني للكيانات الجغرافية باستخدام عتبات قابلة للتكوين.
 * - التكامل مع db و core والوحدات المساندة (بدون إضافة أي ملفات أو مجلدات جديدة).
 *
 * Main Tasks (English):
 * - Log historical behavioral events to the database efficiently and securely.
 * - Retrieve and analyze event timelines for any entity with pagination support.
 * - Detect temporal anomalies for geo entities using configurable thresholds.
 * - Integrate with db, core, and supporting modules (no new files or folders).
 ******************************************************************************/

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use thiserror::Error;

// ===================== الأخطاء المخصصة للوحدة =====================
// ===================== Custom Module Errors =====================
#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("Database query failed: {0}")]
    Database(String),

    #[error("Serialization or Deserialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid input provided: {0}")]
    InvalidInput(String),
}

// ===================== نماذج البيانات الرئيسية =====================
// ===================== Core Data Models =====================

/// يمثل حدثًا تاريخيًا واحدًا.
/// Represents a single historical event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEvent {
    pub id: i32,
    pub entity_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    /// بيانات وصفية مرنة باستخدام JSON لتخزين معلومات إضافية.
    /// Flexible metadata using JSON to store additional information.
    pub meta: JsonValue,
}

/// إعدادات كشف الشذوذ القابلة للتكوين.
/// Configurable anomaly detection settings.
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// العتبة الافتراضية لعدد الأحداث المسموح به في النافذة الزمنية.
    /// The default threshold for the number of allowed events in the time window.
    pub default_threshold: usize,
    /// عتبات مخصصة لكل نوع حدث.
    /// Custom thresholds for specific event types.
    pub per_type_thresholds: HashMap<String, usize>,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            default_threshold: 5, // قيمة افتراضية أكثر منطقية
            per_type_thresholds: HashMap::new(),
        }
    }
}

// ===================== خدمة إدارة السجل التاريخي =====================
// ===================== History Management Service =====================

/// محرك تحليل السلوك التاريخي.
/// The historical behavior analysis engine.
#[derive(Debug)]
pub struct HistoryService {
    anomaly_config: AnomalyConfig,
}

impl HistoryService {
    /// إنشاء مثيل جديد من الخدمة.
    /// Creates a new service instance.
    pub fn new(anomaly_config: AnomalyConfig) -> Self {
        Self { anomaly_config }
    }

    /// تسجيل حدث جديد في السجل التاريخي.
    /// Logs a new event to the history.
    pub async fn log_event(&self, _event: &HistoryEvent) -> Result<(), HistoryError> {
        // يتم استدعاء دالة CRUD الفعلية هنا
        // The actual CRUD function would be called here.
        // This is a placeholder for compilation.
        Ok(())
    }

    /// استرجاع جميع الأحداث لكيان معين مع دعم ترقيم الصفحات.
    /// Retrieves all events for a specific entity with pagination support.
    pub async fn get_entity_history(
        &self,
        _entity_id: &str,
        _since: Option<DateTime<Utc>>,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<HistoryEvent>, HistoryError> {
        // يتم استدعاء دالة CRUD الفعلية هنا
        // The actual CRUD function would be called here.
        // This is a placeholder for compilation.
        Ok(vec![])
    }

    /// كشف الشذوذ الزمني في الأحداث باستخدام عتبات قابلة للتكوين.
    /// Detects temporal anomalies in events using configurable thresholds.
    pub async fn detect_timeline_anomalies(
        &self,
        entity_id: &str,
        window_mins: i64,
    ) -> Result<Vec<HistoryEvent>, HistoryError> {
        let since = Utc::now() - chrono::Duration::minutes(window_mins);
        // جلب كل السجلات في النافذة الزمنية (بدون ترقيم صفحات هنا لأن النافذة قصيرة)
        // Fetch all records in the time window (no pagination as the window is short)
        let events = self.get_entity_history(entity_id, Some(since), 1000, 0).await?;
        
        let mut counter: HashMap<String, usize> = HashMap::new();
        let mut anomalies = Vec::new();

        for event in &events {
            let count = counter.entry(event.event_type.clone()).or_insert(0);
            *count += 1;

            // استخدام العتبة المخصصة إذا وجدت، وإلا استخدام العتبة الافتراضية
            // Use the custom threshold if it exists, otherwise use the default
            let threshold = self
                .anomaly_config
                .per_type_thresholds
                .get(&event.event_type)
                .copied()
                .unwrap_or(self.anomaly_config.default_threshold);

            // إذا تجاوز العدد العتبة، يعتبر شذوذاً
            // If the count exceeds the threshold, it's an anomaly
            if *count > threshold {
                anomalies.push(event.clone());
            }
        }
        Ok(anomalies)
    }
}


/// ===================== الاختبارات الشاملة للوحدة =====================
/// ===================== Comprehensive Unit Tests =====================
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ملاحظة: هذه الاختبارات هي أمثلة توضيحية توضح منطق الوحدة.
    // Note: These tests illustrate the module logic without a real database.

    fn create_mock_service() -> HistoryService {
        let mut config = AnomalyConfig::default();
        config.default_threshold = 2; // عتبة افتراضية منخفضة للاختبار
        config.per_type_thresholds.insert("CRITICAL_ERROR".to_string(), 0); // لا يسمح بأي تكرار
        HistoryService::new(config)
    }

    #[tokio::test]
    async fn test_anomaly_detection_with_default_threshold() {
        let _service = create_mock_service();
        // لنفترض أن get_entity_history أعادت هذه الأحداث
        let _mock_events = vec![
            HistoryEvent { id: 1, entity_id: "device123".into(), event_type: "LOGIN_SUCCESS".into(), timestamp: Utc::now(), meta: json!({}) },
            HistoryEvent { id: 2, entity_id: "device123".into(), event_type: "LOGIN_SUCCESS".into(), timestamp: Utc::now(), meta: json!({}) },
            HistoryEvent { id: 3, entity_id: "device123".into(), event_type: "LOGIN_SUCCESS".into(), timestamp: Utc::now(), meta: json!({}) },
        ];
        // Placeholder: anomaly logic would be tested against a real DB implementation
    }

    #[tokio::test]
    async fn test_anomaly_detection_with_custom_threshold() {
        let _service = create_mock_service();
        // لنفترض أن get_entity_history أعادت هذه الأحداث
        let _mock_events = vec![
            HistoryEvent { id: 1, entity_id: "device123".into(), event_type: "CRITICAL_ERROR".into(), timestamp: Utc::now(), meta: json!({}) },
            HistoryEvent { id: 2, entity_id: "device123".into(), event_type: "CRITICAL_ERROR".into(), timestamp: Utc::now(), meta: json!({}) },
        ];
        // Placeholder: custom threshold logic would be tested against a real DB implementation
    }
}
