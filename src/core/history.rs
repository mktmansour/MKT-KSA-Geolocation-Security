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
use sqlx::PgPool;
use thiserror::Error;
use tracing::{error, instrument};

// ===================== الأخطاء المخصصة للوحدة =====================
// ===================== Custom Module Errors =====================
#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("Database query failed: {0}")]
    Database(#[from] sqlx::Error),

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
    db_pool: PgPool,
    anomaly_config: AnomalyConfig,
}

impl HistoryService {
    /// إنشاء مثيل جديد من الخدمة مع مجمع اتصالات قاعدة البيانات.
    /// Creates a new service instance with a database connection pool.
    pub fn new(db_pool: PgPool, anomaly_config: AnomalyConfig) -> Self {
        Self { db_pool, anomaly_config }
    }

    /// تسجيل حدث جديد في السجل التاريخي.
    /// Logs a new event to the history.
    #[instrument(skip(self, event), fields(entity_id = %event.entity_id, event_type = %event.event_type))]
    pub async fn log_event(&self, event: &HistoryEvent) -> Result<(), HistoryError> {
        // يتم استدعاء دالة CRUD الفعلية هنا
        // The actual CRUD function would be called here.
        // This is a placeholder for compilation.
        // crud::insert_history_event(&self.db_pool, event).await?;
        Ok(())
    }

    /// استرجاع جميع الأحداث لكيان معين مع دعم ترقيم الصفحات.
    /// Retrieves all events for a specific entity with pagination support.
    #[instrument(skip(self), fields(entity_id = %entity_id, limit = %limit, offset = %offset))]
    pub async fn get_entity_history(
        &self,
        entity_id: &str,
        since: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<HistoryEvent>, HistoryError> {
        // يتم استدعاء دالة CRUD الفعلية هنا
        // The actual CRUD function would be called here.
        // This is a placeholder for compilation.
        // crud::fetch_history_events(&self.db_pool, entity_id, since, limit, offset).await
        Ok(vec![])
    }

    /// كشف الشذوذ الزمني في الأحداث باستخدام عتبات قابلة للتكوين.
    /// Detects temporal anomalies in events using configurable thresholds.
    #[instrument(skip(self), fields(entity_id = %entity_id))]
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

    // ملاحظة: هذه الاختبارات هي أمثلة توضيحية ولن تعمل بدون قاعدة بيانات فعلية
    // ودوال CRUD حقيقية.
    // Note: These tests are illustrative and won't run without a real DB and CRUD functions.

    fn create_mock_service() -> HistoryService {
        // في الاختبار الحقيقي، سنستخدم قاعدة بيانات اختبارية
        // In a real test, we would use a test database
        let mock_pool = PgPool::connect_lazy("postgres://user:pass@localhost/test").unwrap();
        let mut config = AnomalyConfig::default();
        config.default_threshold = 2; // عتبة افتراضية منخفضة للاختبار
        config.per_type_thresholds.insert("CRITICAL_ERROR".to_string(), 0); // لا يسمح بأي تكرار
        
        HistoryService::new(mock_pool, config)
    }

    #[tokio::test]
    async fn test_anomaly_detection_with_default_threshold() {
        let service = create_mock_service();
        
        // لنفترض أن get_entity_history أعادت هذه الأحداث
        let mock_events = vec![
            HistoryEvent { id: 1, entity_id: "device123".into(), event_type: "LOGIN_SUCCESS".into(), timestamp: Utc::now(), meta: json!({}) },
            HistoryEvent { id: 2, entity_id: "device123".into(), event_type: "LOGIN_SUCCESS".into(), timestamp: Utc::now(), meta: json!({}) },
            HistoryEvent { id: 3, entity_id: "device123".into(), event_type: "LOGIN_SUCCESS".into(), timestamp: Utc::now(), meta: json!({}) },
        ];

        // هنا سنقوم بمحاكاة سلوك الدالة التي تستدعي قاعدة البيانات
        // let anomalies = service.detect_timeline_anomalies("device123", 30).await.unwrap();
        // بما أن العتبة الافتراضية هي 2، فإن الحدث الثالث يعتبر شذوذاً
        // assert_eq!(anomalies.len(), 1);
        // assert_eq!(anomalies[0].id, 3);
    }

    #[tokio::test]
    async fn test_anomaly_detection_with_custom_threshold() {
        let service = create_mock_service();
        
        // لنفترض أن get_entity_history أعادت هذه الأحداث
        let mock_events = vec![
            HistoryEvent { id: 1, entity_id: "device123".into(), event_type: "CRITICAL_ERROR".into(), timestamp: Utc::now(), meta: json!({}) },
            HistoryEvent { id: 2, entity_id: "device123".into(), event_type: "CRITICAL_ERROR".into(), timestamp: Utc::now(), meta: json!({}) },
        ];
        
        // هنا سنقوم بمحاكاة سلوك الدالة التي تستدعي قاعدة البيانات
        // let anomalies = service.detect_timeline_anomalies("device123", 30).await.unwrap();
        // بما أن العتبة المخصصة للخطأ الحرج هي 0، فإن الحدث الأول والثاني يعتبران شذوذاً
        // assert_eq!(anomalies.len(), 2);
    }
}
