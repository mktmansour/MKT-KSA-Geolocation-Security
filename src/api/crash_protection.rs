/// Crash Protection Module
/// حماية من الانهيار
/// System crash protection and auto-recovery
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Crash Protection Status
/// حالة حماية الانهيار
#[derive(Debug, Clone, PartialEq)]
pub enum CrashProtectionStatus {
    Active,     // نشط
    Standby,    // في الانتظار
    Recovering, // في حالة الاسترداد
    Disabled,   // معطل
}

/// Recovery Strategy
/// استراتيجية الاسترداد
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryStrategy {
    Restart,          // إعادة تشغيل
    Rollback,         // التراجع
    GracefulShutdown, // إغلاق آمن
    EmergencyMode,    // الوضع الطارئ
    AutoHeal,         // الشفاء التلقائي
}

/// Crash Event
/// حدث الانهيار
#[derive(Debug, Clone)]
pub struct CrashEvent {
    pub id: String,
    pub timestamp: u64,
    pub severity: CrashSeverity,
    pub component: String,
    pub error_message: String,
    pub recovery_strategy: RecoveryStrategy,
    pub resolved: bool,
}

/// Crash Severity
/// خطورة الانهيار
#[derive(Debug, Clone, PartialEq)]
pub enum CrashSeverity {
    Low,      // منخفض
    Medium,   // متوسط
    High,     // عالي
    Critical, // حرج
}

/// Health Check
/// فحص الصحة
#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub id: String,
    pub name: String,
    pub component: String,
    pub check_interval_ms: u64,
    pub timeout_ms: u64,
    pub enabled: bool,
}

/// Fallback Strategy
/// استراتيجية الاحتياطي
#[derive(Debug, Clone)]
pub struct FallbackStrategy {
    pub id: String,
    pub name: String,
    pub trigger_conditions: Vec<String>,
    pub recovery_actions: Vec<String>,
    pub enabled: bool,
}

/// Crash Protection Configuration
/// تكوين حماية الانهيار
#[derive(Debug, Clone)]
pub struct CrashProtectionConfig {
    pub auto_recovery: bool,
    pub max_recovery_attempts: u32,
    pub recovery_timeout_ms: u64,
    pub emergency_mode_threshold: u32,
    pub health_check_interval_ms: u64,
    pub enabled: bool,
}

/// Crash Protection Manager
/// مدير حماية الانهيار
pub struct CrashProtectionManager {
    status: Arc<Mutex<CrashProtectionStatus>>,
    config: Arc<Mutex<CrashProtectionConfig>>,
    crash_events: Arc<Mutex<Vec<CrashEvent>>>,
    health_checks: Arc<Mutex<Vec<HealthCheck>>>,
    fallback_strategies: Arc<Mutex<Vec<FallbackStrategy>>>,
    recovery_count: Arc<Mutex<u32>>,
}

impl CrashProtectionManager {
    /// Create new Crash Protection Manager
    /// إنشاء مدير حماية انهيار جديد
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(CrashProtectionStatus::Active)),
            config: Arc::new(Mutex::new(CrashProtectionConfig {
                auto_recovery: true,
                max_recovery_attempts: 3,
                recovery_timeout_ms: 30000, // 30 seconds
                emergency_mode_threshold: 5,
                health_check_interval_ms: 5000, // 5 seconds
                enabled: true,
            })),
            crash_events: Arc::new(Mutex::new(Vec::new())),
            health_checks: Arc::new(Mutex::new(Vec::new())),
            fallback_strategies: Arc::new(Mutex::new(Vec::new())),
            recovery_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Enable Crash Protection
    /// تفعيل حماية الانهيار
    pub fn enable(&self) -> Result<(), String> {
        let mut status = self.status.lock().map_err(|e| e.to_string())?;
        *status = CrashProtectionStatus::Active;
        Ok(())
    }

    /// Disable Crash Protection
    /// إلغاء تفعيل حماية الانهيار
    pub fn disable(&self) -> Result<(), String> {
        let mut status = self.status.lock().map_err(|e| e.to_string())?;
        *status = CrashProtectionStatus::Disabled;
        Ok(())
    }

    /// Get Protection Status
    /// الحصول على حالة الحماية
    pub fn get_status(&self) -> Result<CrashProtectionStatus, String> {
        let status = self.status.lock().map_err(|e| e.to_string())?;
        Ok(status.clone())
    }

    /// Report Crash Event
    /// الإبلاغ عن حدث انهيار
    pub fn report_crash(
        &self,
        component: &str,
        error_message: &str,
        severity: CrashSeverity,
    ) -> Result<String, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as u64;

        let crash_id = self.generate_crash_id();

        let crash_event = CrashEvent {
            id: crash_id.clone(),
            timestamp,
            severity: severity.clone(),
            component: component.to_string(),
            error_message: error_message.to_string(),
            recovery_strategy: self.determine_recovery_strategy(&severity),
            resolved: false,
        };

        // Store crash event
        let mut crash_events = self.crash_events.lock().map_err(|e| e.to_string())?;
        crash_events.push(crash_event.clone());

        // Keep only last 100 crash events
        if crash_events.len() > 100 {
            crash_events.remove(0);
        }

        // Attempt recovery if enabled
        if self.should_attempt_recovery(&severity) {
            self.attempt_recovery(&crash_event)?;
        }

        Ok(crash_id)
    }

    /// Attempt Recovery
    /// محاولة الاسترداد
    pub fn attempt_recovery(&self, crash_event: &CrashEvent) -> Result<bool, String> {
        let config = self.config.lock().map_err(|e| e.to_string())?;
        let mut recovery_count = self.recovery_count.lock().map_err(|e| e.to_string())?;

        if *recovery_count >= config.max_recovery_attempts {
            return Err("Maximum recovery attempts exceeded".to_string());
        }

        *recovery_count += 1;

        // Set status to recovering
        let mut status = self.status.lock().map_err(|e| e.to_string())?;
        *status = CrashProtectionStatus::Recovering;

        // Simulate recovery process
        let recovery_successful = match crash_event.recovery_strategy {
            RecoveryStrategy::Restart => self.perform_restart(),
            RecoveryStrategy::Rollback => self.perform_rollback(),
            RecoveryStrategy::GracefulShutdown => self.perform_graceful_shutdown(),
            RecoveryStrategy::EmergencyMode => self.enter_emergency_mode(),
            RecoveryStrategy::AutoHeal => self.perform_auto_heal(),
        };

        if recovery_successful {
            *status = CrashProtectionStatus::Active;
            *recovery_count = 0;
        } else {
            *status = CrashProtectionStatus::Standby;
        }

        Ok(recovery_successful)
    }

    /// Add Health Check
    /// إضافة فحص صحة
    pub fn add_health_check(&self, health_check: HealthCheck) -> Result<(), String> {
        let mut health_checks = self.health_checks.lock().map_err(|e| e.to_string())?;
        health_checks.push(health_check);
        Ok(())
    }

    /// Add Fallback Strategy
    /// إضافة استراتيجية احتياطي
    pub fn add_fallback_strategy(&self, strategy: FallbackStrategy) -> Result<(), String> {
        let mut fallback_strategies = self.fallback_strategies.lock().map_err(|e| e.to_string())?;
        fallback_strategies.push(strategy);
        Ok(())
    }

    /// Get Crash Statistics
    /// الحصول على إحصائيات الانهيار
    pub fn get_crash_stats(&self) -> Result<HashMap<String, u64>, String> {
        let crash_events = self.crash_events.lock().map_err(|e| e.to_string())?;
        let mut stats = HashMap::new();

        stats.insert("total_crashes".to_string(), crash_events.len() as u64);
        stats.insert(
            "critical_crashes".to_string(),
            crash_events
                .iter()
                .filter(|e| e.severity == CrashSeverity::Critical)
                .count() as u64,
        );
        stats.insert(
            "high_crashes".to_string(),
            crash_events
                .iter()
                .filter(|e| e.severity == CrashSeverity::High)
                .count() as u64,
        );
        stats.insert(
            "resolved_crashes".to_string(),
            crash_events.iter().filter(|e| e.resolved).count() as u64,
        );

        Ok(stats)
    }

    /// Update Configuration
    /// تحديث التكوين
    pub fn update_config(&self, config: CrashProtectionConfig) -> Result<(), String> {
        let mut current_config = self.config.lock().map_err(|e| e.to_string())?;
        *current_config = config;
        Ok(())
    }

    /// Get Configuration
    /// الحصول على التكوين
    pub fn get_config(&self) -> Result<CrashProtectionConfig, String> {
        let config = self.config.lock().map_err(|e| e.to_string())?;
        Ok(config.clone())
    }

    // Helper methods
    fn generate_crash_id(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        format!("crash_{}", hasher.finish())
    }

    fn determine_recovery_strategy(&self, severity: &CrashSeverity) -> RecoveryStrategy {
        match severity {
            CrashSeverity::Critical => RecoveryStrategy::EmergencyMode,
            CrashSeverity::High => RecoveryStrategy::Restart,
            CrashSeverity::Medium => RecoveryStrategy::AutoHeal,
            CrashSeverity::Low => RecoveryStrategy::AutoHeal,
        }
    }

    fn should_attempt_recovery(&self, severity: &CrashSeverity) -> bool {
        let config = self.config.lock().unwrap();
        config.enabled
            && config.auto_recovery
            && matches!(severity, CrashSeverity::High | CrashSeverity::Critical)
    }

    fn perform_restart(&self) -> bool {
        // Simulate restart process
        true
    }

    fn perform_rollback(&self) -> bool {
        // Simulate rollback process
        true
    }

    fn perform_graceful_shutdown(&self) -> bool {
        // Simulate graceful shutdown
        true
    }

    fn enter_emergency_mode(&self) -> bool {
        // Simulate emergency mode
        true
    }

    fn perform_auto_heal(&self) -> bool {
        // Simulate auto-healing process
        true
    }
}

impl Default for CrashProtectionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global Crash Protection Manager Instance
/// مثيل مدير حماية الانهيار العالمي
use std::sync::OnceLock;
static CRASH_PROTECTION_MANAGER: OnceLock<CrashProtectionManager> = OnceLock::new();

/// Get Global Crash Protection Manager
/// الحصول على مدير حماية الانهيار العالمي
pub fn get_crash_protection_manager() -> &'static CrashProtectionManager {
    CRASH_PROTECTION_MANAGER.get_or_init(CrashProtectionManager::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crash_protection_creation() {
        let manager = CrashProtectionManager::new();
        assert_eq!(manager.get_status().unwrap(), CrashProtectionStatus::Active);
    }

    #[test]
    fn test_report_crash() {
        let manager = CrashProtectionManager::new();
        let crash_id = manager
            .report_crash("test_component", "test error", CrashSeverity::Medium)
            .unwrap();
        assert!(!crash_id.is_empty());
    }

    #[test]
    fn test_crash_stats() {
        let manager = CrashProtectionManager::new();
        manager
            .report_crash("test", "error", CrashSeverity::Critical)
            .unwrap();
        let stats = manager.get_crash_stats().unwrap();
        assert_eq!(stats.get("total_crashes").unwrap(), &1);
    }
}
