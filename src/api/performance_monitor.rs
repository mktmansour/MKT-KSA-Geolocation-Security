/// Performance Monitor Module
/// مراقب الأداء
/// Performance monitoring system
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Performance Metrics
/// مقاييس الأداء
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub memory_total: u64,
    pub memory_used: u64,
    pub request_rate: u64,
    pub error_rate: f64,
    pub response_time_ms: u64,
    pub active_connections: u64,
    pub timestamp: u64,
}

/// System Health Status
/// حالة صحة النظام
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,  // صحي
    Warning,  // تحذير
    Critical, // حرج
    Down,     // معطل
}

/// Health Check Result
/// نتيجة فحص الصحة
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub message: String,
    pub timestamp: u64,
    pub metrics: PerformanceMetrics,
}

/// Alert Configuration
/// تكوين التنبيهات
#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub cpu_threshold: f64,
    pub memory_threshold: f64,
    pub error_rate_threshold: f64,
    pub response_time_threshold: u64,
    pub enabled: bool,
}

/// Performance Monitor
/// مراقب الأداء
pub struct PerformanceMonitor {
    metrics_history: Arc<Mutex<Vec<PerformanceMetrics>>>,
    alert_config: Arc<Mutex<AlertConfig>>,
    health_checks: Arc<Mutex<Vec<HealthCheckResult>>>,
    is_monitoring: Arc<Mutex<bool>>,
}

impl PerformanceMonitor {
    /// Create new Performance Monitor
    /// إنشاء مراقب أداء جديد
    pub fn new() -> Self {
        Self {
            metrics_history: Arc::new(Mutex::new(Vec::new())),
            alert_config: Arc::new(Mutex::new(AlertConfig {
                cpu_threshold: 80.0,
                memory_threshold: 85.0,
                error_rate_threshold: 5.0,
                response_time_threshold: 5000,
                enabled: true,
            })),
            health_checks: Arc::new(Mutex::new(Vec::new())),
            is_monitoring: Arc::new(Mutex::new(false)),
        }
    }

    /// Start Monitoring
    /// بدء المراقبة
    pub fn start_monitoring(&self) -> Result<(), String> {
        let mut is_monitoring = self.is_monitoring.lock().map_err(|e| e.to_string())?;
        *is_monitoring = true;
        Ok(())
    }

    /// Stop Monitoring
    /// إيقاف المراقبة
    pub fn stop_monitoring(&self) -> Result<(), String> {
        let mut is_monitoring = self.is_monitoring.lock().map_err(|e| e.to_string())?;
        *is_monitoring = false;
        Ok(())
    }

    /// Collect Performance Metrics
    /// جمع مقاييس الأداء
    pub fn collect_metrics(&self) -> Result<PerformanceMetrics, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as u64;

        // Simulate metric collection
        let metrics = PerformanceMetrics {
            cpu_usage: self.get_cpu_usage(),
            memory_usage: self.get_memory_usage(),
            memory_total: 8 * 1024 * 1024 * 1024,      // 8GB
            memory_used: (8 * 1024 * 1024 * 1024) / 2, // 4GB
            request_rate: self.get_request_rate(),
            error_rate: self.get_error_rate(),
            response_time_ms: self.get_response_time(),
            active_connections: self.get_active_connections(),
            timestamp,
        };

        // Store metrics history
        let mut history = self.metrics_history.lock().map_err(|e| e.to_string())?;
        history.push(metrics.clone());

        // Keep only last 1000 metrics
        if history.len() > 1000 {
            history.remove(0);
        }

        Ok(metrics)
    }

    /// Perform Health Check
    /// إجراء فحص الصحة
    pub fn perform_health_check(&self) -> Result<HealthCheckResult, String> {
        let metrics = self.collect_metrics()?;
        let alert_config = self.alert_config.lock().map_err(|e| e.to_string())?;

        let (status, message) = if metrics.cpu_usage > alert_config.cpu_threshold {
            (
                HealthStatus::Critical,
                format!("CPU usage critical: {:.1}%", metrics.cpu_usage),
            )
        } else if metrics.memory_usage > alert_config.memory_threshold {
            (
                HealthStatus::Critical,
                format!("Memory usage critical: {:.1}%", metrics.memory_usage),
            )
        } else if metrics.error_rate > alert_config.error_rate_threshold {
            (
                HealthStatus::Warning,
                format!("Error rate high: {:.1}%", metrics.error_rate),
            )
        } else if metrics.response_time_ms > alert_config.response_time_threshold {
            (
                HealthStatus::Warning,
                format!("Response time slow: {}ms", metrics.response_time_ms),
            )
        } else {
            (HealthStatus::Healthy, "System is healthy".to_string())
        };

        let health_check = HealthCheckResult {
            status,
            message,
            timestamp: metrics.timestamp,
            metrics,
        };

        // Store health check result
        let mut health_checks = self.health_checks.lock().map_err(|e| e.to_string())?;
        health_checks.push(health_check.clone());

        // Keep only last 100 health checks
        if health_checks.len() > 100 {
            health_checks.remove(0);
        }

        Ok(health_check)
    }

    /// Get Performance Statistics
    /// الحصول على إحصائيات الأداء
    pub fn get_performance_stats(&self) -> Result<HashMap<String, f64>, String> {
        let history = self.metrics_history.lock().map_err(|e| e.to_string())?;
        let mut stats = HashMap::new();

        if history.is_empty() {
            return Ok(stats);
        }

        let avg_cpu = history.iter().map(|m| m.cpu_usage).sum::<f64>() / history.len() as f64;
        let avg_memory = history.iter().map(|m| m.memory_usage).sum::<f64>() / history.len() as f64;
        let avg_response_time =
            history.iter().map(|m| m.response_time_ms).sum::<u64>() as f64 / history.len() as f64;
        let total_requests = history.iter().map(|m| m.request_rate).sum::<u64>() as f64;

        stats.insert("avg_cpu_usage".to_string(), avg_cpu);
        stats.insert("avg_memory_usage".to_string(), avg_memory);
        stats.insert("avg_response_time".to_string(), avg_response_time);
        stats.insert("total_requests".to_string(), total_requests);

        Ok(stats)
    }

    /// Update Alert Configuration
    /// تحديث تكوين التنبيهات
    pub fn update_alert_config(&self, config: AlertConfig) -> Result<(), String> {
        let mut alert_config = self.alert_config.lock().map_err(|e| e.to_string())?;
        *alert_config = config;
        Ok(())
    }

    /// Get Alert Configuration
    /// الحصول على تكوين التنبيهات
    pub fn get_alert_config(&self) -> Result<AlertConfig, String> {
        let alert_config = self.alert_config.lock().map_err(|e| e.to_string())?;
        Ok(alert_config.clone())
    }

    // Helper methods to simulate system metrics
    fn get_cpu_usage(&self) -> f64 {
        // Simulate CPU usage between 10-90%
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        (hasher.finish() % 80 + 10) as f64
    }

    fn get_memory_usage(&self) -> f64 {
        // Simulate memory usage between 20-80%
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 60)
            .hash(&mut hasher);
        (hasher.finish() % 60 + 20) as f64
    }

    fn get_request_rate(&self) -> u64 {
        // Simulate request rate between 100-1000 req/min
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 30)
            .hash(&mut hasher);
        hasher.finish() % 900 + 100
    }

    fn get_error_rate(&self) -> f64 {
        // Simulate error rate between 0-10%
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 15)
            .hash(&mut hasher);
        (hasher.finish() % 10) as f64
    }

    fn get_response_time(&self) -> u64 {
        // Simulate response time between 50-500ms
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 1000)
            .hash(&mut hasher);
        hasher.finish() % 450 + 50
    }

    fn get_active_connections(&self) -> u64 {
        // Simulate active connections between 10-100
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 20)
            .hash(&mut hasher);
        hasher.finish() % 90 + 10
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Global Performance Monitor Instance
/// مثيل مراقب الأداء العالمي
use std::sync::OnceLock;
static PERFORMANCE_MONITOR: OnceLock<PerformanceMonitor> = OnceLock::new();

/// Get Global Performance Monitor
/// الحصول على مراقب الأداء العالمي
pub fn get_performance_monitor() -> &'static PerformanceMonitor {
    PERFORMANCE_MONITOR.get_or_init(PerformanceMonitor::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_monitor_creation() {
        let monitor = PerformanceMonitor::new();
        assert!(monitor.collect_metrics().is_ok());
    }

    #[test]
    fn test_health_check() {
        let monitor = PerformanceMonitor::new();
        let result = monitor.perform_health_check().unwrap();
        assert!(matches!(
            result.status,
            HealthStatus::Healthy | HealthStatus::Warning | HealthStatus::Critical
        ));
    }

    #[test]
    fn test_alert_config() {
        let monitor = PerformanceMonitor::new();
        let config = AlertConfig {
            cpu_threshold: 75.0,
            memory_threshold: 80.0,
            error_rate_threshold: 3.0,
            response_time_threshold: 3000,
            enabled: true,
        };
        assert!(monitor.update_alert_config(config).is_ok());
    }
}
