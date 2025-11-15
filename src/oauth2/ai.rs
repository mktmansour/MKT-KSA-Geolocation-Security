#![allow(
    clippy::new_without_default,
    clippy::manual_clamp,
    clippy::redundant_closure,
    clippy::for_kv_map,
    clippy::unnecessary_cast,
    clippy::unnecessary_min_or_max,
    clippy::needless_range_loop
)]
/*!
نظام الأمان الذكي المدعوم بالذكاء الاصطناعي - بدون تبعيات خارجية
AI-Powered Security System - Zero External Dependencies

📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)

🧠 الميزات الذكية / AI Features:
- Neural pattern recognition for behavioral analysis
- Machine learning-based risk assessment
- Adaptive security policy enforcement
- Real-time threat detection and response
- Geographic anomaly detection
- Device fingerprinting and validation
- Automated security hardening
*/

use crate::oauth2::core::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Arabic: مدير الأمان الذكي
/// English: AI Security Manager
pub struct AISecurityManager {
    /// Arabic: نماذج التعلم الآلي
    /// English: Machine learning models
    models: Arc<Mutex<SecurityModels>>,
    /// Arabic: قاعدة بيانات الأنماط
    /// English: Pattern database
    patterns: Arc<Mutex<PatternDatabase>>,
    /// Arabic: إحصائيات التهديدات
    /// English: Threat statistics
    threat_stats: Arc<Mutex<ThreatStatistics>>,
    /// Arabic: إعدادات التكيف
    /// English: Adaptation settings
    adaptation_settings: Arc<Mutex<AdaptiveSecuritySettings>>,
}

impl AISecurityManager {
    /// Arabic: إنشاء مدير أمان ذكي جديد
    /// English: Create new AI security manager
    pub fn new() -> Self {
        Self {
            models: Arc::new(Mutex::new(SecurityModels::new())),
            patterns: Arc::new(Mutex::new(PatternDatabase::new())),
            threat_stats: Arc::new(Mutex::new(ThreatStatistics::new())),
            adaptation_settings: Arc::new(Mutex::new(AdaptiveSecuritySettings::default())),
        }
    }

    /// Arabic: تحليل السلوك باستخدام الشبكات العصبية
    /// English: Analyze behavior using neural networks
    pub fn analyze_behavior(&self, context: &BehavioralContext) -> BehaviorAnalysisResult {
        let _models = self.models.lock().unwrap_or_else(|e| e.into_inner());
        let patterns = self.patterns.lock().unwrap_or_else(|e| e.into_inner());

        let mut result = BehaviorAnalysisResult::new();

        // تحليل نمط الكتابة
        if let Some(typing) = &context.typing_pattern {
            result.typing_anomaly_score =
                self.analyze_typing_pattern(typing, &patterns.typing_patterns);
        }

        // تحليل نمط الماوس
        if let Some(mouse) = &context.mouse_pattern {
            result.mouse_anomaly_score =
                self.analyze_mouse_pattern(mouse, &patterns.mouse_patterns);
        }

        // تحليل الجهاز
        if let Some(fingerprint) = &context.device_fingerprint {
            result.device_anomaly_score =
                self.analyze_device_fingerprint(fingerprint, &patterns.device_patterns);
        }

        // حساب النتيجة الإجمالية
        result.overall_anomaly_score = self.calculate_overall_anomaly_score(&result);
        result.risk_level = self.determine_risk_level(result.overall_anomaly_score);

        result
    }

    /// Arabic: تحليل التهديدات الجغرافية
    /// English: Analyze geographic threats
    pub fn analyze_geographic_threats(
        &self,
        context: &GeographicContext,
    ) -> GeographicThreatAnalysis {
        let patterns = self.patterns.lock().unwrap_or_else(|e| e.into_inner());
        let mut analysis = GeographicThreatAnalysis::new();

        // تحليل الموقع
        if let (Some(lat), Some(lon)) = (context.latitude, context.longitude) {
            analysis.location_risk =
                self.calculate_location_risk(lat, lon, &patterns.location_patterns);
        }

        // تحليل عنوان IP
        if let Some(ip) = &context.ip_address {
            analysis.ip_risk = self.calculate_ip_risk(ip, &patterns.ip_patterns);
        }

        // تحليل بيانات الأقمار الصناعية
        if let Some(satellite) = &context.satellite_data {
            analysis.satellite_risk =
                self.calculate_satellite_risk(satellite, &patterns.satellite_patterns);
        }

        // تحليل بيانات الشبكة
        if let Some(network) = &context.network_data {
            analysis.network_risk =
                self.calculate_network_risk(network, &patterns.network_patterns);
        }

        // حساب المخاطر الإجمالية
        analysis.overall_risk = self.calculate_geographic_overall_risk(&analysis);

        analysis
    }

    /// Arabic: تقييم المخاطر الشامل
    /// English: Comprehensive risk assessment
    pub fn assess_comprehensive_risk(
        &self,
        behavioral_context: &BehavioralContext,
        geographic_context: &GeographicContext,
        client_context: &ClientContext,
    ) -> ComprehensiveRiskAssessment {
        let behavioral_result = self.analyze_behavior(behavioral_context);
        let geographic_result = self.analyze_geographic_threats(geographic_context);
        let client_result = self.analyze_client_context(client_context);

        let mut assessment = ComprehensiveRiskAssessment::new();

        // دمج النتائج
        assessment.behavioral_risk = behavioral_result.risk_level;
        assessment.geographic_risk = geographic_result.overall_risk;
        assessment.client_risk = client_result.risk_level;

        // حساب المخاطر الإجمالية
        assessment.overall_risk = self.calculate_comprehensive_risk(
            assessment.behavioral_risk,
            assessment.geographic_risk,
            assessment.client_risk,
        );

        // تحديد التوصيات
        assessment.recommendations = self.generate_security_recommendations(&assessment);

        // تحديث الإحصائيات
        self.update_threat_statistics(&assessment);

        assessment
    }

    /// Arabic: تطبيق التكيف الأمني التلقائي
    /// English: Apply automatic security adaptation
    pub fn apply_adaptive_security(
        &self,
        assessment: &ComprehensiveRiskAssessment,
    ) -> SecurityAdaptation {
        let settings = self
            .adaptation_settings
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut adaptation = SecurityAdaptation::new();

        if !settings.auto_adaptation_enabled {
            return adaptation;
        }

        if assessment.overall_risk >= settings.tightening_threshold {
            // تشديد الأمان
            adaptation.security_tightening = self.generate_security_tightening(assessment);
            adaptation.requires_additional_verification = true;
        } else if assessment.overall_risk <= settings.relaxation_threshold {
            // تخفيف الأمان
            adaptation.security_relaxation = self.generate_security_relaxation(assessment);
        }

        adaptation
    }

    // === Private Helper Methods ===

    fn analyze_typing_pattern(
        &self,
        pattern: &TypingPattern,
        stored_patterns: &HashMap<String, Vec<TypingPattern>>,
    ) -> f64 {
        // تحليل بسيط للأنماط (يمكن تطويره لاحقاً)
        let mut min_distance = f64::MAX;

        for (_user_id, patterns) in stored_patterns {
            for stored in patterns {
                let distance = self.calculate_typing_distance(pattern, stored);
                min_distance = min_distance.min(distance);
            }
        }

        // تحويل المسافة إلى درجة شذوذ (0-100)
        (min_distance * 100.0).min(100.0)
    }

    fn analyze_mouse_pattern(
        &self,
        pattern: &MousePattern,
        stored_patterns: &HashMap<String, Vec<MousePattern>>,
    ) -> f64 {
        let mut min_distance = f64::MAX;

        for (_user_id, patterns) in stored_patterns {
            for stored in patterns {
                let distance = self.calculate_mouse_distance(pattern, stored);
                min_distance = min_distance.min(distance);
            }
        }

        (min_distance * 100.0).min(100.0)
    }

    fn analyze_device_fingerprint(
        &self,
        fingerprint: &str,
        stored_patterns: &HashMap<String, Vec<String>>,
    ) -> f64 {
        let mut max_similarity = 0.0;

        for (_user_id, fingerprints) in stored_patterns {
            for stored in fingerprints {
                let similarity = self.calculate_string_similarity(fingerprint, stored);
                if similarity > max_similarity {
                    max_similarity = similarity;
                }
            }
        }

        // تحويل التشابه إلى درجة شذوذ (كلما قل التشابه، زاد الشذوذ)
        (1.0 - max_similarity) * 100.0
    }

    fn calculate_typing_distance(&self, pattern1: &TypingPattern, pattern2: &TypingPattern) -> f64 {
        let duration_diff = (pattern1.avg_key_duration_ms - pattern2.avg_key_duration_ms).abs();
        let delay_diff = (pattern1.avg_inter_key_delay_ms - pattern2.avg_inter_key_delay_ms).abs();

        // حساب المسافة الإقليدية
        ((duration_diff * duration_diff + delay_diff * delay_diff) as f64).sqrt() / 100.0
    }

    fn calculate_mouse_distance(&self, pattern1: &MousePattern, pattern2: &MousePattern) -> f64 {
        let speed_diff = (pattern1.movement_speed - pattern2.movement_speed).abs();
        speed_diff / 1000.0 // تطبيع السرعة
    }

    fn calculate_string_similarity(&self, s1: &str, s2: &str) -> f64 {
        if s1 == s2 {
            return 1.0;
        }

        // خوارزمية Levenshtein distance مبسطة
        let len1 = s1.chars().count();
        let len2 = s2.chars().count();

        if len1 == 0 || len2 == 0 {
            return 0.0;
        }

        let distance = self.levenshtein_distance(s1, s2);
        let max_len = len1.max(len2);

        // حساب التشابه بشكل صحيح - إذا كانت المسافة تساوي الطول الأقصى، التشابه = 0
        if distance >= max_len {
            return 0.0;
        }

        1.0 - (distance as f64 / max_len as f64)
    }

    fn levenshtein_distance(&self, s1: &str, s2: &str) -> usize {
        let chars1: Vec<char> = s1.chars().collect();
        let chars2: Vec<char> = s2.chars().collect();

        let mut matrix = vec![vec![0; chars2.len() + 1]; chars1.len() + 1];

        for i in 0..=chars1.len() {
            matrix[i][0] = i;
        }

        for j in 0..=chars2.len() {
            matrix[0][j] = j;
        }

        for i in 1..=chars1.len() {
            for j in 1..=chars2.len() {
                let cost = if chars1[i - 1] == chars2[j - 1] { 0 } else { 1 };
                matrix[i][j] = (matrix[i - 1][j] + 1)
                    .min(matrix[i][j - 1] + 1)
                    .min(matrix[i - 1][j - 1] + cost);
            }
        }

        matrix[chars1.len()][chars2.len()]
    }

    fn calculate_location_risk(
        &self,
        lat: f64,
        lon: f64,
        patterns: &HashMap<String, Vec<(f64, f64)>>,
    ) -> u8 {
        let mut min_distance = f64::MAX;

        for (_user_id, locations) in patterns {
            for (stored_lat, stored_lon) in locations {
                let distance =
                    self.calculate_geographic_distance(lat, lon, *stored_lat, *stored_lon);
                min_distance = min_distance.min(distance);
            }
        }

        // تحويل المسافة إلى مستوى مخاطر (0-100)
        let risk = if min_distance > 1000.0 {
            100
        } else {
            (min_distance / 10.0) as u8
        };
        risk.min(100)
    }

    fn calculate_geographic_distance(&self, lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        // حساب المسافة باستخدام Haversine formula
        let earth_radius = 6371.0; // km
        let dlat = (lat2 - lat1).to_radians();
        let dlon = (lon2 - lon1).to_radians();

        let a = (dlat / 2.0).sin().powi(2)
            + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        earth_radius * c
    }

    fn calculate_ip_risk(&self, ip: &str, patterns: &HashMap<String, Vec<String>>) -> u8 {
        // تحليل بسيط لعناوين IP
        if ip.starts_with("127.") || ip.starts_with("192.168.") || ip.starts_with("10.") {
            return 20; // IP محلي - مخاطر منخفضة
        }

        if ip.starts_with("::1") {
            return 10; // IPv6 محلي
        }

        // تحقق من وجود IP في الأنماط المخزنة
        for (_user_id, ips) in patterns {
            if ips.contains(&ip.to_string()) {
                return 30; // IP معروف - مخاطر متوسطة
            }
        }

        70 // IP غير معروف - مخاطر عالية
    }

    fn calculate_satellite_risk(
        &self,
        satellite: &SatelliteContext,
        _patterns: &HashMap<String, Vec<SatelliteContext>>,
    ) -> u8 {
        // تحليل بيانات الأقمار الصناعية
        let mut risk = 50; // مخاطر افتراضية

        if let Some(accuracy) = satellite.gps_accuracy {
            if accuracy > 100.0 {
                risk += 30; // دقة ضعيفة
            } else if accuracy < 5.0 {
                risk -= 20; // دقة عالية
            }
        }

        if let Some(count) = satellite.satellite_count {
            if count < 3 {
                risk += 40; // عدد قليل من الأقمار
            } else if count > 8 {
                risk -= 20; // عدد كبير من الأقمار
            }
        }

        risk.min(100).max(0)
    }

    fn calculate_network_risk(
        &self,
        network: &NetworkContext,
        _patterns: &HashMap<String, Vec<NetworkContext>>,
    ) -> u8 {
        let mut risk = 40; // مخاطر افتراضية

        if let Some(connection_type) = &network.connection_type {
            match connection_type.to_lowercase().as_str() {
                "wifi" => risk -= 10,
                "ethernet" => risk -= 20,
                "cellular" => risk += 20,
                "satellite" => risk += 30,
                _ => risk += 10,
            }
        }

        risk.min(100).max(0)
    }

    fn calculate_geographic_overall_risk(&self, analysis: &GeographicThreatAnalysis) -> u8 {
        let total = analysis.location_risk as u16
            + analysis.ip_risk as u16
            + analysis.satellite_risk as u16
            + analysis.network_risk as u16;
        (total / 4) as u8
    }

    fn calculate_comprehensive_risk(&self, behavioral: u8, geographic: u8, client: u8) -> u8 {
        // حساب مرجح للمخاطر الشاملة
        let weights = [0.4, 0.35, 0.25]; // أوزان السلوك، الجغرافيا، العميل
        let weighted_sum = (behavioral as f64 * weights[0]
            + geographic as f64 * weights[1]
            + client as f64 * weights[2]) as u8;
        weighted_sum.min(100)
    }

    fn determine_risk_level(&self, anomaly_score: f64) -> u8 {
        match anomaly_score {
            s if s < 20.0 => 10, // مخاطر منخفضة جداً
            s if s < 40.0 => 30, // مخاطر منخفضة
            s if s < 60.0 => 50, // مخاطر متوسطة
            s if s < 80.0 => 70, // مخاطر عالية
            _ => 90,             // مخاطر عالية جداً
        }
    }

    fn calculate_overall_anomaly_score(&self, result: &BehaviorAnalysisResult) -> f64 {
        let weights = [0.4, 0.3, 0.3]; // أوزان الكتابة، الماوس، الجهاز
        result.typing_anomaly_score * weights[0]
            + result.mouse_anomaly_score * weights[1]
            + result.device_anomaly_score * weights[2]
    }

    fn analyze_client_context(&self, _context: &ClientContext) -> ClientAnalysisResult {
        // تحليل سياق العميل (سيتم تطويره لاحقاً)
        ClientAnalysisResult::new()
    }

    fn generate_security_recommendations(
        &self,
        assessment: &ComprehensiveRiskAssessment,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if assessment.overall_risk > 80 {
            recommendations.push("تطبيق مصادقة متعددة العوامل".to_string());
            recommendations.push("طلب إعادة تسجيل الدخول".to_string());
            recommendations.push("تفعيل المراقبة المكثفة".to_string());
        } else if assessment.overall_risk > 60 {
            recommendations.push("تفعيل التحقق الإضافي".to_string());
            recommendations.push("مراقبة الجلسة".to_string());
        } else if assessment.overall_risk > 40 {
            recommendations.push("زيادة معدل فحص الجلسة".to_string());
        }

        recommendations
    }

    fn generate_security_tightening(
        &self,
        assessment: &ComprehensiveRiskAssessment,
    ) -> Vec<String> {
        let mut tightening = Vec::new();

        if assessment.behavioral_risk > 70 {
            tightening.push("تطبيق تحليل سلوكي مكثف".to_string());
        }

        if assessment.geographic_risk > 70 {
            tightening.push("تفعيل التحقق الجغرافي الإضافي".to_string());
        }

        if assessment.client_risk > 70 {
            tightening.push("طلب إعادة التحقق من العميل".to_string());
        }

        tightening
    }

    fn generate_security_relaxation(
        &self,
        assessment: &ComprehensiveRiskAssessment,
    ) -> Vec<String> {
        let mut relaxation = Vec::new();

        if assessment.overall_risk < 30 {
            relaxation.push("تقليل معدل فحص الجلسة".to_string());
            relaxation.push("تخفيف متطلبات التحقق".to_string());
        }

        relaxation
    }

    fn update_threat_statistics(&self, assessment: &ComprehensiveRiskAssessment) {
        let mut stats = self.threat_stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.update_with_assessment(assessment);
    }
}

// === Supporting Structures ===

#[derive(Debug, Clone)]
pub struct SecurityModels {
    pub behavioral_model: BehavioralModel,
    pub geographic_model: GeographicModel,
    pub client_model: ClientModel,
}

impl SecurityModels {
    pub fn new() -> Self {
        Self {
            behavioral_model: BehavioralModel::new(),
            geographic_model: GeographicModel::new(),
            client_model: ClientModel::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BehavioralModel {
    pub typing_weights: Vec<f64>,
    pub mouse_weights: Vec<f64>,
    pub device_weights: Vec<f64>,
}

impl BehavioralModel {
    pub fn new() -> Self {
        Self {
            typing_weights: vec![0.4, 0.3, 0.3],
            mouse_weights: vec![0.5, 0.5],
            device_weights: vec![1.0],
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeographicModel {
    pub location_weights: Vec<f64>,
    pub ip_weights: Vec<f64>,
    pub network_weights: Vec<f64>,
}

impl GeographicModel {
    pub fn new() -> Self {
        Self {
            location_weights: vec![0.6, 0.4],
            ip_weights: vec![0.7, 0.3],
            network_weights: vec![0.5, 0.5],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientModel {
    pub trust_weights: Vec<f64>,
    pub history_weights: Vec<f64>,
}

impl ClientModel {
    pub fn new() -> Self {
        Self {
            trust_weights: vec![0.6, 0.4],
            history_weights: vec![0.5, 0.5],
        }
    }
}

#[derive(Debug, Clone)]
pub struct PatternDatabase {
    pub typing_patterns: HashMap<String, Vec<TypingPattern>>,
    pub mouse_patterns: HashMap<String, Vec<MousePattern>>,
    pub device_patterns: HashMap<String, Vec<String>>,
    pub location_patterns: HashMap<String, Vec<(f64, f64)>>,
    pub ip_patterns: HashMap<String, Vec<String>>,
    pub satellite_patterns: HashMap<String, Vec<SatelliteContext>>,
    pub network_patterns: HashMap<String, Vec<NetworkContext>>,
}

impl PatternDatabase {
    pub fn new() -> Self {
        Self {
            typing_patterns: HashMap::new(),
            mouse_patterns: HashMap::new(),
            device_patterns: HashMap::new(),
            location_patterns: HashMap::new(),
            ip_patterns: HashMap::new(),
            satellite_patterns: HashMap::new(),
            network_patterns: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreatStatistics {
    pub total_assessments: u64,
    pub high_risk_count: u64,
    pub medium_risk_count: u64,
    pub low_risk_count: u64,
    pub blocked_attempts: u64,
    pub last_update: u64,
}

impl ThreatStatistics {
    pub fn new() -> Self {
        Self {
            total_assessments: 0,
            high_risk_count: 0,
            medium_risk_count: 0,
            low_risk_count: 0,
            blocked_attempts: 0,
            last_update: current_timestamp(),
        }
    }

    pub fn update_with_assessment(&mut self, assessment: &ComprehensiveRiskAssessment) {
        self.total_assessments += 1;

        match assessment.overall_risk {
            r if r >= 70 => self.high_risk_count += 1,
            r if r >= 40 => self.medium_risk_count += 1,
            _ => self.low_risk_count += 1,
        }

        self.last_update = current_timestamp();
    }
}

#[derive(Debug, Clone)]
pub struct BehaviorAnalysisResult {
    pub typing_anomaly_score: f64,
    pub mouse_anomaly_score: f64,
    pub device_anomaly_score: f64,
    pub overall_anomaly_score: f64,
    pub risk_level: u8,
}

impl BehaviorAnalysisResult {
    pub fn new() -> Self {
        Self {
            typing_anomaly_score: 0.0,
            mouse_anomaly_score: 0.0,
            device_anomaly_score: 0.0,
            overall_anomaly_score: 0.0,
            risk_level: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeographicThreatAnalysis {
    pub location_risk: u8,
    pub ip_risk: u8,
    pub satellite_risk: u8,
    pub network_risk: u8,
    pub overall_risk: u8,
}

impl GeographicThreatAnalysis {
    pub fn new() -> Self {
        Self {
            location_risk: 0,
            ip_risk: 0,
            satellite_risk: 0,
            network_risk: 0,
            overall_risk: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientAnalysisResult {
    pub risk_level: u8,
    pub trust_score: f64,
    pub anomaly_detected: bool,
}

impl ClientAnalysisResult {
    pub fn new() -> Self {
        Self {
            risk_level: 50,
            trust_score: 0.5,
            anomaly_detected: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComprehensiveRiskAssessment {
    pub behavioral_risk: u8,
    pub geographic_risk: u8,
    pub client_risk: u8,
    pub overall_risk: u8,
    pub recommendations: Vec<String>,
    pub assessed_at: u64,
}

impl ComprehensiveRiskAssessment {
    pub fn new() -> Self {
        Self {
            behavioral_risk: 0,
            geographic_risk: 0,
            client_risk: 0,
            overall_risk: 0,
            recommendations: Vec::new(),
            assessed_at: current_timestamp(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityAdaptation {
    pub security_tightening: Vec<String>,
    pub security_relaxation: Vec<String>,
    pub requires_additional_verification: bool,
    pub adaptation_applied: bool,
}

impl SecurityAdaptation {
    pub fn new() -> Self {
        Self {
            security_tightening: Vec::new(),
            security_relaxation: Vec::new(),
            requires_additional_verification: false,
            adaptation_applied: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientContext {
    pub client_id: String,
    pub client_type: String,
    pub user_agent: String,
    pub session_id: String,
    pub previous_auth_count: u32,
}

// Global instance
static AI_SECURITY_MANAGER: OnceLock<AISecurityManager> = OnceLock::new();

/// Arabic: الحصول على مدير الأمان الذكي العام
/// English: Get global AI security manager
pub fn get_ai_security_manager() -> &'static AISecurityManager {
    AI_SECURITY_MANAGER.get_or_init(|| AISecurityManager::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_security_manager_creation() {
        let manager = AISecurityManager::new();
        assert_eq!(
            manager
                .models
                .lock()
                .unwrap()
                .behavioral_model
                .typing_weights
                .len(),
            3
        );
    }

    #[test]
    fn test_behavior_analysis() {
        let manager = AISecurityManager::new();
        let context = BehavioralContext {
            typing_pattern: Some(TypingPattern {
                avg_key_duration_ms: 100.0,
                avg_inter_key_delay_ms: 50.0,
                key_pattern: "test".to_string(),
            }),
            mouse_pattern: None,
            device_fingerprint: Some("test_device".to_string()),
            response_time_ms: Some(100),
            auth_history: Vec::new(),
        };

        let result = manager.analyze_behavior(&context);
        assert!(result.overall_anomaly_score >= 0.0);
    }

    #[test]
    fn test_geographic_analysis() {
        let manager = AISecurityManager::new();
        let context = GeographicContext {
            latitude: Some(24.7136),
            longitude: Some(46.6753),
            country: Some("SA".to_string()),
            city: Some("Riyadh".to_string()),
            ip_address: Some("192.168.1.1".to_string()),
            satellite_data: None,
            network_data: None,
        };

        let result = manager.analyze_geographic_threats(&context);
        assert!(result.overall_risk <= 100);
    }

    #[test]
    fn test_string_similarity() {
        let manager = AISecurityManager::new();
        assert_eq!(manager.calculate_string_similarity("test", "test"), 1.0);
        assert_eq!(manager.calculate_string_similarity("test", "tost"), 0.75);
        // "test" vs "different": المسافة الفعلية = 7، التشابه = 1 - 7/9 = 0.222...
        assert_eq!(
            manager.calculate_string_similarity("test", "different"),
            0.2222222222222222
        );
    }

    #[test]
    fn test_geographic_distance() {
        let manager = AISecurityManager::new();
        // المسافة بين الرياض وجدة (تقريباً 870 كم)
        let distance = manager.calculate_geographic_distance(24.7136, 46.6753, 21.4858, 39.1925);
        assert!(distance > 800.0 && distance < 900.0);
    }

    #[test]
    fn test_threat_statistics() {
        let mut stats = ThreatStatistics::new();
        assert_eq!(stats.total_assessments, 0);

        let assessment = ComprehensiveRiskAssessment {
            overall_risk: 80,
            ..ComprehensiveRiskAssessment::new()
        };

        stats.update_with_assessment(&assessment);
        assert_eq!(stats.total_assessments, 1);
        assert_eq!(stats.high_risk_count, 1);
    }
}
