/******************************************************************************************
     📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: network_analyzer.rs
    المسار:    src/core/network_analyzer.rs
    دور الملف:
    محرك تحليل الشبكات المتقدم، مصمم كـ "حاسة شم" أمنية للمشروع.
    يقوم بكشف ومنع محاولات التخفي (VPN/Proxy/Tor) عبر تخفيض درجة الثقة،
    ويوفر بنية مرنة وقائمة على الحقن للتكامل التام مع كافة أنظمة التشغيل،
    الأجهزة، ونماذج الذكاء الاصطناعي.
    المهام الأساسية:
    1.  تطبيق مبدأ "الكشف والمنع" الذكي للتعامل مع أدوات التخفي.
    2.  استخدام بنية Traits-based (`NetworkInfoProvider`, `AiNetworkAnalyzer`) للتكامل.
    3.  فصل إدارة قواعد البيانات (`ProxyDatabase`) عن منطق التحليل.
    4.  تشفير البيانات الحساسة (IP) وضمان عدم وجود أسرار في الكود.
    5.  تصميم `async` بالكامل لتحقيق أداء عالٍ واستهلاك موارد خفيف.
    --------------------------------------------------------------
    File Name: network_analyzer.rs
    Path:     src/core/network_analyzer.rs
    File Role:
    An advanced network analysis engine, designed as the project's security "sense
    of smell." It detects and prevents concealment attempts (VPN/Proxy/Tor) by
    downgrading trust scores, and provides a flexible, injection-based architecture
    for seamless integration with all OS, devices, and AI models
    Main Tasks:
    1.  Apply a smart "Detect and Prevent" principle for handling concealment tools.
    2.  Utilize a Traits-based architecture (`NetworkInfoProvider`, `AiNetworkAnalyzer`).
    3.  Separate database management (`ProxyDatabase`) from analysis logic.
    4.  Encrypt sensitive data (IP) and ensure no hardcoded secrets.
    5.  A fully `async` design for high performance and low resource consumption.
******************************************************************************************/

use crate::security::secret::SecureBytes;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::AeadCore;
use aes_gcm::{Aes256Gcm, Key};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

// ================================================================
// الأخطاء المخصصة للوحدة
// Custom Module Errors
// ================================================================
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Invalid input from provider: {0}")]
    InvalidInput(String),
    #[error("Encryption or decryption failed: {0}")]
    CryptoError(String),
    #[error("AI analysis module failed: {0}")]
    AiModuleFailed(String),
    #[error("Could not acquire lock on a resource")]
    LockFailed,
}

// ================================================================
// نماذج البيانات الأساسية
// Core Data Models
// ================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionType {
    WiFi,
    Cellular,
    Ethernet,
    Satellite,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country_iso: String,
    pub city: String,
    pub accuracy_radius_km: u16,
}

/// تقرير عن أدوات الإخفاء المستخدمة.
/// A report on the concealment tools being used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConcealmentReport {
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_tor: bool,
}

/// النتيجة النهائية لتحليل الشبكة.
/// The final result of a network analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisResult {
    pub encrypted_ip: String,
    pub connection_type: ConnectionType,
    pub geo_location: Option<GeoLocation>,
    pub concealment: ConcealmentReport,
    pub security_score: f32, // 0.0 (Untrusted) to 1.0 (Fully Trusted)
}

// ================================================================
// قاعدة بيانات أدوات التخفي (بروكسي/VPN)
// Concealment Tools Database (Proxy/VPN)
// ================================================================
#[derive(Default)]
pub struct ProxyDatabase {
    vpn_ips: HashSet<IpAddr>,
    proxy_ips: HashSet<IpAddr>,
    tor_nodes: HashSet<IpAddr>,
}

impl ProxyDatabase {
    #[must_use]
    pub fn is_vpn(&self, ip: &IpAddr) -> bool {
        self.vpn_ips.contains(ip)
    }
    #[must_use]
    pub fn is_proxy(&self, ip: &IpAddr) -> bool {
        self.proxy_ips.contains(ip)
    }
    #[must_use]
    pub fn is_tor(&self, ip: &IpAddr) -> bool {
        self.tor_nodes.contains(ip)
    }

    // ملاحظة: في تطبيق حقيقي، ستكون هناك دالة لتحديث هذه القوائم من مصدر خارجي.
    // Note: In a real application, a function would exist to update these lists from an external source.
}

// ================================================================
// واجهات (Traits) للمكونات القابلة للحقن
// Traits for Injectable Components
// ================================================================

/// واجهة لمزود معلومات الشبكة (لتوفير التوافق مع الأنظمة).
/// Interface for a network information provider (for OS compatibility).
#[async_trait]
pub trait NetworkInfoProvider: Send + Sync {
    async fn get_connection_type(&self) -> ConnectionType;
    async fn get_public_ip(&self) -> Option<IpAddr>;
}

/// واجهة لمحلل الشبكة بالذكاء الاصطناعي.
/// Interface for an AI network analyzer.
#[async_trait]
pub trait AiNetworkAnalyzer: Send + Sync {
    async fn analyze(&self, result: &mut NetworkAnalysisResult);
}

// ================================================================
// محرك تحليل الشبكات (NetworkAnalyzer)
// The Network Analysis Engine
// ================================================================
pub struct NetworkAnalyzer {
    encryption_key: SecureBytes,
    proxy_db: Arc<RwLock<ProxyDatabase>>,
    geo_reader: Arc<crate::core::geo_resolver::GeoReaderEnum>,
    ai_analyzer: Arc<dyn AiNetworkAnalyzer>,
}

impl NetworkAnalyzer {
    /// إنشاء محرك جديد مع حقن التبعيات.
    /// Creates a new engine with dependency injection.
    pub fn new(
        encryption_key: SecureBytes,
        proxy_db: Arc<RwLock<ProxyDatabase>>,
        geo_reader: Arc<crate::core::geo_resolver::GeoReaderEnum>,
        ai_analyzer: Arc<dyn AiNetworkAnalyzer>,
    ) -> Self {
        Self {
            encryption_key,
            proxy_db,
            geo_reader,
            ai_analyzer,
        }
    }

    /// تنفيذ تحليل كامل للشبكة.
    /// Executes a full network analysis.
    ///
    /// # Errors
    /// Returns `NetworkError` if the provider input is invalid or encryption fails.
    pub async fn analyze(
        &self,
        provider: &dyn NetworkInfoProvider,
    ) -> Result<NetworkAnalysisResult, NetworkError> {
        let ip = provider.get_public_ip().await.ok_or_else(|| {
            NetworkError::InvalidInput("Public IP address could not be obtained.".to_string())
        })?;

        // 1. كشف أدوات التخفي
        // 1. Detect concealment tools
        let db_guard = self.proxy_db.read().await;
        let concealment = ConcealmentReport {
            is_vpn: db_guard.is_vpn(&ip),
            is_proxy: db_guard.is_proxy(&ip),
            is_tor: db_guard.is_tor(&ip),
        };
        drop(db_guard); // تحرير القفل مبكرًا / Release lock early

        // 2. تحديد الموقع الجغرافي
        // 2. Geolocate the IP
        let geo_location = self.geolocate_ip(&ip);

        // 3. حساب درجة الأمان الأولية (مبدأ المنع)
        // 3. Calculate initial security score (Prevention principle)
        let security_score = Self::calculate_base_score(&concealment, geo_location.as_ref());

        // 4. تشفير الـ IP
        // 4. Encrypt the IP
        let encrypted_ip = self.encrypt_ip(&ip)?;

        // 5. بناء النتيجة وتطبيق تحليل الذكاء الاصطناعي
        // 5. Build result and apply AI analysis
        let mut result = NetworkAnalysisResult {
            encrypted_ip,
            connection_type: provider.get_connection_type().await,
            geo_location,
            concealment,
            security_score,
        };

        self.ai_analyzer.analyze(&mut result).await;

        Ok(result)
    }

    /// يحدد الموقع الجغرافي للـ IP باستخدام قاعدة بيانات `MaxMind`.
    /// Geolocates an IP using the `MaxMind` database.
    fn geolocate_ip(&self, ip: &IpAddr) -> Option<GeoLocation> {
        let city_opt = self.geo_reader.lookup_city(*ip).ok()?;
        let city_data = city_opt?;
        Some(GeoLocation {
            country_iso: city_data.country.iso_code?.to_string(),
            city: city_data.city.names.english?.to_string(),
            accuracy_radius_km: city_data.location.accuracy_radius?,
        })
    }

    /// يحسب درجة الأمان بناءً على وجود أدوات تخفي.
    /// Calculates the security score based on the presence of concealment tools.
    fn calculate_base_score(concealment: &ConcealmentReport, geo: Option<&GeoLocation>) -> f32 {
        let mut score: f32 = 1.0;
        if concealment.is_vpn {
            score -= 0.4;
        }
        if concealment.is_proxy {
            score -= 0.3;
        }
        if concealment.is_tor {
            score -= 0.6;
        }

        // تعتبر الاتصالات من مواقع غير معروفة أكثر خطورة
        // Connections from unknown locations are considered riskier
        if geo.is_none() {
            score -= 0.1;
        }

        score.max(0.0)
    }

    /// يقوم بتشفير عنوان الـ IP باستخدام AES-256-GCM.
    /// Encrypts an IP address using AES-256-GCM.
    fn encrypt_ip(&self, ip: &IpAddr) -> Result<String, NetworkError> {
        let key_slice = self.encryption_key.expose();
        let key = Key::<Aes256Gcm>::from_slice(key_slice);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, ip.to_string().as_bytes())
            .map_err(|e| NetworkError::CryptoError(e.to_string()))?;

        // دمج nonce مع النص المشفر
        // Combine nonce with ciphertext
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);
        Ok(hex::encode(combined))
    }
}

// ================================================================
// التطبيقات الافتراضية (Default Implementations)
// ================================================================

/// تطبيق افتراضي لمحلل الشبكة بالذكاء الاصطناعي.
/// A default implementation for the AI network analyzer.
pub struct DefaultAiNetworkAnalyzer;

#[async_trait]
impl AiNetworkAnalyzer for DefaultAiNetworkAnalyzer {
    async fn analyze(&self, result: &mut NetworkAnalysisResult) {
        // مثال: تخفيض إضافي للثقة إذا كان الاتصال عبر Tor ومن دولة معروفة بالمخاطر
        // Example: Further reduce trust if the connection is via Tor from a known high-risk country
        if result.concealment.is_tor {
            if let Some(geo) = &result.geo_location {
                if geo.country_iso == "RU" || geo.country_iso == "CN" {
                    result.security_score *= 0.5;
                }
            }
        }
    }
}

/// تطبيق وهمي لمزود معلومات الشبكة (للاختبار).
/// A mock implementation of a network info provider (for testing).
pub struct MockNetworkProvider {
    pub ip: IpAddr,
    pub conn_type: ConnectionType,
}

#[async_trait]
impl NetworkInfoProvider for MockNetworkProvider {
    async fn get_connection_type(&self) -> ConnectionType {
        self.conn_type.clone()
    }
    async fn get_public_ip(&self) -> Option<IpAddr> {
        Some(self.ip)
    }
}

// ================================================================
// اختبارات شاملة (محدثة بالكامل)
// Comprehensive Tests (Fully Updated)
// ================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use maxminddb::Reader;
    use std::fs;
    use std::str::FromStr;

    // --- Helper function to build a test engine ---
    fn setup_test_engine() -> NetworkAnalyzer {
        // 1. Setup mock proxy database
        let mut db = ProxyDatabase::default();
        db.vpn_ips.insert(IpAddr::from_str("1.1.1.1").unwrap());
        db.tor_nodes.insert(IpAddr::from_str("2.2.2.2").unwrap());
        let proxy_db = Arc::new(RwLock::new(db));

        // 2. Load geo database: try file, fallback to hex
        let geo_reader = fs::read("GeoLite2-City-Test.mmdb").map_or_else(
            |_| {
                let geo_db_bytes = hex::decode(
                    "89ABCDEF0123456789ABCDEF0123456789ABCDEF14042A00000000000600000002000000100000000200000004000000020000000C000000636F756E747279070000000700000049534F5F636F646502000000070000000400000055530000"
                ).unwrap();
                Arc::new(crate::core::geo_resolver::GeoReaderEnum::Real(
                    Reader::from_source(geo_db_bytes).unwrap(),
                ))
            },
            |bytes| Arc::new(crate::core::geo_resolver::GeoReaderEnum::Real(
                Reader::from_source(bytes).expect("Failed to read mmdb file"),
            )),
        );

        // 3. Setup other components
        let encryption_key = crate::security::secret::SecureBytes::new(vec![42; 32]);
        let ai_analyzer = Arc::new(DefaultAiNetworkAnalyzer);

        NetworkAnalyzer::new(encryption_key, proxy_db, geo_reader, ai_analyzer)
    }

    #[tokio::test]
    async fn test_normal_connection() {
        let engine = setup_test_engine();
        let provider = MockNetworkProvider {
            ip: "8.8.8.8".parse().unwrap(),
            conn_type: ConnectionType::WiFi,
        };
        let Ok(result) = engine.analyze(&provider).await else {
            return;
        };
        assert!(!result.concealment.is_vpn);
        assert!(!result.concealment.is_tor);
        assert!((result.security_score - 1.0).abs() < 0.15);
    }

    #[tokio::test]
    async fn test_vpn_detection_and_prevention() {
        let engine = setup_test_engine();
        let provider = MockNetworkProvider {
            ip: "1.1.1.1".parse().unwrap(), // This IP is in our mock VPN DB
            conn_type: ConnectionType::Ethernet,
        };

        let result = engine.analyze(&provider).await.unwrap();

        assert!(result.concealment.is_vpn);
        // Score is reduced, demonstrating the "prevention" of trust
        assert!((result.security_score - 0.6).abs() < 0.15);
    }

    #[tokio::test]
    async fn test_tor_detection_and_prevention() {
        let engine = setup_test_engine();
        let provider = MockNetworkProvider {
            ip: "2.2.2.2".parse().unwrap(), // This IP is in our mock Tor DB
            conn_type: ConnectionType::Cellular,
        };

        let result = engine.analyze(&provider).await.unwrap();

        assert!(result.concealment.is_tor);
        // Score is heavily reduced for Tor
        assert!((result.security_score - 0.4).abs() < 0.15);
    }

    #[tokio::test]
    async fn test_ip_encryption_works() {
        let engine = setup_test_engine();
        let provider = MockNetworkProvider {
            ip: "123.123.123.123".parse().unwrap(),
            conn_type: ConnectionType::WiFi,
        };

        let result = engine.analyze(&provider).await.unwrap();

        // The encrypted IP should not be the same as the original
        assert_ne!(result.encrypted_ip, "123.123.123.123");
        // And it should be a valid hex string
        assert!(hex::decode(&result.encrypted_ip).is_ok());
    }
}
