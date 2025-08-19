/******************************************************************************************
    🚦 منصة التحقق المركب للمدن الذكية MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Smart City Composite Verification – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    اسم الملف: composite_verification.rs
    المسار:    src/core/composite_verification.rs

    دور الملف:
    - يجمع بين جميع محركات التحقق (الجغرافي، السلوكي، بصمة الجهاز، الشبكة...) في منطق مركب واحد.
    - يسمح بتطبيق سياسات المدن الذكية (مناطق، أوقات، أذونات...).
    - يوفر نقطة مركزية لأي تحقق أمني متقدم في المشروع.

    File name: composite_verification.rs
    Path:     src/core/composite_verification.rs

    File role:
    - Combines all verification engines (geo, behavior, device, network...) into a single composite logic.
    - Enables smart city policies (zones, times, permissions...).
    - Provides a central point for advanced security verification in the project.
******************************************************************************************/

use std::sync::Arc;
use chrono::Timelike;
use crate::core::geo_resolver::{GeoResolver, GeoLocation};
use crate::core::behavior_bio::{BehaviorEngine, BehaviorInput, AnalysisResult as BehaviorResult};
use crate::core::device_fp::{AdaptiveFingerprintEngine, AdaptiveFingerprint};
use crate::core::network_analyzer::{NetworkAnalyzer, NetworkAnalysisResult};

/// Arabic: هيكل التحقق المركب يجمع كل المحركات المتخصصة
/// English: CompositeVerifier struct aggregates all specialized engines
pub struct CompositeVerifier {
    pub geo: Arc<GeoResolver>,
    pub behavior: Arc<BehaviorEngine>,
    pub device_fp: Arc<AdaptiveFingerprintEngine>,
    pub network: Arc<NetworkAnalyzer>,
}

impl CompositeVerifier {
    /// دالة تحقق مركبة تدعم سياسات المدن الذكية
    /// Composite verification function supporting smart city policies
    pub async fn verify_smart_access(
        &self,
        geo_input: Option<(std::net::IpAddr, (f64, f64, u8, f64))>,
        behavior_input: BehaviorInput,
        device_info: (&str, &str, &str),
        allowed_zones: &[String],
        allowed_hours: Option<(u8, u8)>,
    ) -> Result<bool, String> {
        // 1. تحقق جغرافي
        let geo_location = match &geo_input {
            Some((ip, gps)) => {
                self.geo
                    .resolve(crate::core::geo_resolver::GeoResolver::ResolveParams {
                        ip: Some(*ip),
                        gps: Some(*gps),
                        sim_location: None,
                        satellite_location: None,
                        indoor_data: None,
                        ar_data: None,
                        mfa_token: None,
                    })
                    .await
                    .map_err(|e| format!("Geo error: {e}"))?
            },
            None => return Err("Geo input missing".to_string()),
        };
        if let Some(city) = &geo_location.city {
            if !allowed_zones.contains(city) {
                return Err("Access denied: zone not allowed".to_string());
            }
        } else {
            return Err("Geo location city missing".to_string());
        }
        if let Some((start, end)) = allowed_hours {
            let hour = chrono::Utc::now().hour() as u8;
            if hour < start || hour > end {
                return Err("Access denied: outside allowed hours".to_string());
            }
        }
        // 2. تحقق سلوكي
        let behavior_result = self.behavior.process(behavior_input).await.map_err(|e| format!("Behavior error: {e}"))?;
        if behavior_result.risk_level as u8 >= 3 { // Medium or higher
            return Err("Access denied: behavioral risk".to_string());
        }
        // 3. تحقق بصمة الجهاز
        let device_fp = self.device_fp.generate_fingerprint(device_info.0, device_info.1, device_info.2).await.map_err(|e| format!("Device FP error: {e}"))?;
        if device_fp.security_level < 5 {
            return Err("Access denied: device not trusted".to_string());
        }
        // 4. تحقق الشبكة
        // (مثال: يمكن إضافة شروط على نوع الاتصال أو درجة الأمان)
        // let network_result = self.network.analyze(...).await?;
        // if network_result.security_score < 0.5 { return Err("Access denied: network not trusted".to_string()); }
        // 5. إذا نجحت كل الشروط
        Ok(true)
    }
}