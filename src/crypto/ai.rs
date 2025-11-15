/*! Arabic: واجهات ذكاء/إشارات مخاطر للتكيّف مع التشفير (Zero‑deps)
English: AI/Risk signal interfaces for adaptive crypto (zero‑deps) */

use crate::crypto::selector::{RiskContext, RiskScorer};

// Arabic: مزوّد إشارات المخاطر (قابل للتركيب من محركات السلوك/الشبكة/الجهاز)
// English: Risk signals provider (composable from behavior/network/device engines)
pub trait RiskSignalProvider {
    fn device_risk(&self) -> u8; // 0..100
    fn network_risk(&self) -> u8; // 0..100
    fn is_fips_env(&self) -> bool {
        false
    }
}

pub struct AdaptiveRiskScorer<'a, T: RiskSignalProvider> {
    pub provider: &'a T,
}

impl<'a, T: RiskSignalProvider> RiskScorer for AdaptiveRiskScorer<'a, T> {
    fn device_risk(&self) -> u8 {
        self.provider.device_risk()
    }
    fn network_risk(&self) -> u8 {
        self.provider.network_risk()
    }
    fn is_fips_env(&self) -> bool {
        self.provider.is_fips_env()
    }
}

pub fn to_context<T: RiskSignalProvider>(p: &T) -> RiskContext {
    RiskContext {
        is_fips_env: p.is_fips_env(),
        device_risk_score: p.device_risk(),
        network_risk_score: p.network_risk(),
    }
}
