/*! Arabic: مُحدد تكيفي لاختيار الخوارزمية بناءً على السياسة والسياق
English: Adaptive selector to choose algorithms based on policy and context */

use crate::crypto::policy::CryptoPolicy;

// Arabic: واجهة حساب مخاطر قابلة للحقن (Zero‑deps)
// English: Pluggable risk scoring interface (zero‑deps)
pub trait RiskScorer {
    fn device_risk(&self) -> u8; // 0..100
    fn network_risk(&self) -> u8; // 0..100
    fn is_fips_env(&self) -> bool;
}

#[derive(Debug, Clone, Copy)]
pub enum AeadChoice {
    XChaCha20Poly1305,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy)]
pub enum SignChoice {
    Ed25519,
    EcdsaP256,
}

#[derive(Debug, Clone, Copy)]
pub struct CryptoChoices {
    pub aead: AeadChoice,
    pub sign: SignChoice,
}

#[derive(Debug, Clone)]
pub struct RiskContext {
    pub is_fips_env: bool,
    pub device_risk_score: u8,  // 0..100
    pub network_risk_score: u8, // 0..100
}

pub fn choose(policy: &CryptoPolicy, ctx: &RiskContext) -> CryptoChoices {
    let aead = if policy.require_fips || ctx.is_fips_env {
        AeadChoice::Aes256Gcm
    } else if policy.allow_xchacha20_poly1305 {
        AeadChoice::XChaCha20Poly1305
    } else {
        AeadChoice::Aes256Gcm
    };

    let sign = if policy.require_fips {
        SignChoice::EcdsaP256
    } else {
        SignChoice::Ed25519
    };

    CryptoChoices { aead, sign }
}

// Arabic: اختيار مبسّط انطلاقًا من RiskScorer لدمج الذكاء التكيّفي
// English: Convenience selection from RiskScorer for adaptive AI hook
pub fn choose_with_scorer(policy: &CryptoPolicy, scorer: &dyn RiskScorer) -> CryptoChoices {
    let ctx = RiskContext {
        is_fips_env: scorer.is_fips_env(),
        device_risk_score: scorer.device_risk(),
        network_risk_score: scorer.network_risk(),
    };
    choose(policy, &ctx)
}
