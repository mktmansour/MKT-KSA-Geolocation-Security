#[cfg(feature = "jws")]
use crate::security::jws::{key::Ed25519Keypair, sign_json, verify_json};
#[cfg(feature = "jws")]
use serde_json::Value;
#[cfg(feature = "jws")]
use std::path::Path;

#[cfg(feature = "jws")]
use super::errors::LedgerError;

/// Arabic: يبني حمولة مرساة يومية
/// English: Builds a daily anchor payload
#[cfg(feature = "jws")]
pub fn build_daily_anchor_payload(date_ymd: &str, ledger_rel: &str, last_index: u64, last_hash: &str) -> Value {
    serde_json::json!({
        "type": "ledger-anchor",
        "ver": 1,
        "date": date_ymd,          // YYYY-MM-DD
        "ledger": ledger_rel,      // relative path or logical name
        "last_index": last_index,
        "last_hash": last_hash,
    })
}

/// Arabic: يوقّع مرساة يومية ويرجع JWS
/// English: Signs a daily anchor and returns a JWS
#[cfg(feature = "jws")]
pub fn sign_daily_anchor(date_ymd: &str, ledger_rel: &str, last_index: u64, last_hash: &str, kp: &Ed25519Keypair) -> Result<String, LedgerError> {
    let payload = build_daily_anchor_payload(date_ymd, ledger_rel, last_index, last_hash);
    let jws = sign_json(&payload, kp)?;
    Ok(jws)
}

/// Arabic: يتحقق من JWS مرساة يومية ويعيد الحمولة
/// English: Verifies a daily anchor JWS and returns the payload
#[cfg(feature = "jws")]
pub fn verify_daily_anchor(jws: &str, keys: &[Ed25519Keypair]) -> Result<Value, LedgerError> {
    let payload = verify_json(jws, keys)?;
    Ok(payload)
}
