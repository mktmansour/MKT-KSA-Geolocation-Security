/*!
Arabic: وحدة JWS اختيارية لتوقيع/تحقق JSON باستخدام Ed25519 بدون OpenSSL.
English: Optional JWS module to sign/verify JSON using Ed25519 (no OpenSSL).

المبادئ | Principles:
- لا تعرّض أنواع التبعيات للخارج؛ استخدم واجهات وأنواع بسيطة.
- مفاتيح خاصة تُحقن عبر `security::secret::SecureBytes` بطول 32 بايت.
- تطبيع JSON مبسّط (JCS-like) لضمان بصمة ثابتة عبر المنصات.

الملفات | Files:
- `key.rs`: إدارة مفاتيح Ed25519 عبر `SecureBytes`.
- `canonicalize.rs`: تطبيع JSON مضغوط وترتيب مفاتيح.
- `errors.rs`: أخطاء موحّدة.
- هذه الوحدة مفعّلة عبر ميزة `jws` في `Cargo.toml`.
*/

pub mod canonicalize;
pub mod errors;
pub mod key;

use crate::security::jws::canonicalize::canonicalize_json_compact;
use crate::security::jws::errors::JwsError;
use crate::security::jws::key::Ed25519Keypair;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwsHeader<'a> {
    alg: &'a str, // "EdDSA"
    typ: &'a str, // "JWT"
    kid: &'a str, // key id
    iat: Option<i64>,
}

fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn sign_json(value: &Value, kp: &Ed25519Keypair) -> Result<String, JwsError> {
    let header = JwsHeader {
        alg: "EdDSA",
        typ: "JWT",
        kid: &kp.kid,
        iat: Some(Utc::now().timestamp()),
    };
    let header_bytes = serde_json::to_vec(&header)?;
    let payload_bytes = canonicalize_json_compact(value)?;
    let header_b64 = b64u(&header_bytes);
    let payload_b64 = b64u(&payload_bytes);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let sk = SigningKey::from_bytes(kp.secret_bytes());
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let sig_b64 = b64u(&sig.to_bytes());
    Ok(format!("{}.{}", signing_input, sig_b64))
}

#[derive(Debug, Deserialize)]
struct JwsHeaderOwned {
    alg: String,
    #[allow(dead_code)]
    typ: Option<String>,
    kid: String,
    #[allow(dead_code)]
    iat: Option<i64>,
}

fn b64d(input: &str) -> Result<Vec<u8>, JwsError> {
    Ok(URL_SAFE_NO_PAD.decode(input.as_bytes())?)
}

/// Arabic: يتحقق من توقيع JWS ويعيد الحمولة كـ JSON عند النجاح
/// English: Verifies a JWS token and returns the JSON payload on success
pub fn verify_json(token: &str, keys: &[Ed25519Keypair]) -> Result<Value, JwsError> {
    let mut parts = token.split('.');
    let (h_b64, p_b64, s_b64) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
        _ => return Err(JwsError::InvalidFormat),
    };

    let header_bytes = b64d(h_b64)?;
    let payload_bytes = b64d(p_b64)?;
    let sig_bytes = b64d(s_b64)?;

    let header: JwsHeaderOwned = serde_json::from_slice(&header_bytes)?;
    if header.alg != "EdDSA" {
        return Err(JwsError::InvalidAlg);
    }

    let kp = keys
        .iter()
        .find(|k| k.kid == header.kid)
        .ok_or(JwsError::KidNotFound)?;
    let signing_input = format!("{}.{}", h_b64, p_b64);

    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| JwsError::InvalidFormat)?;
    let sig = Signature::from_bytes(&sig_arr);

    let vk = kp.verifying_key();
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| JwsError::VerifyFailed)?;

    let payload: Value = serde_json::from_slice(&payload_bytes)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::secret::SecureBytes;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Fixed secret for determinism in tests
        let secret: [u8; 32] = [1u8; 32];
        let kp =
            Ed25519Keypair::from_secure_bytes("test", &SecureBytes::new(secret.to_vec())).unwrap();

        let payload = serde_json::json!({
            "sub": "user-123",
            "roles": ["admin", "viewer"],
            "exp": 1_700_000_000,
        });

        let token = sign_json(&payload, &kp).expect("sign");
        let out = verify_json(&token, &[kp]).expect("verify");
        assert_eq!(out, payload);
    }

    #[test]
    fn test_verify_kid_not_found() {
        let secret: [u8; 32] = [2u8; 32];
        let kp =
            Ed25519Keypair::from_secure_bytes("other", &SecureBytes::new(secret.to_vec())).unwrap();
        let payload = serde_json::json!({"ok": true});
        let token = sign_json(&payload, &kp).unwrap();
        let err = verify_json(&token, &[]).unwrap_err();
        matches!(err, JwsError::KidNotFound);
    }

    #[test]
    fn test_verify_fail_on_tamper() {
        let secret: [u8; 32] = [3u8; 32];
        let kp =
            Ed25519Keypair::from_secure_bytes("kid", &SecureBytes::new(secret.to_vec())).unwrap();
        let payload = serde_json::json!({"n": 1});
        let mut token = sign_json(&payload, &kp).unwrap();
        // Tamper one character in the signature part (last char)
        if let Some(last) = token.pop() {
            let _ = last;
        }
        token.push('A');
        let err = verify_json(&token, &[kp]).unwrap_err();
        matches!(
            err,
            JwsError::InvalidB64 | JwsError::InvalidFormat | JwsError::VerifyFailed
        );
    }
}
