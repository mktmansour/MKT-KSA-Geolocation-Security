use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwsError {
    #[error("invalid-token-format")]
    InvalidFormat,
    #[error("invalid-base64")]
    InvalidB64(#[from] base64::DecodeError),
    #[error("invalid-json")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid-alg")]
    InvalidAlg,
    #[error("sig-verify-failed")]
    VerifyFailed,
    #[error("kid-not-found")]
    KidNotFound,
}
