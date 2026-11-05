use thiserror::Error;

#[derive(Error, Debug)]
pub enum WhnError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid base64 encoding in key or signature")]
    InvalidEncoding,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("card id mismatch — content was modified")]
    IdMismatch,
    #[error("urgency must be 1..=5, got {0}")]
    BadUrgency(u8),
    #[error("card is expired")]
    Expired,
}
