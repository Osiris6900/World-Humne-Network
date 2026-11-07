use thiserror::Error;

#[derive(Error, Debug)]
pub enum WhnError {
    #[error("invalid object: {0}")]
    InvalidObject(&'static str),
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
    #[error("unsupported protocol spec: {0}")]
    UnsupportedSpec(String),
    #[error("expected card type {expected}, got {actual}")]
    WrongCardType {
        expected: &'static str,
        actual: String,
    },
    #[error("{0} must contain at least one tag, with no blank tags")]
    InvalidTags(&'static str),
    #[error("{0} must be at most 280 Unicode scalar values")]
    NoteTooLong(&'static str),
    #[error("expires_at must be greater than created_at")]
    InvalidValidityPeriod,
    #[error("card is expired")]
    Expired,
}
