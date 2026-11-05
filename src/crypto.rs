use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::WhnError;

/// A node's identity. The private key never leaves the device.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Restore an identity from its 32-byte secret.
    /// The caller is responsible for keeping the secret safe.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// Export the 32-byte secret (for encrypted local backup only).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Public key, base64url (no padding) — this is the node's public identity.
    pub fn public_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    /// Sign `msg`; returns base64url (no padding) signature.
    pub fn sign(&self, msg: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.sign(msg).to_bytes())
    }
}

/// Verify a base64url Ed25519 signature against a base64url public key.
pub fn verify_b64(pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> Result<(), WhnError> {
    let pk_raw = URL_SAFE_NO_PAD
        .decode(pubkey_b64)
        .map_err(|_| WhnError::InvalidEncoding)?;
    let pk_arr: [u8; 32] = pk_raw.try_into().map_err(|_| WhnError::InvalidPublicKey)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| WhnError::InvalidPublicKey)?;

    let sig_raw = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| WhnError::InvalidEncoding)?;
    let sig_arr: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| WhnError::InvalidEncoding)?;
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(msg, &sig).map_err(|_| WhnError::InvalidSignature)
}
