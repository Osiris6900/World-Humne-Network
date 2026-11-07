//! Canonical, signed claims about immutable cards. Claims are not adjudicated facts.

use crate::{
    crypto::{verify_b64, Identity},
    error::WhnError,
    SPEC_VERSION,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Claim {
    VerifiedReal,
    Fulfilled,
    Fraudulent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub spec: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub target_card: String,
    pub claim: Claim,
    pub attestor_pubkey: String,
    pub created_at: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct Payload<'a> {
    spec: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    target_card: &'a str,
    claim: Claim,
    attestor_pubkey: &'a str,
    created_at: u64,
}

pub fn validate_object_id(id: &str) -> Result<(), WhnError> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(WhnError::InvalidObject(
            "expected a 64-character lowercase hex id",
        ));
    }
    Ok(())
}

impl Attestation {
    pub fn sign(
        target_card: &str,
        claim: Claim,
        created_at: u64,
        identity: &Identity,
    ) -> Result<Self, WhnError> {
        validate_object_id(target_card)?;
        let mut att = Self {
            spec: SPEC_VERSION.into(),
            kind: "attestation".into(),
            target_card: target_card.into(),
            claim,
            attestor_pubkey: identity.public_key_b64(),
            created_at,
            signature: String::new(),
        };
        att.signature = identity.sign(&att.signing_payload_bytes()?);
        Ok(att)
    }
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>, WhnError> {
        Ok(serde_json::to_vec(&Payload {
            spec: &self.spec,
            kind: &self.kind,
            target_card: &self.target_card,
            claim: self.claim,
            attestor_pubkey: &self.attestor_pubkey,
            created_at: self.created_at,
        })?)
    }
    /// Content id for local deduplication; not an extra field on the wire.
    pub fn id(&self) -> Result<String, WhnError> {
        Ok(blake3::hash(&self.signing_payload_bytes()?)
            .to_hex()
            .to_string())
    }
    pub fn verify(&self) -> Result<(), WhnError> {
        if self.spec != SPEC_VERSION {
            return Err(WhnError::UnsupportedSpec(self.spec.clone()));
        }
        if self.kind != "attestation" {
            return Err(WhnError::WrongCardType {
                expected: "attestation",
                actual: self.kind.clone(),
            });
        }
        validate_object_id(&self.target_card)?;
        verify_b64(
            &self.attestor_pubkey,
            &self.signing_payload_bytes()?,
            &self.signature,
        )
    }
    pub fn verify_at(&self, now: u64, max_age: u64, future_skew: u64) -> Result<(), WhnError> {
        self.verify()?;
        if self.created_at > now.saturating_add(future_skew)
            || now.saturating_sub(self.created_at) > max_age
        {
            return Err(WhnError::InvalidObject(
                "attestation timestamp outside retention/skew policy",
            ));
        }
        Ok(())
    }
    /// A newer claim replaces the older claim from the same signer/target.
    /// Simultaneous conflicting claims resolve conservatively (fraud first).
    pub fn supersedes(&self, other: &Self) -> Result<bool, WhnError> {
        Ok(
            (self.created_at, self.claim, self.id()?)
                > (other.created_at, other.claim, other.id()?),
        )
    }
}
