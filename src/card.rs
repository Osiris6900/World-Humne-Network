//! Capability and Need cards — spec draft v0.1 (see `docs/protocol.md` §2).
//!
//! Canonical form: JSON with the exact field order declared in the payload
//! structs. Because we never serialize maps, this is deterministic across
//! implementations that follow the same order — which is what makes
//! cross-language test vectors possible.

use serde::{Deserialize, Serialize};

use crate::crypto::{verify_b64, Identity};
use crate::error::WhnError;
use crate::SPEC_VERSION;

// ---------- Capability Card ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityCard {
    pub spec: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub pubkey: String,
    pub offers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_hint: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub pow_nonce: String,
    pub signature: String,
}

#[derive(Serialize)]
struct CapabilityIdPayload<'a> {
    spec: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    pubkey: &'a str,
    offers: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    region_hint: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capacity_note: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_hint: &'a Option<String>,
    created_at: u64,
    expires_at: u64,
    pow_nonce: &'a str,
}

#[derive(Serialize)]
struct CapabilitySignPayload<'a> {
    spec: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    id: &'a str,
    pubkey: &'a str,
    offers: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    region_hint: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capacity_note: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_hint: &'a Option<String>,
    created_at: u64,
    expires_at: u64,
    pow_nonce: &'a str,
}

pub struct CapabilityDraft {
    pub offers: Vec<String>,
    pub region_hint: Option<String>,
    pub capacity_note: Option<String>,
    pub contact_hint: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub pow_nonce: String,
}

impl CapabilityDraft {
    pub fn new(offers: Vec<String>, created_at: u64, expires_at: u64) -> Self {
        Self {
            offers,
            region_hint: None,
            capacity_note: None,
            contact_hint: None,
            created_at,
            expires_at,
            pow_nonce: String::new(),
        }
    }

    pub fn sign(self, identity: &Identity) -> Result<CapabilityCard, WhnError> {
        let pubkey = identity.public_key_b64();
        let id_payload = CapabilityIdPayload {
            spec: SPEC_VERSION,
            kind: "capability",
            pubkey: &pubkey,
            offers: &self.offers,
            region_hint: &self.region_hint,
            capacity_note: &self.capacity_note,
            contact_hint: &self.contact_hint,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        let id = blake3::hash(&serde_json::to_vec(&id_payload)?)
            .to_hex()
            .to_string();

        let sign_payload = CapabilitySignPayload {
            spec: SPEC_VERSION,
            kind: "capability",
            id: &id,
            pubkey: &pubkey,
            offers: &self.offers,
            region_hint: &self.region_hint,
            capacity_note: &self.capacity_note,
            contact_hint: &self.contact_hint,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        let signature = identity.sign(&serde_json::to_vec(&sign_payload)?);

        Ok(CapabilityCard {
            spec: SPEC_VERSION.into(),
            kind: "capability".into(),
            id,
            pubkey,
            offers: self.offers,
            region_hint: self.region_hint,
            capacity_note: self.capacity_note,
            contact_hint: self.contact_hint,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: self.pow_nonce,
            signature,
        })
    }
}

impl CapabilityCard {
    pub fn verify(&self) -> Result<(), WhnError> {
        let id_payload = CapabilityIdPayload {
            spec: &self.spec,
            kind: &self.kind,
            pubkey: &self.pubkey,
            offers: &self.offers,
            region_hint: &self.region_hint,
            capacity_note: &self.capacity_note,
            contact_hint: &self.contact_hint,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        let id = blake3::hash(&serde_json::to_vec(&id_payload)?)
            .to_hex()
            .to_string();
        if id != self.id {
            return Err(WhnError::IdMismatch);
        }

        let sign_payload = CapabilitySignPayload {
            spec: &self.spec,
            kind: &self.kind,
            id: &self.id,
            pubkey: &self.pubkey,
            offers: &self.offers,
            region_hint: &self.region_hint,
            capacity_note: &self.capacity_note,
            contact_hint: &self.contact_hint,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        verify_b64(
            &self.pubkey,
            &serde_json::to_vec(&sign_payload)?,
            &self.signature,
        )
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

// ---------- Need Card ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeedCard {
    pub spec: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub pubkey: String,
    pub needs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region_hint: Option<String>,
    pub urgency: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub pow_nonce: String,
    pub signature: String,
}

#[derive(Serialize)]
struct NeedIdPayload<'a> {
    spec: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    pubkey: &'a str,
    needs: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    region_hint: &'a Option<String>,
    urgency: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: &'a Option<String>,
    created_at: u64,
    expires_at: u64,
    pow_nonce: &'a str,
}

#[derive(Serialize)]
struct NeedSignPayload<'a> {
    spec: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    id: &'a str,
    pubkey: &'a str,
    needs: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    region_hint: &'a Option<String>,
    urgency: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: &'a Option<String>,
    created_at: u64,
    expires_at: u64,
    pow_nonce: &'a str,
}

pub struct NeedDraft {
    pub needs: Vec<String>,
    pub region_hint: Option<String>,
    pub urgency: u8,
    pub note: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub pow_nonce: String,
}

impl NeedDraft {
    pub fn new(needs: Vec<String>, urgency: u8, created_at: u64, expires_at: u64) -> Self {
        Self {
            needs,
            region_hint: None,
            urgency,
            note: None,
            created_at,
            expires_at,
            pow_nonce: String::new(),
        }
    }

    pub fn sign(self, identity: &Identity) -> Result<NeedCard, WhnError> {
        if !(1..=5).contains(&self.urgency) {
            return Err(WhnError::BadUrgency(self.urgency));
        }
        let pubkey = identity.public_key_b64();
        let id_payload = NeedIdPayload {
            spec: SPEC_VERSION,
            kind: "need",
            pubkey: &pubkey,
            needs: &self.needs,
            region_hint: &self.region_hint,
            urgency: self.urgency,
            note: &self.note,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        let id = blake3::hash(&serde_json::to_vec(&id_payload)?)
            .to_hex()
            .to_string();

        let sign_payload = NeedSignPayload {
            spec: SPEC_VERSION,
            kind: "need",
            id: &id,
            pubkey: &pubkey,
            needs: &self.needs,
            region_hint: &self.region_hint,
            urgency: self.urgency,
            note: &self.note,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        let signature = identity.sign(&serde_json::to_vec(&sign_payload)?);

        Ok(NeedCard {
            spec: SPEC_VERSION.into(),
            kind: "need".into(),
            id,
            pubkey,
            needs: self.needs,
            region_hint: self.region_hint,
            urgency: self.urgency,
            note: self.note,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: self.pow_nonce,
            signature,
        })
    }
}

impl NeedCard {
    pub fn verify(&self) -> Result<(), WhnError> {
        let id_payload = NeedIdPayload {
            spec: &self.spec,
            kind: &self.kind,
            pubkey: &self.pubkey,
            needs: &self.needs,
            region_hint: &self.region_hint,
            urgency: self.urgency,
            note: &self.note,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        let id = blake3::hash(&serde_json::to_vec(&id_payload)?)
            .to_hex()
            .to_string();
        if id != self.id {
            return Err(WhnError::IdMismatch);
        }

        let sign_payload = NeedSignPayload {
            spec: &self.spec,
            kind: &self.kind,
            id: &self.id,
            pubkey: &self.pubkey,
            needs: &self.needs,
            region_hint: &self.region_hint,
            urgency: self.urgency,
            note: &self.note,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: &self.pow_nonce,
        };
        verify_b64(
            &self.pubkey,
            &serde_json::to_vec(&sign_payload)?,
            &self.signature,
        )
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}
