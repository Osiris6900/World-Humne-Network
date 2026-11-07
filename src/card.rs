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
#[serde(deny_unknown_fields)]
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
        let mut card = CapabilityCard {
            spec: SPEC_VERSION.into(),
            kind: "capability".into(),
            id: String::new(),
            pubkey: identity.public_key_b64(),
            offers: self.offers,
            region_hint: self.region_hint,
            capacity_note: self.capacity_note,
            contact_hint: self.contact_hint,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: self.pow_nonce,
            signature: String::new(),
        };
        card.validate()?;
        card.id = blake3::hash(&card.id_payload_bytes()?).to_hex().to_string();
        card.signature = identity.sign(&card.signing_payload_bytes()?);
        Ok(card)
    }
}

impl CapabilityCard {
    fn validate(&self) -> Result<(), WhnError> {
        validate_header(&self.spec, &self.kind, "capability")?;
        validate_fields(
            "offers",
            &self.offers,
            "capacity_note",
            self.capacity_note.as_deref(),
            self.created_at,
            self.expires_at,
        )?;
        Ok(())
    }

    /// Exact v0 JSON bytes hashed for the id; excludes `id` and `signature`.
    /// This serialization helper does not validate the card.
    pub fn id_payload_bytes(&self) -> Result<Vec<u8>, WhnError> {
        Ok(serde_json::to_vec(&CapabilityIdPayload {
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
        })?)
    }

    /// Exact v0 JSON bytes signed by the author; excludes only `signature`.
    /// This serialization helper does not validate the card.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>, WhnError> {
        Ok(serde_json::to_vec(&CapabilitySignPayload {
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
        })?)
    }

    /// Verify schema, id and signature independently of the current time.
    /// Use `verify_at` when accepting a live card from the network.
    pub fn verify(&self) -> Result<(), WhnError> {
        self.validate()?;
        let id = blake3::hash(&self.id_payload_bytes()?).to_hex().to_string();
        if id != self.id {
            return Err(WhnError::IdMismatch);
        }
        verify_b64(
            &self.pubkey,
            &self.signing_payload_bytes()?,
            &self.signature,
        )
    }

    /// Verify a live card, rejecting it at or after its expiry timestamp.
    /// `now` is caller-supplied Unix time in seconds.
    pub fn verify_at(&self, now: u64) -> Result<(), WhnError> {
        self.verify()?;
        if self.is_expired(now) {
            return Err(WhnError::Expired);
        }
        Ok(())
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

// ---------- Need Card ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
        let mut card = NeedCard {
            spec: SPEC_VERSION.into(),
            kind: "need".into(),
            id: String::new(),
            pubkey: identity.public_key_b64(),
            needs: self.needs,
            region_hint: self.region_hint,
            urgency: self.urgency,
            note: self.note,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pow_nonce: self.pow_nonce,
            signature: String::new(),
        };
        card.validate()?;
        card.id = blake3::hash(&card.id_payload_bytes()?).to_hex().to_string();
        card.signature = identity.sign(&card.signing_payload_bytes()?);
        Ok(card)
    }
}

impl NeedCard {
    fn validate(&self) -> Result<(), WhnError> {
        validate_header(&self.spec, &self.kind, "need")?;
        validate_fields(
            "needs",
            &self.needs,
            "note",
            self.note.as_deref(),
            self.created_at,
            self.expires_at,
        )?;
        if !(1..=5).contains(&self.urgency) {
            return Err(WhnError::BadUrgency(self.urgency));
        }
        Ok(())
    }

    /// Exact v0 JSON bytes hashed for the id; excludes `id` and `signature`.
    /// This serialization helper does not validate the card.
    pub fn id_payload_bytes(&self) -> Result<Vec<u8>, WhnError> {
        Ok(serde_json::to_vec(&NeedIdPayload {
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
        })?)
    }

    /// Exact v0 JSON bytes signed by the author; excludes only `signature`.
    /// This serialization helper does not validate the card.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>, WhnError> {
        Ok(serde_json::to_vec(&NeedSignPayload {
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
        })?)
    }

    /// Verify schema, id and signature independently of the current time.
    /// Use `verify_at` when accepting a live card from the network.
    pub fn verify(&self) -> Result<(), WhnError> {
        self.validate()?;
        let id = blake3::hash(&self.id_payload_bytes()?).to_hex().to_string();
        if id != self.id {
            return Err(WhnError::IdMismatch);
        }
        verify_b64(
            &self.pubkey,
            &self.signing_payload_bytes()?,
            &self.signature,
        )
    }

    /// Verify a live card, rejecting it at or after its expiry timestamp.
    /// `now` is caller-supplied Unix time in seconds.
    pub fn verify_at(&self, now: u64) -> Result<(), WhnError> {
        self.verify()?;
        if self.is_expired(now) {
            return Err(WhnError::Expired);
        }
        Ok(())
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

fn validate_header(spec: &str, kind: &str, expected: &'static str) -> Result<(), WhnError> {
    if spec != SPEC_VERSION {
        return Err(WhnError::UnsupportedSpec(spec.into()));
    }
    if kind != expected {
        return Err(WhnError::WrongCardType {
            expected,
            actual: kind.into(),
        });
    }
    Ok(())
}

fn validate_fields(
    tags_field: &'static str,
    tags: &[String],
    note_field: &'static str,
    note: Option<&str>,
    created_at: u64,
    expires_at: u64,
) -> Result<(), WhnError> {
    if tags.is_empty() || tags.iter().any(|tag| tag.trim().is_empty()) {
        return Err(WhnError::InvalidTags(tags_field));
    }
    if note.is_some_and(|text| text.chars().count() > 280) {
        return Err(WhnError::NoteTooLong(note_field));
    }
    if expires_at <= created_at {
        return Err(WhnError::InvalidValidityPeriod);
    }
    Ok(())
}
