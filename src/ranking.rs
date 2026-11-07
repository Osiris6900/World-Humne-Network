//! Local trust policy, bounded graph propagation and signed ranking hints.

use crate::{
    attestation::{validate_object_id, Attestation, Claim},
    card::{CapabilityCard, NeedCard},
    crypto::{validate_public_key_b64, verify_b64, Identity},
    error::WhnError,
    SPEC_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SCORE_SCALE: f64 = 1_000_000.0;
pub const MAX_SCORE_MICROS: i64 = 64_000_000;
pub const MAX_SUMMARY_ENTRIES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankingPolicy {
    pub half_life_secs: u64,
    pub max_evidence_age_secs: u64,
    pub max_depth: u8,
    pub hop_discount_millis: u16,
    pub summary_ttl_secs: u64,
    pub max_future_skew_secs: u64,
}
impl Default for RankingPolicy {
    fn default() -> Self {
        Self {
            half_life_secs: 7 * 86400,
            max_evidence_age_secs: 30 * 86400,
            max_depth: 4,
            hop_discount_millis: 500,
            summary_ttl_secs: 300,
            max_future_skew_secs: 300,
        }
    }
}
impl RankingPolicy {
    pub fn validate(&self) -> Result<(), WhnError> {
        if self.half_life_secs == 0
            || self.max_evidence_age_secs < self.half_life_secs
            || self.max_evidence_age_secs > 365 * 86400
            || !(1..=8).contains(&self.max_depth)
            || self.hop_discount_millis > 500
            || !(1..=3600).contains(&self.summary_ttl_secs)
            || self.max_future_skew_secs > 300
        {
            return Err(WhnError::InvalidObject("invalid ranking policy bounds"));
        }
        Ok(())
    }
    pub fn fingerprint(&self, anchors: &TrustAnchors) -> Result<String, WhnError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Policy<'a> {
            profile: &'static str,
            policy: &'a RankingPolicy,
            anchors: &'a BTreeMap<String, u16>,
        }
        Ok(blake3::hash(&serde_json::to_vec(&Policy {
            profile: "whn-rank-v0-1",
            policy: self,
            anchors: &anchors.0,
        })?)
        .to_hex()
        .to_string())
    }
    pub fn decay(&self, created_at: u64, now: u64) -> f64 {
        2.0_f64.powf(-(now.saturating_sub(created_at) as f64) / self.half_life_secs as f64)
    }
}

/// Local choices only; never accepted from gossip as authority.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors(BTreeMap<String, u16>);
impl TrustAnchors {
    pub fn set(&mut self, pubkey: &str, weight_millis: u16) -> Result<(), WhnError> {
        validate_public_key_b64(pubkey)?;
        if weight_millis > 1000 {
            return Err(WhnError::InvalidObject("anchor weight must be 0..=1000"));
        }
        if weight_millis == 0 {
            self.0.remove(pubkey);
        } else {
            if self.0.len() >= 16 && !self.0.contains_key(pubkey) {
                return Err(WhnError::InvalidObject("at most 16 local trust anchors"));
            }
            self.0.insert(pubkey.into(), weight_millis);
        }
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum TargetCard {
    Need(NeedCard),
    Capability(CapabilityCard),
}
impl TargetCard {
    pub fn id(&self) -> &str {
        match self {
            Self::Need(c) => &c.id,
            Self::Capability(c) => &c.id,
        }
    }
    pub fn pubkey(&self) -> &str {
        match self {
            Self::Need(c) => &c.pubkey,
            Self::Capability(c) => &c.pubkey,
        }
    }
    pub fn created_at(&self) -> u64 {
        match self {
            Self::Need(c) => c.created_at,
            Self::Capability(c) => c.created_at,
        }
    }
    pub fn verify(&self) -> Result<(), WhnError> {
        match self {
            Self::Need(c) => c.verify(),
            Self::Capability(c) => c.verify(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RankedNeed {
    pub card_id: String,
    pub local_score: f64,
    pub aggregate_score: f64,
    pub verified_weight: f64,
    pub fraudulent_weight: f64,
    pub fulfilled_weight: f64,
    pub quarantined: bool,
    pub summary_weight: f64,
}

pub struct RankingView {
    pub needs: Vec<RankedNeed>,
    pub reputation: BTreeMap<String, f64>,
}

pub fn rank_needs(
    needs: &[NeedCard],
    targets: &[TargetCard],
    attestations: &[Attestation],
    anchors: &TrustAnchors,
    policy: &RankingPolicy,
    now: u64,
) -> Result<RankingView, WhnError> {
    policy.validate()?;
    let authors: BTreeMap<_, _> = targets
        .iter()
        .filter(|c| c.verify().is_ok())
        .map(|c| (c.id().to_owned(), (c.pubkey().to_owned(), c.created_at())))
        .collect();
    let mut latest = BTreeMap::<(String, String), &Attestation>::new();
    for att in attestations {
        if att
            .verify_at(
                now,
                policy.max_evidence_age_secs,
                policy.max_future_skew_secs,
            )
            .is_err()
        {
            continue;
        }
        let Some((author, created_at)) = authors.get(&att.target_card) else {
            continue;
        };
        if author == &att.attestor_pubkey || att.created_at < *created_at {
            continue;
        }
        let key = (att.target_card.clone(), att.attestor_pubkey.clone());
        if let Some(previous) = latest.get(&key) {
            if !att.supersedes(previous)? {
                continue;
            }
        }
        latest.insert(key, att);
    }
    let mut edges = BTreeMap::<(String, String), f64>::new();
    for att in latest.values().filter(|a| a.claim != Claim::Fraudulent) {
        let author = &authors[&att.target_card].0;
        let strength = policy.decay(att.created_at, now);
        edges
            .entry((att.attestor_pubkey.clone(), author.clone()))
            .and_modify(|old| *old = old.max(strength))
            .or_insert(strength);
    }
    let reciprocal: BTreeSet<_> = edges
        .keys()
        .filter(|(a, b)| edges.contains_key(&(b.clone(), a.clone())))
        .cloned()
        .collect();
    edges.retain(|key, _| !reciprocal.contains(key));
    let mut reputation: BTreeMap<_, _> = anchors
        .0
        .iter()
        .map(|(k, v)| (k.clone(), *v as f64 / 1000.0))
        .collect();
    let mut frontier = reputation.clone();
    let mut visited: BTreeSet<_> = reputation.keys().cloned().collect();
    for _ in 0..policy.max_depth {
        let mut next = BTreeMap::<String, f64>::new();
        for (source, mass) in frontier {
            let outgoing: Vec<_> = edges
                .iter()
                .filter(|((a, b), _)| a == &source && !visited.contains(b))
                .collect();
            let total: f64 = outgoing.iter().map(|(_, strength)| **strength).sum();
            for ((_, target), strength) in outgoing {
                *next.entry(target.clone()).or_default() +=
                    mass * (policy.hop_discount_millis as f64 / 1000.0) * strength / total.max(1.0);
            }
        }
        if next.is_empty() {
            break;
        }
        for (peer, weight) in &mut next {
            *weight = weight.min(1.0);
            visited.insert(peer.clone());
            reputation.insert(peer.clone(), *weight);
        }
        frontier = next;
    }
    let mut ranked = Vec::new();
    let mut seen = BTreeSet::new();
    for need in needs {
        if need.verify_at(now).is_err() || !seen.insert(&need.id) {
            continue;
        }
        let (mut verified, mut fraudulent, mut fulfilled) = (0.0, 0.0, 0.0);
        for att in latest.values().filter(|a| a.target_card == need.id) {
            let weight = reputation.get(&att.attestor_pubkey).copied().unwrap_or(0.0)
                * policy.decay(att.created_at, now);
            match att.claim {
                Claim::VerifiedReal => verified += weight,
                Claim::Fraudulent => fraudulent += weight,
                Claim::Fulfilled => fulfilled += weight,
            }
        }
        let prior = 1.0 + (need.urgency as f64 - 1.0) * 0.25;
        let freshness = policy.decay(need.created_at, now);
        let quarantined = fraudulent > verified;
        let mut score =
            prior * freshness * (0.05 + verified - 2.0 * fraudulent) / (1.0 + 2.0 * fulfilled);
        if quarantined {
            score = score.min(-0.01);
        }
        score = score.clamp(-64.0, 64.0);
        ranked.push(RankedNeed {
            card_id: need.id.clone(),
            local_score: score,
            aggregate_score: score,
            verified_weight: verified,
            fraudulent_weight: fraudulent,
            fulfilled_weight: fulfilled,
            quarantined,
            summary_weight: 0.0,
        });
    }
    ranked.sort_by(|a, b| {
        b.local_score
            .total_cmp(&a.local_score)
            .then_with(|| a.card_id.cmp(&b.card_id))
    });
    Ok(RankingView {
        needs: ranked,
        reputation,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryEntry {
    pub card_id: String,
    pub score_micros: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankingSummary {
    pub spec: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub category: String,
    pub region: String,
    pub policy_id: String,
    pub publisher_pubkey: String,
    pub created_at: u64,
    pub entries: Vec<SummaryEntry>,
    pub signature: String,
}
#[derive(Serialize)]
struct SummaryPayload<'a> {
    spec: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    category: &'a str,
    region: &'a str,
    policy_id: &'a str,
    publisher_pubkey: &'a str,
    created_at: u64,
    entries: &'a [SummaryEntry],
}
impl RankingSummary {
    pub fn sign(
        category: &str,
        region: &str,
        policy_id: &str,
        entries: Vec<SummaryEntry>,
        created_at: u64,
        identity: &Identity,
    ) -> Result<Self, WhnError> {
        let mut summary = Self {
            spec: SPEC_VERSION.into(),
            kind: "ranking-summary".into(),
            category: category.into(),
            region: region.into(),
            policy_id: policy_id.into(),
            publisher_pubkey: identity.public_key_b64(),
            created_at,
            entries,
            signature: String::new(),
        };
        summary.validate()?;
        summary.signature = identity.sign(&summary.signing_payload_bytes()?);
        Ok(summary)
    }
    fn validate(&self) -> Result<(), WhnError> {
        if self.spec != SPEC_VERSION {
            return Err(WhnError::UnsupportedSpec(self.spec.clone()));
        }
        if self.kind != "ranking-summary" {
            return Err(WhnError::WrongCardType {
                expected: "ranking-summary",
                actual: self.kind.clone(),
            });
        }
        validate_object_id(&self.policy_id)?;
        if self.category.is_empty()
            || self.category.len() > 32
            || self.region.is_empty()
            || self.region.len() > 32
            || self.entries.len() > MAX_SUMMARY_ENTRIES
        {
            return Err(WhnError::InvalidObject("invalid summary scope or size"));
        }
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            validate_object_id(&entry.card_id)?;
            if !ids.insert(&entry.card_id)
                || !(-MAX_SCORE_MICROS..=MAX_SCORE_MICROS).contains(&entry.score_micros)
            {
                return Err(WhnError::InvalidObject(
                    "duplicate summary id or score outside bounds",
                ));
            }
        }
        Ok(())
    }
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>, WhnError> {
        Ok(serde_json::to_vec(&SummaryPayload {
            spec: &self.spec,
            kind: &self.kind,
            category: &self.category,
            region: &self.region,
            policy_id: &self.policy_id,
            publisher_pubkey: &self.publisher_pubkey,
            created_at: self.created_at,
            entries: &self.entries,
        })?)
    }
    pub fn verify_at(&self, now: u64, policy: &RankingPolicy) -> Result<(), WhnError> {
        policy.validate()?;
        self.validate()?;
        if self.created_at > now.saturating_add(policy.max_future_skew_secs)
            || now.saturating_sub(self.created_at) > policy.summary_ttl_secs
        {
            return Err(WhnError::InvalidObject("stale or future ranking summary"));
        }
        verify_b64(
            &self.publisher_pubkey,
            &self.signing_payload_bytes()?,
            &self.signature,
        )
    }
}

/// At most one compatible summary per publisher. Scores are bounded signed
/// hints, weighted by local reputation; local quarantine cannot be lifted.
pub fn merge_summaries(
    view: &mut RankingView,
    summaries: &[RankingSummary],
    own_pubkey: &str,
    policy_id: &str,
    policy: &RankingPolicy,
    now: u64,
) {
    let mut latest = BTreeMap::<&str, &RankingSummary>::new();
    for summary in summaries {
        if summary.publisher_pubkey == own_pubkey
            || summary.policy_id != policy_id
            || summary.verify_at(now, policy).is_err()
        {
            continue;
        }
        if let Some(old) = latest.get(summary.publisher_pubkey.as_str()) {
            // Signature provides a stable tie-break independent of arrival order.
            if (summary.created_at, &summary.signature) <= (old.created_at, &old.signature) {
                continue;
            }
        }
        latest.insert(&summary.publisher_pubkey, summary);
    }
    for need in &mut view.needs {
        let (mut total, mut weight) = (need.local_score, 1.0);
        for summary in latest.values() {
            let trust = view
                .reputation
                .get(&summary.publisher_pubkey)
                .copied()
                .unwrap_or(0.0);
            if let Some(entry) = summary.entries.iter().find(|e| e.card_id == need.card_id) {
                total += trust * entry.score_micros as f64 / SCORE_SCALE;
                weight += trust;
            }
        }
        need.summary_weight = weight - 1.0;
        need.aggregate_score = total / weight;
        if need.quarantined {
            need.aggregate_score = need.aggregate_score.min(need.local_score);
        }
    }
    view.needs.sort_by(|a, b| {
        b.aggregate_score
            .total_cmp(&a.aggregate_score)
            .then_with(|| a.card_id.cmp(&b.card_id))
    });
}
