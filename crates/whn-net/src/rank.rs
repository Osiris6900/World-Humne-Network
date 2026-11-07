//! Bounded evidence/proof storage and scope-checked ranking gossip.

use crate::{
    gossip::{Announcement, GossipSnapshot, TopicKind, TopicSpec},
    record::MAX_RECORD_BYTES,
    Error,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use whn_core::{
    attestation::Attestation,
    crypto::Identity,
    ranking::{
        merge_summaries, rank_needs, RankedNeed, RankingPolicy, RankingSummary, SummaryEntry,
        TargetCard, TrustAnchors, MAX_SUMMARY_ENTRIES, SCORE_SCALE,
    },
};

type EvidenceKey = (String, String, String, String);
type ProofKey = (String, String, String);
#[derive(Clone)]
struct StoredAttestation {
    attestation: Attestation,
    local: bool,
}

#[derive(Clone)]
pub(crate) struct RankingState {
    pub policy: RankingPolicy,
    anchors: TrustAnchors,
    evidence: BTreeMap<EvidenceKey, StoredAttestation>,
    proofs: BTreeMap<ProofKey, Announcement>,
    summaries: BTreeMap<(String, String, String), RankingSummary>,
}

fn target(card: &Announcement) -> TargetCard {
    match card {
        Announcement::Need(c) => TargetCard::Need(c.clone()),
        Announcement::Capability(c) => TargetCard::Capability(c.clone()),
    }
}
fn snapshot_targets(snapshot: &GossipSnapshot) -> impl Iterator<Item = Announcement> + '_ {
    snapshot
        .needs
        .iter()
        .cloned()
        .map(Announcement::Need)
        .chain(
            snapshot
                .capabilities
                .iter()
                .cloned()
                .map(Announcement::Capability),
        )
}

impl RankingState {
    pub(crate) fn weight_candidates(
        &mut self,
        category: &str,
        snapshot: &GossipSnapshot,
        candidates: &mut Vec<whn_core::matcher::MatchCandidate>,
        now: u64,
    ) -> Result<(), Error> {
        self.prune(now);
        let mut weights = BTreeMap::new();
        for card in &snapshot.capabilities {
            let region = card.region_hint.as_deref().unwrap_or("global");
            if weights.contains_key(region) {
                continue;
            }
            let mut targets: Vec<_> = snapshot_targets(snapshot)
                .filter(|c| c.region() == region)
                .map(|c| target(&c))
                .collect();
            targets.extend(
                self.proofs
                    .iter()
                    .filter(|((c, r, _), _)| c == category && r == region)
                    .map(|(_, c)| target(c)),
            );
            let evidence: Vec<_> = self
                .evidence
                .iter()
                .filter(|((c, r, _, _), _)| c == category && r == region)
                .map(|(_, a)| a.attestation.clone())
                .collect();
            weights.insert(
                region.to_owned(),
                rank_needs(&[], &targets, &evidence, &self.anchors, &self.policy, now)?.reputation,
            );
        }
        candidates.retain_mut(|candidate| {
            let Some(card) = snapshot
                .capabilities
                .iter()
                .find(|c| c.id == candidate.capability_id)
            else {
                return false;
            };
            let region = card.region_hint.as_deref().unwrap_or("global");
            let reputation = &weights[region];
            let (mut fraud, mut verified) = (0.0, 0.0);
            for ((c, r, id, _), stored) in &self.evidence {
                if c != category || r != region || id != &card.id {
                    continue;
                }
                let att = &stored.attestation;
                if att.created_at > now.saturating_add(self.policy.max_future_skew_secs) {
                    continue;
                }
                let weight = reputation.get(&att.attestor_pubkey).copied().unwrap_or(0.0)
                    * self.policy.decay(att.created_at, now);
                match att.claim {
                    whn_core::attestation::Claim::Fraudulent => fraud += weight,
                    _ => verified += weight,
                }
            }
            if fraud > verified {
                return false;
            }
            let author_weight = reputation.get(&card.pubkey).copied().unwrap_or(0.0);
            candidate.reputation_weight = 0.1 + 0.9 * author_weight;
            candidate.score *= candidate.reputation_weight;
            true
        });
        candidates.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.capability_id.cmp(&b.capability_id))
        });
        candidates.truncate(100);
        Ok(())
    }
    pub(crate) fn new(policy: RankingPolicy) -> Result<Self, Error> {
        policy.validate()?;
        Ok(Self {
            policy,
            anchors: TrustAnchors::default(),
            evidence: BTreeMap::new(),
            proofs: BTreeMap::new(),
            summaries: BTreeMap::new(),
        })
    }
    pub(crate) fn counts(&self) -> (usize, usize, usize) {
        (
            self.evidence.len(),
            self.summaries.len(),
            self.anchors.len(),
        )
    }
    pub(crate) fn trust(&mut self, pubkey: &str, weight_millis: u16) -> Result<(), Error> {
        self.anchors.set(pubkey, weight_millis)?;
        // A policy change cannot keep old-policy ranking votes alive.
        self.summaries.clear();
        Ok(())
    }
    pub(crate) fn prune(&mut self, now: u64) {
        self.evidence.retain(|_, att| {
            now.saturating_sub(att.attestation.created_at) <= self.policy.max_evidence_age_secs
        });
        let used: BTreeSet<_> = self
            .evidence
            .keys()
            .map(|(c, r, id, _)| (c.as_str(), r.as_str(), id.as_str()))
            .collect();
        self.proofs.retain(|(category, region, id), _| {
            used.contains(&(category.as_str(), region.as_str(), id.as_str()))
        });
        self.summaries.retain(|_, summary| {
            now.saturating_sub(summary.created_at) <= self.policy.summary_ttl_secs
        });
    }
    pub(crate) fn unsubscribe(&mut self, spec: &TopicSpec) {
        if spec.kind != TopicKind::Ranking {
            return;
        }
        self.evidence.retain(|(c, r, _, _), stored| {
            stored.local || c != &spec.category || r != &spec.region
        });
        self.summaries
            .retain(|(c, r, _), _| c != &spec.category || r != &spec.region);
    }
    fn proof(
        &self,
        category: &str,
        target_id: &str,
        snapshot: &GossipSnapshot,
    ) -> Option<Announcement> {
        snapshot_targets(snapshot)
            .find(|c| c.id() == target_id)
            .or_else(|| {
                self.proofs
                    .iter()
                    .find(|((c, _, id), _)| c == category && id == target_id)
                    .map(|(_, card)| card.clone())
            })
    }
    pub(crate) fn attestation_topic(
        &self,
        category: &str,
        att: &Attestation,
        snapshot: &GossipSnapshot,
    ) -> Result<TopicSpec, Error> {
        let proof = self
            .proof(category, &att.target_card, snapshot)
            .ok_or(Error::NotFound)?;
        TopicSpec::new(TopicKind::Ranking, category, proof.region())
    }
    pub(crate) fn insert_attestation(
        &mut self,
        spec: &TopicSpec,
        att: Attestation,
        snapshot: &GossipSnapshot,
        local: bool,
        now: u64,
    ) -> Result<(), Error> {
        spec.name()?;
        if spec.kind != TopicKind::Ranking {
            return Err(Error::InvalidTopic);
        }
        att.verify_at(
            now,
            self.policy.max_evidence_age_secs,
            self.policy.max_future_skew_secs,
        )?;
        let proof = self
            .proof(&spec.category, &att.target_card, snapshot)
            .ok_or(Error::NotFound)?;
        if proof.region() != spec.region {
            return Err(Error::InvalidAnnouncement(
                "attestation target belongs to another region",
            ));
        }
        target(&proof).verify()?;
        if target(&proof).pubkey() == att.attestor_pubkey
            || att.created_at < target(&proof).created_at()
        {
            return Err(Error::InvalidAnnouncement(
                "self-attestation or claim predating target card",
            ));
        }
        self.prune(now);
        let key = (
            spec.category.clone(),
            spec.region.clone(),
            att.target_card.clone(),
            att.attestor_pubkey.clone(),
        );
        let proof_key = (
            spec.category.clone(),
            spec.region.clone(),
            att.target_card.clone(),
        );
        if let Some(old) = self.evidence.get_mut(&key) {
            old.local |= local;
            if !att.supersedes(&old.attestation)? {
                return Ok(());
            }
        } else if self.evidence.len() >= 1024 {
            return Err(Error::CacheFull);
        }
        if self.proofs.len() >= 256 && !self.proofs.contains_key(&proof_key) {
            return Err(Error::CacheFull);
        }
        let local = local || self.evidence.get(&key).is_some_and(|old| old.local);
        self.evidence.insert(
            key,
            StoredAttestation {
                attestation: att,
                local,
            },
        );
        self.proofs.insert(proof_key, proof);
        Ok(())
    }
    pub(crate) fn ingest(
        &mut self,
        spec: &TopicSpec,
        bytes: &[u8],
        snapshot: &GossipSnapshot,
        now: u64,
    ) -> Result<(), Error> {
        spec.name()?;
        if spec.kind != TopicKind::Ranking {
            return Err(Error::InvalidTopic);
        }
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::RecordTooLarge);
        }
        #[derive(Deserialize)]
        struct Header {
            #[serde(rename = "type")]
            kind: String,
        }
        let header: Header = serde_json::from_slice(bytes)?;
        match header.kind.as_str() {
            "attestation" => {
                self.insert_attestation(spec, serde_json::from_slice(bytes)?, snapshot, false, now)
            }
            "ranking-summary" => {
                let summary: RankingSummary = serde_json::from_slice(bytes)?;
                self.insert_summary(spec, summary, snapshot, now)
            }
            _ => Err(Error::InvalidAnnouncement("unsupported rank message type")),
        }
    }
    fn insert_summary(
        &mut self,
        spec: &TopicSpec,
        summary: RankingSummary,
        snapshot: &GossipSnapshot,
        now: u64,
    ) -> Result<(), Error> {
        summary.verify_at(now, &self.policy)?;
        if summary.category != spec.category
            || summary.region != spec.region
            || spec.kind != TopicKind::Ranking
        {
            return Err(Error::InvalidAnnouncement(
                "summary scope does not match topic",
            ));
        }
        for entry in &summary.entries {
            if let Some(known) = self.proof(&spec.category, &entry.card_id, snapshot) {
                if known.region() != spec.region || known.kind() != TopicKind::Need {
                    return Err(Error::InvalidAnnouncement(
                        "summary entry has wrong scope or kind",
                    ));
                }
            }
        }
        // Policy is local. Forward a valid foreign-policy hint without storing
        // it as a vote, so mixed-policy relays do not partition the topic.
        if summary.policy_id != self.policy.fingerprint(&self.anchors)? {
            return Ok(());
        }
        self.prune(now);
        let key = (
            summary.category.clone(),
            summary.region.clone(),
            summary.publisher_pubkey.clone(),
        );
        if let Some(old) = self.summaries.get(&key) {
            if (summary.created_at, &summary.signature) <= (old.created_at, &old.signature) {
                return Ok(());
            }
        } else if self.summaries.len() >= 128 {
            return Err(Error::CacheFull);
        }
        self.summaries.insert(key, summary);
        Ok(())
    }
    pub(crate) fn ranks(
        &mut self,
        category: &str,
        region: &str,
        snapshot: &GossipSnapshot,
        own_pubkey: &str,
        now: u64,
    ) -> Result<Vec<RankedNeed>, Error> {
        TopicSpec::new(TopicKind::Ranking, category, region)?;
        self.prune(now);
        let mut targets: Vec<_> = snapshot_targets(snapshot)
            .filter(|c| c.region() == region)
            .map(|c| target(&c))
            .collect();
        targets.extend(
            self.proofs
                .iter()
                .filter(|((c, r, _), _)| c == category && r == region)
                .map(|(_, c)| target(c)),
        );
        let needs: Vec<_> = snapshot
            .needs
            .iter()
            .filter(|c| c.region_hint.as_deref().unwrap_or("global") == region)
            .cloned()
            .collect();
        let attestations: Vec<_> = self
            .evidence
            .iter()
            .filter(|((c, r, _, _), _)| c == category && r == region)
            .map(|(_, att)| att.attestation.clone())
            .collect();
        let mut view = rank_needs(
            &needs,
            &targets,
            &attestations,
            &self.anchors,
            &self.policy,
            now,
        )?;
        let summaries: Vec<_> = self
            .summaries
            .iter()
            .filter(|((c, r, _), _)| c == category && r == region)
            .map(|(_, s)| s.clone())
            .collect();
        merge_summaries(
            &mut view,
            &summaries,
            own_pubkey,
            &self.policy.fingerprint(&self.anchors)?,
            &self.policy,
            now,
        );
        Ok(view.needs)
    }
    pub(crate) fn summary(
        &mut self,
        category: &str,
        region: &str,
        snapshot: &GossipSnapshot,
        identity: &Identity,
        now: u64,
    ) -> Result<RankingSummary, Error> {
        let mut ranks = self.ranks(category, region, snapshot, &identity.public_key_b64(), now)?;
        // Never gossip aggregated hints back as fresh independent evidence.
        ranks.sort_by(|a, b| {
            b.local_score
                .total_cmp(&a.local_score)
                .then_with(|| a.card_id.cmp(&b.card_id))
        });
        let entries = ranks
            .into_iter()
            .take(MAX_SUMMARY_ENTRIES)
            .map(|r| SummaryEntry {
                card_id: r.card_id,
                score_micros: (r.local_score * SCORE_SCALE).round() as i64,
            })
            .collect();
        Ok(RankingSummary::sign(
            category,
            region,
            &self.policy.fingerprint(&self.anchors)?,
            entries,
            now,
            identity,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whn_core::{attestation::Claim, card::NeedDraft};
    const NOW: u64 = 1_800_000_000;
    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32])
    }
    fn need(author: u8, created: u64, expires: u64) -> whn_core::card::NeedCard {
        NeedDraft::new(vec!["water".into()], 4, created, expires)
            .sign(&identity(author))
            .unwrap()
    }
    fn topic() -> TopicSpec {
        TopicSpec::new(TopicKind::Ranking, "water", "global").unwrap()
    }

    #[test]
    fn historical_signed_targets_keep_earned_reputation_after_card_expiry() {
        let mut state = RankingState::new(RankingPolicy::default()).unwrap();
        state.trust(&identity(1).public_key_b64(), 1000).unwrap();
        let old = need(2, NOW - 1, NOW + 1);
        let snapshot = GossipSnapshot {
            needs: vec![old.clone()],
            capabilities: vec![],
        };
        state
            .insert_attestation(
                &topic(),
                Attestation::sign(&old.id, Claim::Fulfilled, NOW, &identity(1)).unwrap(),
                &snapshot,
                true,
                NOW,
            )
            .unwrap();
        state.prune(NOW + 2);
        assert_eq!(state.proofs.len(), 1);
        let new = need(3, NOW + 2, NOW + 60);
        let snapshot = GossipSnapshot {
            needs: vec![new.clone()],
            capabilities: vec![],
        };
        state
            .insert_attestation(
                &topic(),
                Attestation::sign(&new.id, Claim::VerifiedReal, NOW + 2, &identity(2)).unwrap(),
                &snapshot,
                false,
                NOW + 2,
            )
            .unwrap();
        let ranks = state
            .ranks("water", "global", &snapshot, "other", NOW + 2)
            .unwrap();
        assert!(ranks[0].verified_weight > 0.49 && ranks[0].verified_weight <= 0.5);
    }

    #[test]
    fn replayed_claims_do_not_replace_newer_claims_or_grow_the_cache() {
        let mut state = RankingState::new(RankingPolicy::default()).unwrap();
        let card = need(2, NOW - 10, NOW + 60);
        let snapshot = GossipSnapshot {
            needs: vec![card.clone()],
            capabilities: vec![],
        };
        let newer = Attestation::sign(&card.id, Claim::Fraudulent, NOW, &identity(1)).unwrap();
        let older =
            Attestation::sign(&card.id, Claim::VerifiedReal, NOW - 1, &identity(1)).unwrap();
        state
            .insert_attestation(&topic(), newer, &snapshot, true, NOW)
            .unwrap();
        for _ in 0..3 {
            state
                .insert_attestation(&topic(), older.clone(), &snapshot, false, NOW)
                .unwrap();
        }
        assert_eq!(state.evidence.len(), 1);
        assert_eq!(
            state.evidence.values().next().unwrap().attestation.claim,
            Claim::Fraudulent
        );
        state.unsubscribe(&topic());
        assert_eq!(state.evidence.len(), 1); // explicit local evidence remains
    }

    #[test]
    fn foreign_policy_summaries_are_forwardable_but_not_votes_and_stale_votes_expire() {
        let mut state = RankingState::new(RankingPolicy::default()).unwrap();
        let snapshot = GossipSnapshot::default();
        let make = |policy: &str| {
            RankingSummary::sign("water", "global", policy, vec![], NOW, &identity(1)).unwrap()
        };
        let foreign = make(&"a".repeat(64));
        state
            .ingest(
                &topic(),
                &serde_json::to_vec(&foreign).unwrap(),
                &snapshot,
                NOW,
            )
            .unwrap();
        assert_eq!(state.summaries.len(), 0);
        let compatible = make(&state.policy.fingerprint(&state.anchors).unwrap());
        state
            .ingest(
                &topic(),
                &serde_json::to_vec(&compatible).unwrap(),
                &snapshot,
                NOW,
            )
            .unwrap();
        assert_eq!(state.summaries.len(), 1);
        state.prune(NOW + state.policy.summary_ttl_secs + 1);
        assert_eq!(state.summaries.len(), 0);
    }

    #[test]
    fn evidence_must_resolve_to_a_known_target_in_the_topic_region() {
        let mut state = RankingState::new(RankingPolicy::default()).unwrap();
        let card = need(2, NOW - 1, NOW + 60);
        let att = Attestation::sign(&card.id, Claim::VerifiedReal, NOW, &identity(1)).unwrap();
        assert!(matches!(
            state.insert_attestation(
                &topic(),
                att.clone(),
                &GossipSnapshot::default(),
                false,
                NOW
            ),
            Err(Error::NotFound)
        ));
        let snapshot = GossipSnapshot {
            needs: vec![card],
            capabilities: vec![],
        };
        let wrong = TopicSpec::new(TopicKind::Ranking, "water", "IN-RJ").unwrap();
        assert!(state
            .insert_attestation(&wrong, att, &snapshot, false, NOW)
            .is_err());
        assert_eq!(state.evidence.len(), 0);
    }
}
