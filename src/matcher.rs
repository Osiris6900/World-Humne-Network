//! Deterministic, local-only candidate matching. Reputation is neutral in v0.

use crate::{
    card::{CapabilityCard, NeedCard},
    error::WhnError,
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MatchCandidate {
    pub need_id: String,
    pub capability_id: String,
    pub shared_tags: Vec<String>,
    pub tag_coverage: f64,
    pub region_affinity: f64,
    pub freshness: f64,
    /// Neutral in the base scorer; the node applies its local trust policy.
    pub reputation_weight: f64,
    pub score: f64,
}

/// Validate the need and each capability, then rank live candidates.
/// Invalid/expired capabilities are ignored; an invalid need is an error.
/// Tags are exact, case-sensitive strings, deduplicated before scoring.
pub fn rank_candidates(
    need: &NeedCard,
    capabilities: &[CapabilityCard],
    now: u64,
) -> Result<Vec<MatchCandidate>, WhnError> {
    need.verify_at(now)?;
    let required: BTreeSet<_> = need.needs.iter().collect();
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for card in capabilities {
        if card.verify_at(now).is_err() || card.pubkey == need.pubkey || !seen.insert(&card.id) {
            continue;
        }
        let offered: BTreeSet<_> = card.offers.iter().collect();
        let shared_tags: Vec<String> = required
            .intersection(&offered)
            .map(|s| (*s).clone())
            .collect();
        if shared_tags.is_empty() {
            continue;
        }
        let tag_coverage = shared_tags.len() as f64 / required.len() as f64;
        let region_affinity =
            region_affinity(need.region_hint.as_deref(), card.region_hint.as_deref());
        let freshness = 1.0 / (1.0 + now.saturating_sub(card.created_at) as f64 / 86_400.0);
        let reputation_weight = 1.0;
        let score = tag_coverage * (0.7 + 0.3 * region_affinity) * freshness * reputation_weight;
        result.push(MatchCandidate {
            need_id: need.id.clone(),
            capability_id: card.id.clone(),
            shared_tags,
            tag_coverage,
            region_affinity,
            freshness,
            reputation_weight,
            score,
        });
    }
    result.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.capability_id.cmp(&b.capability_id))
    });
    Ok(result)
}

fn region_affinity(a: Option<&str>, b: Option<&str>) -> f64 {
    match (a.filter(|s| !s.is_empty()), b.filter(|s| !s.is_empty())) {
        (Some(a), Some(b)) if a == b => 1.0,
        (Some(a), Some(b)) if a.split('-').next() == b.split('-').next() => 0.6,
        (Some(_), Some(_)) => 0.2,
        _ => 0.4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        card::{CapabilityDraft, NeedDraft},
        crypto::Identity,
    };

    const NOW: u64 = 1_800_000_000;
    fn need() -> NeedCard {
        let mut draft = NeedDraft::new(
            vec!["water".into(), "water".into(), "tools".into()],
            4,
            NOW - 10,
            NOW + 100,
        );
        draft.region_hint = Some("IN-RJ".into());
        draft.sign(&Identity::from_secret_bytes(&[1; 32])).unwrap()
    }
    fn cap(tags: &[&str], region: Option<&str>, age: u64) -> CapabilityCard {
        let mut draft = CapabilityDraft::new(
            tags.iter().map(|t| (*t).into()).collect(),
            NOW - age,
            NOW + 100,
        );
        draft.region_hint = region.map(String::from);
        draft.sign(&Identity::from_secret_bytes(&[2; 32])).unwrap()
    }

    #[test]
    fn tag_overlap_is_required_and_duplicates_do_not_inflate_coverage() {
        let cap = cap(&["water", "water"], Some("IN-RJ"), 0);
        let matches = rank_candidates(
            &need(),
            &[cap.clone(), cap, self::cap(&["food"], None, 0)],
            NOW,
        )
        .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].shared_tags, vec!["water"]);
        assert_eq!(matches[0].tag_coverage, 0.5);
        assert_eq!(matches[0].reputation_weight, 1.0);
    }

    #[test]
    fn region_and_freshness_rank_candidates_without_network_calls() {
        let local = cap(&["water"], Some("IN-RJ"), 0);
        let country = cap(&["water"], Some("IN-DL"), 0);
        let foreign = cap(&["water"], Some("US-CA"), 0);
        let old = cap(&["water"], Some("IN-RJ"), 7 * 86_400);
        let ranked = rank_candidates(
            &need(),
            &[old.clone(), foreign.clone(), country.clone(), local.clone()],
            NOW,
        )
        .unwrap();
        assert_eq!(
            ranked
                .iter()
                .map(|c| c.capability_id.as_str())
                .collect::<Vec<_>>(),
            [local.id, country.id, foreign.id, old.id]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn expired_forged_and_self_authored_capabilities_are_excluded() {
        let expired = CapabilityDraft::new(vec!["water".into()], NOW - 100, NOW)
            .sign(&Identity::from_secret_bytes(&[2; 32]))
            .unwrap();
        let mut forged = cap(&["water"], None, 0);
        forged.offers.push("tools".into());
        let own = CapabilityDraft::new(vec!["water".into()], NOW - 1, NOW + 10)
            .sign(&Identity::from_secret_bytes(&[1; 32]))
            .unwrap();
        assert!(rank_candidates(&need(), &[expired, forged, own], NOW)
            .unwrap()
            .is_empty());
        assert!(rank_candidates(&need(), &[], NOW + 100).is_err());
    }

    #[test]
    fn ties_have_a_stable_id_order_and_unknown_regions_are_neutral() {
        let a = cap(&["water"], None, 0);
        let mut draft = CapabilityDraft::new(vec!["water".into()], NOW, NOW + 100);
        draft.pow_nonce = "1".into();
        let b = draft.sign(&Identity::from_secret_bytes(&[2; 32])).unwrap();
        let expected = rank_candidates(&need(), &[a.clone(), b.clone()], NOW).unwrap();
        assert_eq!(expected, rank_candidates(&need(), &[b, a], NOW).unwrap());
        assert!(expected[0].capability_id < expected[1].capability_id);
        assert_eq!(expected[0].region_affinity, 0.4);
    }
}
