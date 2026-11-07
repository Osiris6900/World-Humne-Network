use whn_core::{
    attestation::{Attestation, Claim},
    card::{CapabilityDraft, NeedCard, NeedDraft},
    crypto::Identity,
    ranking::{
        merge_summaries, rank_needs, RankingPolicy, RankingSummary, SummaryEntry, TargetCard,
        TrustAnchors,
    },
};

const NOW: u64 = 1_800_000_000;
fn identity(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32])
}
fn need(author: u8, nonce: &str) -> NeedCard {
    let mut draft = NeedDraft::new(vec!["water".into()], 4, NOW - 14 * 86400, NOW + 100);
    draft.pow_nonce = nonce.into();
    draft.sign(&identity(author)).unwrap()
}
fn target(author: u8) -> TargetCard {
    TargetCard::Capability(
        CapabilityDraft::new(vec!["water".into()], NOW - 14 * 86400, NOW + 100)
            .sign(&identity(author))
            .unwrap(),
    )
}
fn att(id: &str, claim: Claim, seed: u8, time: u64) -> Attestation {
    Attestation::sign(id, claim, time, &identity(seed)).unwrap()
}
fn anchors(seeds: &[u8]) -> TrustAnchors {
    let mut anchors = TrustAnchors::default();
    for seed in seeds {
        anchors
            .set(&identity(*seed).public_key_b64(), 1000)
            .unwrap();
    }
    anchors
}

#[test]
fn attested_need_rises_and_trusted_fraud_claim_sinks() {
    let needs = vec![need(2, "a"), need(2, "b"), need(2, "c")];
    let targets: Vec<_> = needs.iter().cloned().map(TargetCard::Need).collect();
    let evidence = vec![
        att(&needs[0].id, Claim::VerifiedReal, 1, NOW),
        att(&needs[2].id, Claim::Fraudulent, 1, NOW),
    ];
    let view = rank_needs(
        &needs,
        &targets,
        &evidence,
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        view.needs
            .iter()
            .map(|r| r.card_id.as_str())
            .collect::<Vec<_>>(),
        needs.iter().map(|n| n.id.as_str()).collect::<Vec<_>>()
    );
    assert!(view.needs[0].local_score > view.needs[1].local_score);
    assert!(view.needs[2].local_score < 0.0 && view.needs[2].quarantined);
}

#[test]
fn fresh_disconnected_identities_cannot_vote_themselves_into_reputation() {
    let need = need(90, "target");
    let targets = [TargetCard::Need(need.clone())];
    let evidence: Vec<_> = (2..40)
        .map(|seed| att(&need.id, Claim::VerifiedReal, seed, NOW))
        .collect();
    let base = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &[],
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    let flooded = rank_needs(
        &[need],
        &targets,
        &evidence,
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    assert_eq!(flooded.needs[0].local_score, base.needs[0].local_score);
    assert_eq!(flooded.needs[0].verified_weight, 0.0);
}

#[test]
fn graph_depth_discounts_trust_and_reciprocal_edges_are_excluded() {
    let a = target(2);
    let b = target(3);
    let need = need(4, "target");
    let targets = vec![a.clone(), b.clone(), TargetCard::Need(need.clone())];
    let mut evidence = vec![
        att(a.id(), Claim::VerifiedReal, 1, NOW),
        att(b.id(), Claim::VerifiedReal, 2, NOW),
        att(&need.id, Claim::VerifiedReal, 3, NOW),
    ];
    let view = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &evidence,
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    assert_eq!(view.reputation[&identity(2).public_key_b64()], 0.5);
    assert_eq!(view.reputation[&identity(3).public_key_b64()], 0.25);
    assert_eq!(view.needs[0].verified_weight, 0.25);
    evidence.push(att(a.id(), Claim::VerifiedReal, 3, NOW));
    let reciprocal = rank_needs(
        &[need],
        &targets,
        &evidence,
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    assert_eq!(reciprocal.needs[0].verified_weight, 0.0);
}

#[test]
fn fanout_shares_a_budget_instead_of_minting_weight_per_key() {
    let mut targets: Vec<_> = (2..12).map(target).collect();
    let need = need(80, "target");
    let mut evidence = Vec::new();
    for (seed, card) in (2..12).zip(&targets) {
        evidence.push(att(card.id(), Claim::VerifiedReal, 1, NOW));
        evidence.push(att(&need.id, Claim::VerifiedReal, seed, NOW));
    }
    targets.push(TargetCard::Need(need.clone()));
    let view = rank_needs(
        &[need],
        &targets,
        &evidence,
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    assert!((view.needs[0].verified_weight - 0.5).abs() < 1e-12);
    assert!(view.reputation.values().sum::<f64>() < 2.0);
}

#[test]
fn latest_claim_wins_replays_do_not_amplify_and_conflicts_are_order_independent() {
    let need = need(2, "target");
    let targets = [TargetCard::Need(need.clone())];
    let old = att(&need.id, Claim::VerifiedReal, 1, NOW - 1);
    let fraud = att(&need.id, Claim::Fraudulent, 1, NOW);
    let simultaneous = att(&need.id, Claim::VerifiedReal, 1, NOW);
    let a = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &[old.clone(), fraud.clone(), simultaneous.clone(), old],
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    let b = rank_needs(
        &[need],
        &targets,
        &[simultaneous, fraud],
        &anchors(&[1]),
        &RankingPolicy::default(),
        NOW,
    )
    .unwrap();
    assert!(a.needs[0].quarantined);
    assert_eq!(a.needs[0].verified_weight, 0.0);
    assert_eq!(a.needs[0].local_score, b.needs[0].local_score);
}

#[test]
fn evidence_decays_by_half_and_fulfilment_reduces_active_priority() {
    let need = need(2, "target");
    let targets = [TargetCard::Need(need.clone())];
    let policy = RankingPolicy::default();
    let aged = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &[att(
            &need.id,
            Claim::VerifiedReal,
            1,
            NOW - policy.half_life_secs,
        )],
        &anchors(&[1]),
        &policy,
        NOW,
    )
    .unwrap();
    assert_eq!(aged.needs[0].verified_weight, 0.5);
    let base = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &[],
        &anchors(&[1]),
        &policy,
        NOW,
    )
    .unwrap();
    let done = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &[att(&need.id, Claim::Fulfilled, 1, NOW)],
        &anchors(&[1]),
        &policy,
        NOW,
    )
    .unwrap();
    assert!(done.needs[0].local_score < base.needs[0].local_score);
    let own = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &[att(&need.id, Claim::VerifiedReal, 2, NOW)],
        &anchors(&[2]),
        &policy,
        NOW,
    )
    .unwrap();
    assert_eq!(own.needs[0].verified_weight, 0.0);
}

#[test]
fn weighted_summaries_are_deduplicated_and_cannot_lift_local_quarantine() {
    let need = need(3, "target");
    let policy = RankingPolicy::default();
    let anchors = anchors(&[1, 2]);
    let fingerprint = policy.fingerprint(&anchors).unwrap();
    let targets = [TargetCard::Need(need.clone())];
    let make_view = || {
        rank_needs(
            std::slice::from_ref(&need),
            &targets,
            &[],
            &anchors,
            &policy,
            NOW,
        )
        .unwrap()
    };
    let summary = RankingSummary::sign(
        "water",
        "global",
        &fingerprint,
        vec![SummaryEntry {
            card_id: need.id.clone(),
            score_micros: 500_000,
        }],
        NOW,
        &identity(2),
    )
    .unwrap();
    let mut view = make_view();
    let local = view.needs[0].local_score;
    merge_summaries(
        &mut view,
        &vec![summary.clone(); 10],
        &identity(99).public_key_b64(),
        &fingerprint,
        &policy,
        NOW,
    );
    assert_eq!(view.needs[0].summary_weight, 1.0);
    assert!((view.needs[0].aggregate_score - (local + 0.5) / 2.0).abs() < 1e-12);
    let mut quarantined = rank_needs(
        std::slice::from_ref(&need),
        &targets,
        &[att(&need.id, Claim::Fraudulent, 1, NOW)],
        &anchors,
        &policy,
        NOW,
    )
    .unwrap();
    let original = quarantined.needs[0].local_score;
    merge_summaries(
        &mut quarantined,
        &[summary],
        "other",
        &fingerprint,
        &policy,
        NOW,
    );
    assert!(quarantined.needs[0].aggregate_score <= original);
    let untrusted = RankingSummary::sign(
        "water",
        "global",
        &fingerprint,
        vec![SummaryEntry {
            card_id: need.id.clone(),
            score_micros: 64_000_000,
        }],
        NOW,
        &identity(4),
    )
    .unwrap();
    let mut view = make_view();
    merge_summaries(&mut view, &[untrusted], "other", &fingerprint, &policy, NOW);
    assert_eq!(view.needs[0].aggregate_score, local);
}

#[test]
fn signing_validation_rejects_tampering_stale_future_and_malformed_objects() {
    let mut evidence = att(&"a".repeat(64), Claim::VerifiedReal, 1, NOW);
    evidence.verify_at(NOW, 100, 0).unwrap();
    assert!(evidence.verify_at(NOW - 1, 100, 0).is_err());
    assert!(evidence.verify_at(NOW + 101, 100, 0).is_err());
    evidence.claim = Claim::Fraudulent;
    assert!(evidence.verify().is_err());
    let duplicate =
        serde_json::to_string(&evidence)
            .unwrap()
            .replacen('{', "{\"claim\":\"fraudulent\",", 1);
    assert!(serde_json::from_str::<Attestation>(&duplicate).is_err());
    let policy = RankingPolicy {
        half_life_secs: 0,
        ..Default::default()
    };
    assert!(policy.validate().is_err());
    assert!(anchors(&[]).clone().set("invalid", 1000).is_err());
    assert!(RankingSummary::sign(
        "water",
        "global",
        &"a".repeat(64),
        vec![SummaryEntry {
            card_id: "b".repeat(64),
            score_micros: i64::MIN
        }],
        NOW,
        &identity(1)
    )
    .is_err());
}

#[test]
fn fixed_ranking_objects_verify_exact_published_bytes() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/ranking-v0.json")).unwrap();
    let att: Attestation = serde_json::from_value(fixture["attestation"].clone()).unwrap();
    let summary: RankingSummary = serde_json::from_value(fixture["summary"].clone()).unwrap();
    att.verify().unwrap();
    summary.verify_at(NOW, &RankingPolicy::default()).unwrap();
    assert_eq!(att.id().unwrap(), fixture["attestation_id"]);
    assert_eq!(
        att.signing_payload_bytes().unwrap(),
        fixture["attestation_signing_payload_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        summary.signing_payload_bytes().unwrap(),
        fixture["summary_signing_payload_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
}
