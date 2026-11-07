//! Real TCP gossip on one host; multi-host acceptance remains pending.
use std::time::Duration;
use tokio::time::{sleep, timeout};
use whn_core::{
    card::{NeedCard, NeedDraft},
    crypto::Identity,
};
use whn_net::{
    record::unix_now, Announcement, Attestation, Claim, Node, NodeConfig, TopicKind, TopicSpec,
};

fn identity(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32])
}
fn need(nonce: &str) -> NeedCard {
    let now = unix_now();
    let mut draft = NeedDraft::new(vec!["water".into()], 4, now - 1, now + 60);
    draft.pow_nonce = nonce.into();
    draft.sign(&identity(3)).unwrap()
}
fn topic() -> TopicSpec {
    TopicSpec::new(TopicKind::Ranking, "water", "global").unwrap()
}
async fn ready(node: &Node) {
    timeout(Duration::from_secs(8), async {
        while node
            .stats()
            .await
            .unwrap()
            .gossip_subscribers
            .get("whn/0.1/rank/water/global")
            .copied()
            .unwrap_or(0)
            == 0
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn signed_attestations_raise_verified_needs_and_sink_flagged_needs_on_both_nodes() {
    let a = Node::spawn(&identity(2), NodeConfig::default())
        .await
        .unwrap();
    let b = Node::spawn(&identity(1), NodeConfig::default())
        .await
        .unwrap();
    let needs = [need("verified"), need("plain"), need("flagged")];
    for node in [&a, &b] {
        node.subscribe(topic()).await.unwrap();
        node.trust(&identity(1).public_key_b64(), 1000)
            .await
            .unwrap();
        for need in &needs {
            node.register("water", Announcement::Need(need.clone()))
                .await
                .unwrap();
        }
    }
    a.connect(b.address()).await.unwrap();
    ready(&b).await;
    for (index, claim) in [(0, Claim::VerifiedReal), (2, Claim::Fraudulent)] {
        let att = Attestation::sign(&needs[index].id, claim, unix_now(), &identity(1)).unwrap();
        b.announce_attestation("water", att).await.unwrap();
    }
    timeout(Duration::from_secs(8), async {
        while a.stats().await.unwrap().ranking_attestations < 2 {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    for node in [&a, &b] {
        let ranks = node.ranks("water", "global").await.unwrap();
        assert_eq!(
            ranks.iter().map(|r| r.card_id.as_str()).collect::<Vec<_>>(),
            needs.iter().map(|n| n.id.as_str()).collect::<Vec<_>>()
        );
        assert!(ranks[0].local_score > ranks[1].local_score);
        assert!(ranks[2].quarantined && ranks[2].local_score < 0.0);
    }
}

#[tokio::test]
async fn periodic_signed_summaries_merge_using_local_trust_and_reset_with_policy() {
    let a = Node::spawn(&identity(4), NodeConfig::default())
        .await
        .unwrap();
    let b = Node::spawn(
        &identity(2),
        NodeConfig {
            rank_gossip_interval: Some(Duration::from_millis(100)),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let need = need("target");
    for node in [&a, &b] {
        node.subscribe(topic()).await.unwrap();
        node.trust(&identity(1).public_key_b64(), 1000)
            .await
            .unwrap();
        node.trust(&identity(2).public_key_b64(), 1000)
            .await
            .unwrap();
        node.register("water", Announcement::Need(need.clone()))
            .await
            .unwrap();
    }
    let att = Attestation::sign(&need.id, Claim::VerifiedReal, unix_now(), &identity(1)).unwrap();
    b.register_attestation("water", att).await.unwrap();
    a.connect(b.address()).await.unwrap();
    timeout(Duration::from_secs(8), async {
        loop {
            let ranks = a.ranks("water", "global").await.unwrap();
            if ranks[0].summary_weight > 0.0 {
                assert!(ranks[0].aggregate_score > ranks[0].local_score);
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(b.stats().await.unwrap().ranking_published > 0);
    a.trust(&identity(2).public_key_b64(), 0).await.unwrap();
    let rank = &a.ranks("water", "global").await.unwrap()[0];
    assert_eq!(rank.summary_weight, 0.0);
    assert_eq!(rank.aggregate_score, rank.local_score);
}

#[tokio::test]
async fn unknown_and_self_attestations_are_not_registered() {
    let node = Node::spawn(&identity(3), NodeConfig::default())
        .await
        .unwrap();
    let need = need("target");
    let att = Attestation::sign(&need.id, Claim::VerifiedReal, unix_now(), &identity(3)).unwrap();
    assert!(node
        .register_attestation("water", att.clone())
        .await
        .is_err());
    node.register("water", Announcement::Need(need))
        .await
        .unwrap();
    assert!(node.register_attestation("water", att).await.is_err());
    assert_eq!(node.stats().await.unwrap().ranking_attestations, 0);
}

#[tokio::test]
async fn matcher_uses_reputation_and_excludes_locally_quarantined_capabilities() {
    let node = Node::spawn(&identity(9), NodeConfig::default())
        .await
        .unwrap();
    let need = need("target");
    node.register("water", Announcement::Need(need.clone()))
        .await
        .unwrap();
    node.trust(&identity(1).public_key_b64(), 1000)
        .await
        .unwrap();
    let now = unix_now();
    let good = whn_core::card::CapabilityDraft::new(vec!["water".into()], now - 1, now + 60)
        .sign(&identity(2))
        .unwrap();
    let bad = whn_core::card::CapabilityDraft::new(vec!["water".into()], now - 1, now + 60)
        .sign(&identity(4))
        .unwrap();
    for card in [&good, &bad] {
        node.register("water", Announcement::Capability(card.clone()))
            .await
            .unwrap();
    }
    for (card, claim) in [(&good, Claim::VerifiedReal), (&bad, Claim::Fraudulent)] {
        node.register_attestation(
            "water",
            Attestation::sign(&card.id, claim, now, &identity(1)).unwrap(),
        )
        .await
        .unwrap();
    }
    let matches = node.matches("water", &need.id).await.unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].capability_id, good.id);
    assert!((matches[0].reputation_weight - 0.55).abs() < 0.001);
}
