//! Local TCP/GossipSub integration; independent-machine gates are deferred.

use std::time::Duration;
use tokio::time::{sleep, timeout};
use whn_core::{
    card::{CapabilityDraft, NeedDraft},
    crypto::Identity,
};
use whn_net::{
    record::unix_now, Announcement, GossipProfile, Node, NodeConfig, TopicKind, TopicSpec,
};

async fn node() -> Node {
    Node::spawn(&Identity::generate(), NodeConfig::default())
        .await
        .unwrap()
}
fn topic(kind: TopicKind) -> TopicSpec {
    TopicSpec::new(kind, "water", "global").unwrap()
}
fn cap() -> whn_core::card::CapabilityCard {
    let now = unix_now();
    CapabilityDraft::new(vec!["water".into()], now, now + 60)
        .sign(&Identity::generate())
        .unwrap()
}
fn need() -> whn_core::card::NeedCard {
    let now = unix_now();
    NeedDraft::new(vec!["water".into()], 4, now, now + 60)
        .sign(&Identity::generate())
        .unwrap()
}
async fn ready_to_send(sender: &Node, topic: &TopicSpec) {
    let name = topic.name().unwrap();
    timeout(Duration::from_secs(8), async {
        while sender
            .stats()
            .await
            .unwrap()
            .gossip_subscribers
            .get(&name)
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
async fn received(node: &Node, count: u64) {
    timeout(Duration::from_secs(8), async {
        while node.stats().await.unwrap().gossip_accepted < count {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn broadcast_need_matches_a_remote_local_capability() {
    let a = node().await;
    let b = Node::spawn(
        &Identity::generate(),
        NodeConfig {
            gossip_profile: GossipProfile::Polite,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    b.subscribe(topic(TopicKind::Need)).await.unwrap();
    let cap = cap();
    b.register("water", Announcement::Capability(cap.clone()))
        .await
        .unwrap();
    a.connect(b.address()).await.unwrap();
    ready_to_send(&a, &topic(TopicKind::Need)).await;
    let need = need();
    a.announce("water", Announcement::Need(need.clone()))
        .await
        .unwrap();
    received(&b, 1).await;
    let matches = b.matches("water", &need.id).await.unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].capability_id, cap.id);
    assert_eq!(matches[0].shared_tags, vec!["water"]);
    // Repeating a valid announcement must not create duplicate cache rows.
    a.announce("water", Announcement::Need(need.clone()))
        .await
        .unwrap();
    received(&b, 2).await;
    assert_eq!(b.known_cards("water").await.unwrap().needs.len(), 1);
    assert_eq!(
        b.matches("water", &need.id).await.unwrap()[0].capability_id,
        cap.id
    );
}

#[tokio::test]
async fn capability_announcements_discover_candidates_without_a_known_card_id() {
    let a = node().await;
    let b = node().await;
    a.subscribe(topic(TopicKind::Capability)).await.unwrap();
    let need = need();
    a.register("water", Announcement::Need(need.clone()))
        .await
        .unwrap();
    a.connect(b.address()).await.unwrap();
    ready_to_send(&b, &topic(TopicKind::Capability)).await;
    let cap = cap();
    b.announce("water", Announcement::Capability(cap.clone()))
        .await
        .unwrap();
    received(&a, 1).await;
    assert_eq!(
        a.matches("water", &need.id).await.unwrap()[0].capability_id,
        cap.id
    );
}

#[tokio::test]
async fn unsubscribe_removes_remote_cards_and_stops_new_announcements() {
    let a = node().await;
    let b = node().await;
    let topic = topic(TopicKind::Need);
    b.subscribe(topic.clone()).await.unwrap();
    a.connect(b.address()).await.unwrap();
    ready_to_send(&a, &topic).await;
    a.announce("water", Announcement::Need(need()))
        .await
        .unwrap();
    received(&b, 1).await;
    assert!(b.unsubscribe(topic.clone()).await.unwrap());
    assert!(b.known_cards("water").await.unwrap().needs.is_empty());
    timeout(Duration::from_secs(8), async {
        while a
            .stats()
            .await
            .unwrap()
            .gossip_subscribers
            .contains_key(&topic.name().unwrap())
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(a
        .announce("water", Announcement::Need(need()))
        .await
        .is_err());
}

#[tokio::test]
async fn polite_mode_limits_subscriptions_and_releases_slots() {
    let node = Node::spawn(
        &Identity::generate(),
        NodeConfig {
            gossip_profile: GossipProfile::Polite,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for category in ["water", "food", "tools", "energy"] {
        node.subscribe(TopicSpec::new(TopicKind::Need, category, "global").unwrap())
            .await
            .unwrap();
    }
    assert!(!node.subscribe(topic(TopicKind::Need)).await.unwrap());
    let extra = TopicSpec::new(TopicKind::Need, "health", "global").unwrap();
    assert!(matches!(
        node.subscribe(extra.clone()).await,
        Err(whn_net::Error::SubscriptionLimit)
    ));
    node.unsubscribe(topic(TopicKind::Need)).await.unwrap();
    node.subscribe(extra).await.unwrap();
}

#[tokio::test]
async fn failed_broadcast_is_not_reported_as_delivered_or_cached() {
    let node = node().await;
    assert!(node
        .announce("water", Announcement::Need(need()))
        .await
        .is_err());
    assert_eq!(node.stats().await.unwrap().gossip_cached_cards, 0);
}
