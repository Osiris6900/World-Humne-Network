//! Real TCP/Noise swarms on loopback; these are NOT independent-host release gates.

use std::time::Duration;
use tokio::time::{sleep, timeout};
use whn_core::{card::CapabilityDraft, crypto::Identity};
use whn_net::{record::unix_now, Error, Node, NodeConfig};

fn config() -> NodeConfig {
    NodeConfig {
        query_timeout: Duration::from_secs(2),
        ..Default::default()
    }
}

async fn node() -> Node {
    Node::spawn(&Identity::generate(), config()).await.unwrap()
}

fn card(ttl: u64) -> whn_core::card::CapabilityCard {
    let now = unix_now();
    CapabilityDraft::new(vec!["water".into(), "water/जल".into()], now, now + ttl)
        .sign(&Identity::generate())
        .unwrap()
}

#[tokio::test]
async fn a_new_node_resolves_all_offers_after_the_publisher_leaves() {
    let publisher = node().await;
    let replica = node().await;
    publisher.connect(replica.address()).await.unwrap();
    publisher.bootstrap().await.unwrap();
    let card = card(60);
    publisher.publish(&card).await.unwrap();
    assert_eq!(replica.stats().await.unwrap().stored_records, 2);
    drop(publisher);
    let newcomer = node().await;
    newcomer.connect(replica.address()).await.unwrap();
    for tag in &card.offers {
        assert_eq!(newcomer.resolve(tag, &card.id).await.unwrap(), card);
    }
}

#[tokio::test]
async fn expired_cards_disappear_and_are_not_republished() {
    let publisher = Node::spawn(&Identity::generate(), fast_config())
        .await
        .unwrap();
    let replica = node().await;
    publisher.connect(replica.address()).await.unwrap();
    let card = card(3);
    publisher.publish(&card).await.unwrap();
    replica.resolve("water", &card.id).await.unwrap();
    timeout(Duration::from_secs(6), async {
        while unix_now() < card.expires_at {
            sleep(Duration::from_millis(50)).await;
        }
        loop {
            if publisher.stats().await.unwrap().stored_records == 0
                && replica.stats().await.unwrap().stored_records == 0
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        replica.resolve("water", &card.id).await,
        Err(Error::NotFound)
    ));
    assert!(publisher.publish(&card).await.is_err());
}

fn fast_config() -> NodeConfig {
    NodeConfig {
        replication_interval: Duration::from_millis(100),
        republish_interval: Duration::from_millis(400),
        record_ttl: Duration::from_secs(2),
        replication_factor: std::num::NonZeroUsize::new(1).unwrap(),
        ..config()
    }
}

#[tokio::test]
async fn publication_is_periodically_repeated() {
    let publisher = Node::spawn(&Identity::generate(), fast_config())
        .await
        .unwrap();
    let replica = Node::spawn(&Identity::generate(), fast_config())
        .await
        .unwrap();
    publisher.connect(replica.address()).await.unwrap();
    publisher.publish(&card(60)).await.unwrap();
    let repeated = timeout(Duration::from_secs(6), async {
        while publisher.stats().await.unwrap().republish_successes == 0 {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        repeated.is_ok(),
        "no republish: {:?}",
        publisher.stats().await.unwrap()
    );
    // Outlive the initial two-second replica TTL. The signed card is still
    // live, so periodic publication must refresh the remote copy.
    sleep(Duration::from_secs(3)).await;
    assert_eq!(replica.stats().await.unwrap().stored_records, 2);
}

#[tokio::test]
async fn isolated_node_does_not_claim_remote_publication_success() {
    let node = node().await;
    assert!(node.bootstrap().await.is_err());
    assert!(node.publish(&card(60)).await.is_err());
    assert!(matches!(
        node.resolve("missing", &"0".repeat(64)).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn noise_rejects_a_bootstrap_peer_with_the_wrong_identity() {
    let a = node().await;
    let b = node().await;
    let mut wrong_address = b.address();
    wrong_address.pop();
    wrong_address.push(libp2p::multiaddr::Protocol::P2p(libp2p::PeerId::random()));
    assert!(a.connect(wrong_address).await.is_err());
    a.connect(b.address()).await.unwrap();
}

#[tokio::test]
async fn core_identity_determines_peer_id_and_bad_config_is_rejected() {
    let identity = Identity::from_secret_bytes(&[7; 32]);
    let expected = libp2p::identity::Keypair::ed25519_from_bytes([7; 32])
        .unwrap()
        .public()
        .to_peer_id();
    let node = Node::spawn(&identity, config()).await.unwrap();
    assert_eq!(node.peer_id(), expected);
    let bad = NodeConfig {
        record_ttl: Duration::ZERO,
        ..config()
    };
    assert!(matches!(
        Node::spawn(&identity, bad).await,
        Err(Error::Configuration(_))
    ));
}
