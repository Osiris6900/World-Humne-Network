//! Valid GossipSub transport signatures do not make an invalid card acceptable.

use futures::StreamExt;
use libp2p::{
    gossipsub, identity, multiaddr::Protocol, noise, swarm::SwarmEvent, tcp, yamux, Multiaddr,
    SwarmBuilder,
};
use std::time::Duration;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};
use whn_core::{
    card::{NeedCard, NeedDraft},
    crypto::Identity,
};
use whn_net::{record::unix_now, Node, NodeConfig, TopicKind, TopicSpec};

struct Publish {
    topic: gossipsub::IdentTopic,
    data: Vec<u8>,
    reply: oneshot::Sender<bool>,
}
struct RawPeer {
    address: Multiaddr,
    command: mpsc::Sender<Publish>,
    task: JoinHandle<()>,
}
impl Drop for RawPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn raw_peer() -> RawPeer {
    let keys = identity::Keypair::generate_ed25519();
    let peer_id = keys.public().to_peer_id();
    let gossip: gossipsub::Behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keys.clone()),
        gossipsub::Config::default(),
    )
    .unwrap();
    let mut swarm = SwarmBuilder::with_existing_identity(keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| gossip)
        .unwrap()
        .build();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let (ready, started) = oneshot::channel();
    let (command, mut commands) = mpsc::channel::<Publish>(8);
    let task = tokio::spawn(async move {
        let mut ready = Some(ready);
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { mut address, .. } = event {
                        address.push(Protocol::P2p(peer_id));
                        if let Some(ready) = ready.take() { let _ = ready.send(address); }
                    }
                }
                command = commands.recv() => {
                    let Some(command) = command else { break; };
                    let result = swarm.behaviour_mut().publish(command.topic, command.data).is_ok();
                    let _ = command.reply.send(result);
                }
            }
        }
    });
    let address = timeout(Duration::from_secs(5), started)
        .await
        .unwrap()
        .unwrap();
    RawPeer {
        address,
        command,
        task,
    }
}

async fn send(peer: &RawPeer, topic: &TopicSpec, data: Vec<u8>) {
    timeout(Duration::from_secs(8), async {
        loop {
            let (reply, response) = oneshot::channel();
            peer.command
                .send(Publish {
                    topic: topic.topic().unwrap(),
                    data: data.clone(),
                    reply,
                })
                .await
                .unwrap();
            if response.await.unwrap() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

fn need(region: Option<&str>, ttl: u64) -> NeedCard {
    let now = unix_now();
    let mut draft = NeedDraft::new(vec!["water".into()], 4, now - 100, now + ttl);
    draft.region_hint = region.map(String::from);
    draft.sign(&Identity::generate()).unwrap()
}

#[tokio::test]
async fn invalid_cards_are_rejected_before_cache_and_matcher() {
    let raw = raw_peer().await;
    let node = Node::spawn(&Identity::generate(), NodeConfig::default())
        .await
        .unwrap();
    let topic = TopicSpec::new(TopicKind::Need, "water", "IN-RJ").unwrap();
    node.subscribe(topic.clone()).await.unwrap();
    node.connect(raw.address.clone()).await.unwrap();
    let valid = need(Some("IN-RJ"), 60);
    let payload = serde_json::to_vec(&valid).unwrap();
    let mut forged = valid.clone();
    forged.note = Some("forged claim".into());
    let duplicate = String::from_utf8(payload.clone())
        .unwrap()
        .replacen('{', "{\"urgency\":4,", 1);
    let unknown =
        String::from_utf8(payload.clone())
            .unwrap()
            .replacen('{', "{\"unsigned_extra\":true,", 1);
    let wrong_region = serde_json::to_vec(&need(Some("IN-DL"), 60)).unwrap();
    let mut expired = NeedDraft::new(vec!["water".into()], 4, unix_now() - 100, unix_now() - 1);
    expired.region_hint = Some("IN-RJ".into());
    let expired = serde_json::to_vec(&expired.sign(&Identity::generate()).unwrap()).unwrap();
    for data in [
        serde_json::to_vec(&forged).unwrap(),
        duplicate.into_bytes(),
        unknown.into_bytes(),
        wrong_region,
        expired,
    ] {
        send(&raw, &topic, data).await;
    }
    timeout(Duration::from_secs(8), async {
        while node.stats().await.unwrap().gossip_rejected < 5 {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(node.known_cards("water").await.unwrap().needs.is_empty());
    send(&raw, &topic, payload).await;
    timeout(Duration::from_secs(8), async {
        while node.stats().await.unwrap().gossip_accepted < 1 {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(node.known_cards("water").await.unwrap().needs, vec![valid]);
}
