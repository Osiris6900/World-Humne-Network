//! Exercise the wire trust boundary using a deliberately unvalidated peer.

use futures::StreamExt;
use libp2p::{
    identity,
    kad::{
        self,
        store::{MemoryStore, RecordStore},
        QueryId, Quorum, Record,
    },
    multiaddr::Protocol,
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, StreamProtocol, SwarmBuilder,
};
use std::{collections::HashMap, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use whn_core::{card::CapabilityDraft, crypto::Identity};
use whn_net::{
    record::{capability_key, unix_now, MAX_RECORD_BYTES},
    Error, Node, NodeConfig,
};

type Ack = oneshot::Sender<()>;
enum Command {
    Send(Record, Multiaddr, Ack),
}
struct Untrusted {
    address: Multiaddr,
    command: mpsc::Sender<Command>,
    task: JoinHandle<()>,
}
impl Drop for Untrusted {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn untrusted(initial: Option<Record>) -> Untrusted {
    let keys = identity::Keypair::generate_ed25519();
    let peer = keys.public().to_peer_id();
    let mut store = MemoryStore::new(peer);
    if let Some(record) = initial {
        store.put(record).unwrap();
    }
    let mut config = kad::Config::new(StreamProtocol::new("/whn/kad/0.1.0"));
    config
        .set_query_timeout(Duration::from_secs(2))
        .set_substreams_timeout(Duration::from_secs(1))
        .set_publication_interval(None)
        .set_replication_interval(None)
        .set_periodic_bootstrap_interval(None);
    let mut kad = kad::Behaviour::with_config(peer, store, config);
    kad.set_mode(Some(kad::Mode::Server));
    let mut swarm = SwarmBuilder::with_existing_identity(keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| kad)
        .unwrap()
        .build();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let (ready, started) = oneshot::channel();
    let (command, mut commands) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        let mut ready = Some(ready);
        let mut pending = HashMap::<QueryId, Ack>::new();
        loop {
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { mut address, .. } => {
                        address.push(Protocol::P2p(peer));
                        if let Some(ready) = ready.take() { let _ = ready.send(address); }
                    }
                    SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed { id, step, .. }) if step.last => {
                        if let Some(ack) = pending.remove(&id) { let _ = ack.send(()); }
                    }
                    _ => {}
                },
                command = commands.recv() => match command {
                    Some(Command::Send(record, mut address, ack)) => {
                        let Some(Protocol::P2p(peer)) = address.pop() else { panic!("invalid test address") };
                        swarm.behaviour_mut().add_address(&peer, address);
                        let query = swarm.behaviour_mut().put_record_to(record, vec![peer].into_iter(), Quorum::One);
                        pending.insert(query, ack);
                    }
                    None => break,
                }
            }
        }
    });
    let address = timeout(Duration::from_secs(5), started)
        .await
        .unwrap()
        .unwrap();
    Untrusted {
        address,
        command,
        task,
    }
}

async fn honest() -> Node {
    Node::spawn(
        &Identity::generate(),
        NodeConfig {
            query_timeout: Duration::from_secs(2),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn record() -> Record {
    let now = unix_now();
    let card = CapabilityDraft::new(vec!["water".into()], now, now + 60)
        .sign(&Identity::generate())
        .unwrap();
    Record::new(
        capability_key("water", &card.id).unwrap(),
        serde_json::to_vec(&card).unwrap(),
    )
}

#[tokio::test]
async fn forged_lookup_responses_are_rejected_and_not_cached() {
    let mut record = record();
    let mut card: whn_core::card::CapabilityCard = serde_json::from_slice(&record.value).unwrap();
    let id = card.id.clone();
    card.capacity_note = Some("forged content".into());
    record.value = serde_json::to_vec(&card).unwrap();
    let bad = untrusted(Some(record)).await;
    let honest = honest().await;
    honest.connect(bad.address.clone()).await.unwrap();
    assert!(matches!(
        honest.resolve("water", &id).await,
        Err(Error::NotFound)
    ));
    assert_eq!(honest.stats().await.unwrap().stored_records, 0);
}

#[tokio::test]
async fn validated_lookup_results_are_cached() {
    let record = record();
    let expected: whn_core::card::CapabilityCard = serde_json::from_slice(&record.value).unwrap();
    let source = untrusted(Some(record)).await;
    let honest = honest().await;
    honest.connect(source.address.clone()).await.unwrap();
    assert_eq!(
        honest.resolve("water", &expected.id).await.unwrap(),
        expected
    );
    drop(source);
    assert_eq!(
        honest.resolve("water", &expected.id).await.unwrap(),
        expected
    );
}

#[tokio::test]
async fn invalid_network_puts_do_not_enter_the_dht_store() {
    let good = record();
    let mut wrong_key = good.clone();
    wrong_key.key = capability_key("food", &"0".repeat(64)).unwrap();
    let mut forged = good.clone();
    let mut card: whn_core::card::CapabilityCard = serde_json::from_slice(&forged.value).unwrap();
    card.capacity_note = Some("forged content".into());
    forged.value = serde_json::to_vec(&card).unwrap();
    let mut oversized = good.clone();
    oversized.value = vec![b'x'; MAX_RECORD_BYTES + 1];
    let source = untrusted(None).await;
    let honest = honest().await;
    honest.connect(source.address.clone()).await.unwrap();
    for record in [wrong_key, forged, oversized] {
        let (ack, reply) = oneshot::channel();
        source
            .command
            .send(Command::Send(record, honest.address(), ack))
            .await
            .unwrap();
        timeout(Duration::from_secs(5), reply)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(honest.stats().await.unwrap().stored_records, 0);
    }
    let (ack, reply) = oneshot::channel();
    source
        .command
        .send(Command::Send(good, honest.address(), ack))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), reply)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(honest.stats().await.unwrap().stored_records, 1);
}
