use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroUsize,
    time::Duration,
};

use futures::StreamExt;
use libp2p::{
    gossipsub, identify, identity,
    kad::{self, store::RecordStore, GetRecordOk, QueryId, QueryResult, Quorum, Record, RecordKey},
    multiaddr::Protocol,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time,
};
use whn_core::{card::CapabilityCard, crypto::Identity};

use crate::{
    gossip::{
        Announcement, GossipCache, GossipProfile, GossipSnapshot, SubscriptionFilter, TopicSpec,
        WhnSubscriptionFilter,
    },
    record::{records_for, unix_now, validate_record, ValidatingStore},
    Error,
};

type Reply<T> = oneshot::Sender<Result<T, Error>>;
const MAX_PENDING: usize = 128;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub listen: Multiaddr,
    pub query_timeout: Duration,
    pub record_ttl: Duration,
    pub republish_interval: Duration,
    pub replication_interval: Duration,
    /// Target remote copies. Initial publication needs one ACK; automatic
    /// republishing reports success only when this whole target is met.
    pub replication_factor: NonZeroUsize,
    pub gossip_profile: GossipProfile,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            query_timeout: Duration::from_secs(10),
            record_ttl: Duration::from_secs(3600),
            republish_interval: Duration::from_secs(300),
            replication_interval: Duration::from_secs(60),
            replication_factor: NonZeroUsize::new(3).unwrap(),
            gossip_profile: GossipProfile::Standard,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct NodeStats {
    pub connected_peers: usize,
    pub stored_records: usize,
    pub republish_successes: u64,
    pub republish_failures: u64,
    pub gossip_accepted: u64,
    pub gossip_rejected: u64,
    pub gossip_ignored: u64,
    pub gossip_cached_cards: usize,
    pub gossip_subscriptions: usize,
    /// Connected peers advertising each topic; this is not a delivery ACK.
    pub gossip_subscribers: BTreeMap<String, usize>,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<ValidatingStore>,
    identify: identify::Behaviour,
    gossip: gossipsub::Behaviour<gossipsub::IdentityTransform, SubscriptionFilter>,
}

enum Command {
    Connect(Multiaddr, Reply<()>),
    Bootstrap(Reply<()>),
    Put(Record, Reply<()>),
    Get(RecordKey, Reply<CapabilityCard>),
    Stats(Reply<NodeStats>),
    Subscribe(TopicSpec, Reply<bool>),
    Unsubscribe(TopicSpec, Reply<bool>),
    Register(String, Announcement, Reply<()>),
    Announce(String, Announcement, Reply<String>),
    Snapshot(String, Reply<GossipSnapshot>),
    Matches(
        String,
        String,
        Reply<Vec<whn_core::matcher::MatchCandidate>>,
    ),
}

enum Pending {
    Put(Reply<()>),
    Bootstrap(Reply<()>),
    Get {
        key: RecordKey,
        reply: Reply<CapabilityCard>,
    },
}

impl Pending {
    fn is_closed(&self) -> bool {
        match self {
            Self::Put(reply) | Self::Bootstrap(reply) => reply.is_closed(),
            Self::Get { reply, .. } => reply.is_closed(),
        }
    }
}

/// A running swarm. Dropping it closes connections and stops all background jobs.
pub struct Node {
    peer_id: PeerId,
    address: Multiaddr,
    commands: mpsc::Sender<Command>,
    task: JoinHandle<()>,
    operation_timeout: Duration,
}

impl Node {
    pub async fn spawn(identity: &Identity, config: NodeConfig) -> Result<Self, Error> {
        if config.query_timeout.is_zero()
            || config.replication_interval.is_zero()
            || config.republish_interval <= config.replication_interval
            || config.record_ttl <= config.republish_interval
            || config.record_ttl > Duration::from_secs(365 * 24 * 3600)
            || config.query_timeout > Duration::from_secs(300)
        {
            return Err(Error::Configuration(
                "require 0 < replication < republish < record_ttl <= 365 days, and 0 < query timeout <= 300 seconds",
            ));
        }
        let operation_timeout = config
            .query_timeout
            .checked_mul(4)
            .and_then(|t| t.checked_add(Duration::from_secs(5)))
            .ok_or(Error::Configuration("query timeout is too large"))?;
        let keys = identity::Keypair::ed25519_from_bytes(identity.secret_bytes())
            .map_err(network_error)?;
        let peer_id = keys.public().to_peer_id();
        let mut kad_config = kad::Config::new(StreamProtocol::new("/whn/kad/0.1.0"));
        kad_config
            .set_query_timeout(config.query_timeout)
            .set_record_ttl(Some(config.record_ttl))
            .set_publication_interval(Some(config.republish_interval))
            .set_replication_interval(Some(config.replication_interval))
            .set_replication_factor(config.replication_factor)
            .set_periodic_bootstrap_interval(Some(Duration::from_secs(60)))
            .set_max_packet_size(32 * 1024);
        let mut kad =
            kad::Behaviour::with_config(peer_id, ValidatingStore::new(peer_id), kad_config);
        kad.set_mode(Some(kad::Mode::Server));
        let behaviour = Behaviour {
            kad,
            identify: identify::Behaviour::new(identify::Config::new(
                "/whn/id/0.1.0".into(),
                keys.public(),
            )),
            gossip: gossipsub::Behaviour::new_with_subscription_filter(
                gossipsub::MessageAuthenticity::Signed(keys.clone()),
                config.gossip_profile.config()?,
                SubscriptionFilter {
                    filter: WhnSubscriptionFilter,
                    max_subscribed_topics: 32,
                    max_subscriptions_per_request: 16,
                },
            )
            .map_err(network_error)?,
        };
        let mut swarm = SwarmBuilder::with_existing_identity(keys)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(network_error)?
            .with_behaviour(|_| behaviour)
            .map_err(network_error)?
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(120))
            })
            .build();
        swarm.listen_on(config.listen).map_err(network_error)?;
        let (commands, receiver) = mpsc::channel(32);
        let (ready, started) = oneshot::channel();
        let task = tokio::spawn(run(
            swarm,
            receiver,
            ready,
            config.gossip_profile.subscription_limit(),
        ));
        // Construct the guard before waiting, so cancellation also stops the swarm.
        let mut node = Self {
            peer_id,
            address: Multiaddr::empty(),
            commands,
            task,
            operation_timeout,
        };
        node.address = time::timeout(operation_timeout, started)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Stopped)??;
        node.address.push(Protocol::P2p(peer_id));
        Ok(node)
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    /// Full dial address, ending in `/p2p/<PeerId>`.
    pub fn address(&self) -> Multiaddr {
        self.address.clone()
    }

    async fn request<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T, Error> {
        time::timeout(self.operation_timeout, async {
            let (reply, response) = oneshot::channel();
            self.commands
                .send(command(reply))
                .await
                .map_err(|_| Error::Stopped)?;
            response.await.map_err(|_| Error::Stopped)?
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    /// Authenticate and connect to an explicit bootstrap peer.
    pub async fn connect(&self, address: Multiaddr) -> Result<(), Error> {
        self.request(|reply| Command::Connect(address, reply)).await
    }

    pub async fn bootstrap(&self) -> Result<(), Error> {
        self.request(Command::Bootstrap).await
    }

    /// Publish each signed offer under its exact key; requires one remote ACK
    /// per distinct offer. On failure, some records may already be stored.
    pub async fn publish(&self, card: &CapabilityCard) -> Result<(), Error> {
        for record in records_for(card)? {
            self.request(|reply| Command::Put(record, reply)).await?;
        }
        Ok(())
    }

    pub async fn resolve(&self, tag: &str, card_id: &str) -> Result<CapabilityCard, Error> {
        let key = crate::record::capability_key(tag, card_id)?;
        self.request(|reply| Command::Get(key, reply)).await
    }

    pub async fn stats(&self) -> Result<NodeStats, Error> {
        self.request(Command::Stats).await
    }

    pub async fn subscribe(&self, topic: TopicSpec) -> Result<bool, Error> {
        topic.name()?;
        self.request(|reply| Command::Subscribe(topic, reply)).await
    }
    pub async fn unsubscribe(&self, topic: TopicSpec) -> Result<bool, Error> {
        topic.name()?;
        self.request(|reply| Command::Unsubscribe(topic, reply))
            .await
    }
    /// Keep a validated local card for matching without broadcasting it.
    pub async fn register(&self, category: &str, card: Announcement) -> Result<(), Error> {
        self.request(|reply| Command::Register(category.into(), card, reply))
            .await
    }
    /// Queue a signed announcement to connected subscribers, then cache it
    /// locally. Success means queued, not remotely received or fulfilled.
    pub async fn announce(&self, category: &str, card: Announcement) -> Result<String, Error> {
        self.request(|reply| Command::Announce(category.into(), card, reply))
            .await
    }
    pub async fn known_cards(&self, category: &str) -> Result<GossipSnapshot, Error> {
        self.request(|reply| Command::Snapshot(category.into(), reply))
            .await
    }
    pub async fn matches(
        &self,
        category: &str,
        need_id: &str,
    ) -> Result<Vec<whn_core::matcher::MatchCandidate>, Error> {
        self.request(|reply| Command::Matches(category.into(), need_id.into(), reply))
            .await
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn network_error(err: impl std::fmt::Debug) -> Error {
    Error::Network(format!("{err:?}"))
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut commands: mpsc::Receiver<Command>,
    ready: Reply<Multiaddr>,
    subscription_limit: usize,
) {
    let mut ready = Some(ready);
    let mut pending = HashMap::<QueryId, Pending>::new();
    let mut connecting = HashMap::<PeerId, Vec<Reply<()>>>::new();
    let mut maintenance = time::interval(Duration::from_millis(250));
    let mut stats = NodeStats::default();
    let mut cache = GossipCache::default();
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break; };
                if pending.len() + connecting.values().map(Vec::len).sum::<usize>() >= MAX_PENDING {
                    reject_busy(command);
                    continue;
                }
                match command {
                    Command::Connect(mut address, reply) => {
                        let Some(Protocol::P2p(peer)) = address.pop() else {
                            let _ = reply.send(Err(Error::Configuration("dial address must end with /p2p/<PeerId>")));
                            continue;
                        };
                        if peer == *swarm.local_peer_id() {
                            let _ = reply.send(Err(Error::Configuration("cannot dial self")));
                            continue;
                        }
                        swarm.behaviour_mut().kad.add_address(&peer, address.clone());
                        if swarm.is_connected(&peer) {
                            let _ = reply.send(Ok(()));
                        } else if let Some(waiters) = connecting.get_mut(&peer) {
                            waiters.push(reply);
                        } else {
                            address.push(Protocol::P2p(peer));
                            match swarm.dial(address) {
                                Ok(()) => { connecting.insert(peer, vec![reply]); },
                                Err(err) => { let _ = reply.send(Err(network_error(err))); }
                            }
                        }
                    }
                    Command::Bootstrap(reply) => match swarm.behaviour_mut().kad.bootstrap() {
                        Ok(id) => { pending.insert(id, Pending::Bootstrap(reply)); },
                        Err(err) => { let _ = reply.send(Err(network_error(err))); }
                    },
                    Command::Put(record, reply) => {
                        if let Err(err) = validate_record(&record, unix_now()) {
                            let _ = reply.send(Err(err));
                            continue;
                        }
                        match swarm.behaviour_mut().kad.put_record(record, Quorum::One) {
                            Ok(id) => { pending.insert(id, Pending::Put(reply)); },
                            Err(err) => { let _ = reply.send(Err(network_error(err))); }
                        }
                    }
                    Command::Get(key, reply) => {
                        let id = swarm.behaviour_mut().kad.get_record(key.clone());
                        pending.insert(id, Pending::Get { key, reply });
                    }
                    Command::Stats(reply) => {
                        stats.connected_peers = swarm.connected_peers().count();
                        stats.stored_records = swarm.behaviour_mut().kad.store_mut().records().count();
                        cache.prune(unix_now());
                        stats.gossip_cached_cards = cache.len();
                        stats.gossip_subscriptions = swarm.behaviour().gossip.topics().count();
                        stats.gossip_subscribers.clear();
                        for (_, topics) in swarm.behaviour().gossip.all_peers() {
                            for topic in topics { *stats.gossip_subscribers.entry(topic.to_string()).or_default() += 1; }
                        }
                        let _ = reply.send(Ok(stats.clone()));
                    }
                    Command::Subscribe(spec, reply) => {
                        let result = spec.topic().and_then(|topic| {
                            let gossip = &mut swarm.behaviour_mut().gossip;
                            if gossip.topics().any(|known| *known == topic.hash()) { return Ok(false); }
                            if gossip.topics().count() >= subscription_limit { return Err(Error::SubscriptionLimit); }
                            gossip.subscribe(&topic).map_err(network_error)
                        });
                        let _ = reply.send(result);
                    }
                    Command::Unsubscribe(spec, reply) => {
                        let result = spec.topic().map(|topic| {
                            let removed = swarm.behaviour_mut().gossip.unsubscribe(&topic);
                            cache.unsubscribe(&spec);
                            removed
                        });
                        let _ = reply.send(result);
                    }
                    Command::Register(category, card, reply) => {
                        let _ = reply.send(cache.insert(&category, card, true, unix_now()));
                    }
                    Command::Announce(category, card, reply) => {
                        let result = (|| {
                            card.validate(unix_now())?;
                            let topic = card.topic(&category)?.topic()?;
                            cache.check_room(&category, &card, unix_now())?;
                            let message = swarm.behaviour_mut().gossip.publish(topic, card.payload()?).map_err(network_error)?;
                            cache.insert(&category, card, true, unix_now())?;
                            Ok(message.to_string())
                        })();
                        let _ = reply.send(result);
                    }
                    Command::Snapshot(category, reply) => { let _ = reply.send(cache.snapshot(&category, unix_now())); }
                    Command::Matches(category, need_id, reply) => { let _ = reply.send(cache.matches(&category, &need_id, unix_now())); }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if let Some(ready) = ready.take() { let _ = ready.send(Ok(address)); }
                }
                SwarmEvent::ListenerError { error, .. } => {
                    if let Some(ready) = ready.take() { let _ = ready.send(Err(network_error(error))); }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if let Some(waiters) = connecting.remove(&peer_id) {
                        for reply in waiters { let _ = reply.send(Ok(())); }
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), error, .. } => {
                    if let Some(waiters) = connecting.remove(&peer) {
                        for reply in waiters { let _ = reply.send(Err(network_error(&error))); }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    for address in info.listen_addrs.into_iter().take(8) {
                        swarm.behaviour_mut().kad.add_address(&peer_id, address);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, step, .. })) => {
                    handle_query(&mut swarm, &mut pending, &mut stats, id, result, step.last);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message { propagation_source, message_id, message })) => {
                    let accepted = (|| {
                        let spec = TopicSpec::parse(message.topic.as_str())?;
                        if !swarm.behaviour().gossip.topics().any(|topic| *topic == message.topic) {
                            return Err(Error::InvalidTopic);
                        }
                        let card = Announcement::from_wire(&spec, &message.data, unix_now())?;
                        cache.insert(&spec.category, card, false, unix_now())
                    })();
                    let acceptance = match accepted {
                        Ok(()) => { stats.gossip_accepted += 1; gossipsub::MessageAcceptance::Accept }
                        Err(Error::CacheFull) => { stats.gossip_ignored += 1; gossipsub::MessageAcceptance::Ignore }
                        Err(_) => { stats.gossip_rejected += 1; gossipsub::MessageAcceptance::Reject }
                    };
                    let _ = swarm.behaviour_mut().gossip.report_message_validation_result(&message_id, &propagation_source, acceptance);
                }
                _ => {}
            },
            _ = maintenance.tick() => {
                swarm.behaviour_mut().kad.store_mut().prune();
                cache.prune(unix_now());
                let cancelled: Vec<_> = pending.iter().filter(|(_, p)| p.is_closed()).map(|(id, _)| *id).collect();
                for id in cancelled {
                    pending.remove(&id);
                    if let Some(mut query) = swarm.behaviour_mut().kad.query_mut(&id) { query.finish(); }
                }
                connecting.retain(|_, waiters| {
                    waiters.retain(|reply| !reply.is_closed());
                    !waiters.is_empty()
                });
            }
        }
    }
}

fn reject_busy(command: Command) {
    match command {
        Command::Connect(_, reply) | Command::Bootstrap(reply) | Command::Put(_, reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
        Command::Get(_, reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
        Command::Stats(reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
        Command::Subscribe(_, reply) | Command::Unsubscribe(_, reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
        Command::Register(_, _, reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
        Command::Announce(_, _, reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
        Command::Snapshot(_, reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
        Command::Matches(_, _, reply) => {
            let _ = reply.send(Err(Error::Busy));
        }
    }
}

fn handle_query(
    swarm: &mut Swarm<Behaviour>,
    pending: &mut HashMap<QueryId, Pending>,
    stats: &mut NodeStats,
    id: QueryId,
    result: QueryResult,
    last: bool,
) {
    match result {
        QueryResult::RepublishRecord(result) => {
            if result.is_ok() {
                stats.republish_successes += 1;
            } else {
                stats.republish_failures += 1;
            }
        }
        QueryResult::PutRecord(result) => {
            if let Some(Pending::Put(reply)) = pending.remove(&id) {
                let _ = reply.send(result.map(|_| ()).map_err(network_error));
            }
        }
        QueryResult::Bootstrap(result) => {
            if (result.is_err() || last) && matches!(pending.get(&id), Some(Pending::Bootstrap(_)))
            {
                if let Some(Pending::Bootstrap(reply)) = pending.remove(&id) {
                    let _ = reply.send(result.map(|_| ()).map_err(network_error));
                }
            }
        }
        QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(record))) => {
            if let Some(Pending::Get { key, .. }) = pending.get(&id) {
                let card = if record.record.key == *key {
                    validate_record(&record.record, unix_now())
                } else {
                    Err(Error::RecordKeyMismatch)
                };
                if let Ok(card) = card {
                    if let Some(Pending::Get { reply, .. }) = pending.remove(&id) {
                        // Cache only a validated result; cache-capacity failure does not
                        // invalidate a successful remote lookup.
                        let _ = swarm.behaviour_mut().kad.store_mut().put(record.record);
                        let _ = reply.send(Ok(card));
                    }
                    if let Some(mut query) = swarm.behaviour_mut().kad.query_mut(&id) {
                        query.finish();
                    }
                } else if last {
                    if let Some(Pending::Get { reply, .. }) = pending.remove(&id) {
                        let _ = reply.send(Err(Error::NotFound));
                    }
                }
            }
        }
        QueryResult::GetRecord(_) if last => {
            if let Some(Pending::Get { reply, .. }) = pending.remove(&id) {
                let _ = reply.send(Err(Error::NotFound));
            }
        }
        _ => {}
    }
}
