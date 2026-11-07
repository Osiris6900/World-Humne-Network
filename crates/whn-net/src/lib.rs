//! Authenticated TCP transport and validated capability-card discovery.

pub mod gossip;
mod node;
mod rank;
pub mod record;

pub use gossip::{Announcement, GossipProfile, GossipSnapshot, TopicKind, TopicSpec};
pub use libp2p::{Multiaddr, PeerId};
pub use node::{Node, NodeConfig, NodeStats};
pub use whn_core::{
    attestation::{Attestation, Claim},
    ranking::{RankedNeed, RankingPolicy, RankingSummary},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid topic category, kind, namespace or region")]
    InvalidTopic,
    #[error("invalid announcement: {0}")]
    InvalidAnnouncement(&'static str),
    #[error("local card cache is full")]
    CacheFull,
    #[error("subscription limit reached for this profile")]
    SubscriptionLimit,
    #[error(transparent)]
    Card(#[from] whn_core::error::WhnError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("tag must be nonblank and at most 128 UTF-8 bytes")]
    InvalidTag,
    #[error("card id must be 64 lowercase hex characters")]
    InvalidCardId,
    #[error("record exceeds 16 KiB")]
    RecordTooLarge,
    #[error("capability card exceeds 32 offers")]
    TooManyOffers,
    #[error("DHT key does not match the card id and one of its signed offers")]
    RecordKeyMismatch,
    #[error("invalid node configuration: {0}")]
    Configuration(&'static str),
    #[error("network operation failed: {0}")]
    Network(String),
    #[error("node is stopped")]
    Stopped,
    #[error("network operation timed out")]
    Timeout,
    #[error("too many pending operations")]
    Busy,
    #[error("record not found or no valid record returned")]
    NotFound,
}
