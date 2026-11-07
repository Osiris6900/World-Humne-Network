//! Scoped topics, validated announcements and a bounded local matching cache.

use crate::{
    record::{capability_key, MAX_RECORD_BYTES},
    Error,
};
use libp2p::gossipsub::{self, IdentTopic, TopicHash, TopicSubscriptionFilter};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};
use whn_core::{
    card::{CapabilityCard, NeedCard},
    matcher::{rank_candidates, MatchCandidate},
};

pub const CATEGORIES: &[&str] = &[
    "water",
    "food",
    "shelter",
    "energy",
    "health",
    "education",
    "tools",
    "transport",
    "skills",
    "compute",
];
pub const MAX_CACHED_CARDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GossipProfile {
    #[default]
    Standard,
    Polite,
}

impl GossipProfile {
    pub fn subscription_limit(self) -> usize {
        match self {
            Self::Standard => 16,
            Self::Polite => 4,
        }
    }
    pub fn config(self) -> Result<gossipsub::Config, Error> {
        let mut config = gossipsub::ConfigBuilder::default();
        config
            .validation_mode(gossipsub::ValidationMode::Strict)
            .validate_messages()
            .max_transmit_size(18 * 1024)
            .max_messages_per_rpc(Some(16))
            .max_ihave_length(256)
            .max_ihave_messages(8);
        if self == Self::Polite {
            config
                .mesh_n(3)
                .mesh_n_low(2)
                .mesh_n_high(4)
                .mesh_outbound_min(1)
                .gossip_lazy(3)
                .heartbeat_interval(Duration::from_secs(3));
        }
        config
            .build()
            .map_err(|err| Error::Network(err.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopicKind {
    #[serde(rename = "need")]
    Need,
    #[serde(rename = "cap")]
    Capability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicSpec {
    pub kind: TopicKind,
    pub category: String,
    pub region: String,
}

pub fn validate_category(category: &str) -> Result<(), Error> {
    if CATEGORIES.contains(&category) {
        Ok(())
    } else {
        Err(Error::InvalidTopic)
    }
}

impl TopicSpec {
    pub fn new(kind: TopicKind, category: &str, region: &str) -> Result<Self, Error> {
        validate_category(category)?;
        let region_valid = region == "global"
            || (!region.is_empty()
                && region.len() <= 32
                && region.as_bytes()[0].is_ascii_uppercase()
                && region
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'));
        if !region_valid {
            return Err(Error::InvalidTopic);
        }
        Ok(Self {
            kind,
            category: category.into(),
            region: region.into(),
        })
    }

    pub fn parse(name: &str) -> Result<Self, Error> {
        let fields: Vec<_> = name.split('/').collect();
        if fields.len() != 5 || fields[0] != "whn" || fields[1] != "0.1" {
            return Err(Error::InvalidTopic);
        }
        let kind = match fields[2] {
            "need" => TopicKind::Need,
            "cap" => TopicKind::Capability,
            _ => return Err(Error::InvalidTopic),
        };
        Self::new(kind, fields[3], fields[4])
    }

    pub fn name(&self) -> Result<String, Error> {
        Self::new(self.kind, &self.category, &self.region)?;
        Ok(format!(
            "whn/0.1/{}/{}/{}",
            match self.kind {
                TopicKind::Need => "need",
                TopicKind::Capability => "cap",
            },
            self.category,
            self.region
        ))
    }
    pub fn topic(&self) -> Result<IdentTopic, Error> {
        Ok(IdentTopic::new(self.name()?))
    }
}

#[derive(Default)]
pub(crate) struct WhnSubscriptionFilter;
impl TopicSubscriptionFilter for WhnSubscriptionFilter {
    fn can_subscribe(&mut self, topic: &TopicHash) -> bool {
        TopicSpec::parse(topic.as_str()).is_ok()
    }
}

pub(crate) type SubscriptionFilter = gossipsub::MaxCountSubscriptionFilter<WhnSubscriptionFilter>;

#[derive(Debug, Clone)]
pub enum Announcement {
    Need(NeedCard),
    Capability(CapabilityCard),
}

impl Announcement {
    pub fn id(&self) -> &str {
        match self {
            Self::Need(c) => &c.id,
            Self::Capability(c) => &c.id,
        }
    }
    pub fn kind(&self) -> TopicKind {
        match self {
            Self::Need(_) => TopicKind::Need,
            Self::Capability(_) => TopicKind::Capability,
        }
    }
    pub fn region(&self) -> &str {
        match self {
            Self::Need(c) => c.region_hint.as_deref(),
            Self::Capability(c) => c.region_hint.as_deref(),
        }
        .unwrap_or("global")
    }
    pub fn expires_at(&self) -> u64 {
        match self {
            Self::Need(c) => c.expires_at,
            Self::Capability(c) => c.expires_at,
        }
    }
    pub fn payload(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            Self::Need(c) => serde_json::to_vec(c)?,
            Self::Capability(c) => serde_json::to_vec(c)?,
        })
    }
    pub fn topic(&self, category: &str) -> Result<TopicSpec, Error> {
        TopicSpec::new(self.kind(), category, self.region())
    }

    pub fn validate(&self, now: u64) -> Result<(), Error> {
        let tags = match self {
            Self::Need(c) => {
                c.verify_at(now)?;
                &c.needs
            }
            Self::Capability(c) => {
                c.verify_at(now)?;
                &c.offers
            }
        };
        if self.payload()?.len() > MAX_RECORD_BYTES {
            return Err(Error::RecordTooLarge);
        }
        if tags.len() > 32 {
            return Err(Error::InvalidAnnouncement("at most 32 tags are allowed"));
        }
        for tag in tags {
            capability_key(tag, self.id())?;
        }
        Ok(())
    }

    pub fn from_wire(topic: &TopicSpec, payload: &[u8], now: u64) -> Result<Self, Error> {
        topic.name()?;
        if payload.len() > MAX_RECORD_BYTES {
            return Err(Error::RecordTooLarge);
        }
        // Decode directly into the selected schema so duplicate/unknown fields
        // are rejected rather than silently erased by a generic JSON Value.
        let card = match topic.kind {
            TopicKind::Need => Self::Need(serde_json::from_slice(payload)?),
            TopicKind::Capability => Self::Capability(serde_json::from_slice(payload)?),
        };
        card.validate(now)?;
        if card.region() != topic.region {
            return Err(Error::InvalidAnnouncement(
                "topic region does not match signed region_hint",
            ));
        }
        Ok(card)
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GossipSnapshot {
    pub needs: Vec<NeedCard>,
    pub capabilities: Vec<CapabilityCard>,
}

struct CachedCard {
    card: Announcement,
    local: bool,
}

#[derive(Default)]
pub(crate) struct GossipCache {
    cards: BTreeMap<(String, String), CachedCard>,
}

impl GossipCache {
    pub(crate) fn prune(&mut self, now: u64) {
        self.cards.retain(|_, entry| now < entry.card.expires_at());
    }
    pub(crate) fn len(&self) -> usize {
        self.cards.len()
    }
    pub(crate) fn check_room(
        &mut self,
        category: &str,
        card: &Announcement,
        now: u64,
    ) -> Result<(), Error> {
        self.prune(now);
        if self.cards.len() >= MAX_CACHED_CARDS
            && !self
                .cards
                .contains_key(&(category.into(), card.id().into()))
        {
            return Err(Error::CacheFull);
        }
        Ok(())
    }
    pub(crate) fn insert(
        &mut self,
        category: &str,
        card: Announcement,
        local: bool,
        now: u64,
    ) -> Result<(), Error> {
        validate_category(category)?;
        card.validate(now)?;
        card.topic(category)?;
        self.check_room(category, &card, now)?;
        let key = (category.into(), card.id().into());
        let local = local || self.cards.get(&key).is_some_and(|entry| entry.local);
        self.cards.insert(key, CachedCard { card, local });
        Ok(())
    }
    pub(crate) fn unsubscribe(&mut self, topic: &TopicSpec) {
        self.cards.retain(|(category, _), entry| {
            entry.local
                || category != &topic.category
                || entry.card.kind() != topic.kind
                || entry.card.region() != topic.region
        });
    }
    pub(crate) fn snapshot(&mut self, category: &str, now: u64) -> Result<GossipSnapshot, Error> {
        validate_category(category)?;
        self.prune(now);
        let mut snapshot = GossipSnapshot::default();
        for ((scope, _), entry) in &self.cards {
            if scope != category {
                continue;
            }
            match &entry.card {
                Announcement::Need(c) => snapshot.needs.push(c.clone()),
                Announcement::Capability(c) => snapshot.capabilities.push(c.clone()),
            }
        }
        Ok(snapshot)
    }
    pub(crate) fn matches(
        &mut self,
        category: &str,
        need_id: &str,
        now: u64,
    ) -> Result<Vec<MatchCandidate>, Error> {
        let snapshot = self.snapshot(category, now)?;
        let need = snapshot
            .needs
            .iter()
            .find(|c| c.id == need_id)
            .ok_or(Error::NotFound)?;
        let mut result = rank_candidates(need, &snapshot.capabilities, now)?;
        result.truncate(100);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whn_core::{
        card::{CapabilityDraft, NeedDraft},
        crypto::Identity,
    };

    const NOW: u64 = 1_800_000_000;
    fn need() -> Announcement {
        Announcement::Need(
            NeedDraft::new(vec!["water".into()], 4, NOW, NOW + 30)
                .sign(&Identity::from_secret_bytes(&[1; 32]))
                .unwrap(),
        )
    }
    fn capability() -> Announcement {
        Announcement::Capability(
            CapabilityDraft::new(vec!["water".into()], NOW, NOW + 30)
                .sign(&Identity::from_secret_bytes(&[2; 32]))
                .unwrap(),
        )
    }

    #[test]
    fn topic_namespace_and_scope_are_strict() {
        for category in CATEGORIES {
            let topic = TopicSpec::new(TopicKind::Need, category, "IN-RJ").unwrap();
            assert_eq!(TopicSpec::parse(&topic.name().unwrap()).unwrap(), topic);
        }
        for name in [
            "whn/0.2/need/water/IN-RJ",
            "whn/0.1/rank/water/IN-RJ",
            "whn/0.1/need/money/IN-RJ",
            "whn/0.1/need/water/",
            "whn/0.1/need/water/IN/RJ",
            "whn/0.1/need/water/in-rj",
        ] {
            assert!(TopicSpec::parse(name).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn wire_validation_preserves_duplicate_and_unknown_field_rejection() {
        let topic = need().topic("water").unwrap();
        let payload = need().payload().unwrap();
        Announcement::from_wire(&topic, &payload, NOW).unwrap();
        let duplicate =
            String::from_utf8(payload.clone())
                .unwrap()
                .replacen('{', "{\"urgency\":4,", 1);
        assert!(Announcement::from_wire(&topic, duplicate.as_bytes(), NOW).is_err());
        let unknown = String::from_utf8(payload.clone()).unwrap().replacen(
            '{',
            "{\"unsigned_extra\":true,",
            1,
        );
        assert!(Announcement::from_wire(&topic, unknown.as_bytes(), NOW).is_err());
        assert!(Announcement::from_wire(&topic, &capability().payload().unwrap(), NOW).is_err());
        assert!(Announcement::from_wire(&topic, &payload, NOW + 30).is_err());
        assert!(Announcement::from_wire(&topic, &vec![0; MAX_RECORD_BYTES + 1], NOW).is_err());
        let wrong_region = TopicSpec::new(TopicKind::Need, "water", "IN-RJ").unwrap();
        assert!(Announcement::from_wire(&wrong_region, &payload, NOW).is_err());
    }

    #[test]
    fn cache_deduplicates_scopes_and_keeps_local_cards_on_unsubscribe() {
        let mut cache = GossipCache::default();
        let need = need();
        let cap = capability();
        cache.insert("water", cap.clone(), true, NOW).unwrap();
        cache.insert("water", need.clone(), false, NOW).unwrap();
        cache.insert("water", need.clone(), false, NOW).unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.matches("water", need.id(), NOW).unwrap().len(), 1);
        cache.insert("food", need.clone(), false, NOW).unwrap();
        assert!(cache.matches("food", need.id(), NOW).unwrap().is_empty());
        cache.unsubscribe(&need.topic("water").unwrap());
        assert!(cache.snapshot("water", NOW).unwrap().needs.is_empty());
        assert_eq!(cache.snapshot("water", NOW).unwrap().capabilities.len(), 1);
        cache.prune(NOW + 30);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_capacity_rejects_new_cards_without_evicting_existing_ones() {
        let mut cache = GossipCache::default();
        let identity = Identity::from_secret_bytes(&[2; 32]);
        for i in 0..MAX_CACHED_CARDS {
            let mut draft = CapabilityDraft::new(vec!["water".into()], NOW, NOW + 30);
            draft.pow_nonce = i.to_string();
            cache
                .insert(
                    "water",
                    Announcement::Capability(draft.sign(&identity).unwrap()),
                    true,
                    NOW,
                )
                .unwrap();
        }
        assert!(matches!(
            cache.insert("water", need(), false, NOW),
            Err(Error::CacheFull)
        ));
        assert_eq!(cache.len(), MAX_CACHED_CARDS);
        cache.prune(NOW + 30);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn polite_profile_reduces_mesh_heartbeat_and_subscription_budget() {
        let standard = GossipProfile::Standard.config().unwrap();
        let polite = GossipProfile::Polite.config().unwrap();
        assert!(polite.mesh_n() < standard.mesh_n());
        assert!(polite.heartbeat_interval() > standard.heartbeat_interval());
        assert!(
            GossipProfile::Polite.subscription_limit()
                < GossipProfile::Standard.subscription_limit()
        );
        assert!(standard.validate_messages() && polite.validate_messages());
    }
}
