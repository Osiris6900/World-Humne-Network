//! DHT keys and a bounded store that never accepts unsigned or mis-keyed cards.

use std::{
    borrow::Cow,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use libp2p::{
    kad::{
        store::{self, MemoryStore, MemoryStoreConfig, RecordStore},
        ProviderRecord, Record, RecordKey,
    },
    PeerId,
};
use whn_core::card::CapabilityCard;

use crate::Error;

pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_OFFERS: usize = 32;
pub const MAX_TAG_BYTES: usize = 128;

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Tags use canonical percent-encoding of UTF-8 path segments.
pub fn capability_key(tag: &str, card_id: &str) -> Result<RecordKey, Error> {
    if tag.trim().is_empty() || tag.len() > MAX_TAG_BYTES {
        return Err(Error::InvalidTag);
    }
    if card_id.len() != 64
        || !card_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidCardId);
    }
    let mut encoded = String::new();
    for b in tag.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            encoded.push(b as char);
        } else {
            use std::fmt::Write;
            write!(&mut encoded, "%{b:02X}").expect("writing to a String cannot fail");
        }
    }
    Ok(RecordKey::new(&format!("/whn/0.1/cap/{encoded}/{card_id}")))
}

pub fn validate_record(record: &Record, now: u64) -> Result<CapabilityCard, Error> {
    if record.value.len() > MAX_RECORD_BYTES {
        return Err(Error::RecordTooLarge);
    }
    let card: CapabilityCard = serde_json::from_slice(&record.value)?;
    card.verify_at(now)?;
    if card.offers.len() > MAX_OFFERS {
        return Err(Error::TooManyOffers);
    }
    let keys = card
        .offers
        .iter()
        .map(|tag| capability_key(tag, &card.id))
        .collect::<Result<Vec<_>, _>>()?;
    if !keys.contains(&record.key) {
        return Err(Error::RecordKeyMismatch);
    }
    if record.is_expired(Instant::now()) {
        return Err(Error::Card(whn_core::error::WhnError::Expired));
    }
    Ok(card)
}

pub(crate) fn records_for(card: &CapabilityCard) -> Result<Vec<Record>, Error> {
    let value = serde_json::to_vec(card)?;
    let mut records = Vec::new();
    for tag in &card.offers {
        let record = Record::new(capability_key(tag, &card.id)?, value.clone());
        validate_record(&record, unix_now())?;
        if !records.iter().any(|r: &Record| r.key == record.key) {
            records.push(record);
        }
    }
    // Even a card with zero offers must go through the core validator.
    card.verify_at(unix_now())?;
    Ok(records)
}

/// All Kademlia inserts, including inbound RPCs and cached reads, pass here.
pub(crate) struct ValidatingStore {
    inner: MemoryStore,
}

impl ValidatingStore {
    pub(crate) fn new(peer: PeerId) -> Self {
        Self {
            inner: MemoryStore::with_config(
                peer,
                MemoryStoreConfig {
                    max_records: 1024,
                    max_value_bytes: MAX_RECORD_BYTES + 1,
                    ..Default::default()
                },
            ),
        }
    }

    pub(crate) fn prune(&mut self) {
        let now = Instant::now();
        self.inner.retain(|_, record| !record.is_expired(now));
    }
}

impl RecordStore for ValidatingStore {
    type RecordsIter<'a> = std::vec::IntoIter<Cow<'a, Record>>;
    type ProvidedIter<'a> = std::iter::Empty<Cow<'a, ProviderRecord>>;

    fn get(&self, key: &RecordKey) -> Option<Cow<'_, Record>> {
        self.inner
            .get(key)
            .filter(|r| validate_record(r, unix_now()).is_ok())
    }

    fn put(&mut self, mut record: Record) -> store::Result<()> {
        // The store trait has no invalid-record variant. Invalid records use
        // ValueTooLarge; the public API returns the detailed validation error.
        let now = unix_now();
        let card = validate_record(&record, now).map_err(|_| store::Error::ValueTooLarge)?;
        let wall_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let remaining = Duration::from_secs(card.expires_at)
            .checked_sub(wall_now)
            .ok_or(store::Error::ValueTooLarge)?;
        let signed_deadline = Instant::now()
            .checked_add(remaining)
            .ok_or(store::Error::ValueTooLarge)?;
        record.expires = Some(
            record
                .expires
                .map_or(signed_deadline, |deadline| deadline.min(signed_deadline)),
        );
        self.prune();
        self.inner.put(record)
    }

    fn remove(&mut self, key: &RecordKey) {
        self.inner.remove(key);
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        let now = unix_now();
        self.inner
            .records()
            // Recheck signed wall-clock expiry as well as the DHT deadline,
            // including after a wall-clock adjustment, before background jobs.
            .filter(|r| validate_record(r, now).is_ok())
            .collect::<Vec<_>>()
            .into_iter()
    }

    // Provider records are not signed card records and are not used in Phase 2.
    fn add_provider(&mut self, _: ProviderRecord) -> store::Result<()> {
        Err(store::Error::MaxProvidedKeys)
    }
    fn providers(&self, _: &RecordKey) -> Vec<ProviderRecord> {
        Vec::new()
    }
    fn provided(&self) -> Self::ProvidedIter<'_> {
        std::iter::empty()
    }
    fn remove_provider(&mut self, _: &RecordKey, _: &PeerId) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use whn_core::{card::CapabilityDraft, crypto::Identity};

    fn card() -> CapabilityCard {
        let now = unix_now();
        CapabilityDraft::new(vec!["water".into()], now, now + 60)
            .sign(&Identity::from_secret_bytes(&[7; 32]))
            .unwrap()
    }

    #[test]
    fn keys_encode_path_segments_without_collisions() {
        let id = "a".repeat(64);
        let key = capability_key("water/जल", &id).unwrap();
        assert_eq!(
            std::str::from_utf8(key.as_ref()).unwrap(),
            format!("/whn/0.1/cap/water%2F%E0%A4%9C%E0%A4%B2/{id}")
        );
        assert_ne!(
            capability_key("/", &id).unwrap(),
            capability_key("%2F", &id).unwrap()
        );
        assert!(capability_key("water", &"A".repeat(64)).is_err());
        assert!(capability_key(" ", &id).is_err());
        assert!(capability_key(&"x".repeat(129), &id).is_err());
    }

    #[test]
    fn invalid_records_never_enter_the_store() {
        let card = card();
        let good = records_for(&card).unwrap().remove(0);
        let mut wrong_key = good.clone();
        wrong_key.key = capability_key("food", &card.id).unwrap();
        let mut tampered = good.clone();
        let mut altered = card.clone();
        altered.offers = vec!["food".into()];
        tampered.value = serde_json::to_vec(&altered).unwrap();
        let mut unknown = good.clone();
        let mut value = serde_json::to_value(&card).unwrap();
        value["unsigned_extra"] = true.into();
        unknown.value = serde_json::to_vec(&value).unwrap();
        let mut oversized = good.clone();
        oversized.value = vec![b'x'; MAX_RECORD_BYTES + 1];
        let mut store = ValidatingStore::new(PeerId::random());
        for record in [wrong_key, tampered, unknown, oversized] {
            assert!(store.put(record).is_err());
        }
        assert_eq!(store.records().count(), 0);
        store.put(good.clone()).unwrap();
        assert_eq!(store.get(&good.key).unwrap().value, good.value);
    }

    #[test]
    fn expiry_is_bound_to_the_signed_card_and_pruned() {
        let card = card();
        let mut record = records_for(&card).unwrap().remove(0);
        assert!(validate_record(&record, card.expires_at).is_err());
        let mut store = ValidatingStore::new(PeerId::random());
        record.expires = Some(Instant::now() + Duration::from_secs(10000));
        store.put(record.clone()).unwrap();
        let stored = store.get(&record.key).unwrap().into_owned();
        assert!(stored.expires.unwrap() <= Instant::now() + Duration::from_secs(60));
        // Monotonic DHT TTL may be shorter than the signed card lifetime.
        store.inner.retain(|_, r| {
            r.expires = Some(Instant::now());
            true
        });
        assert!(store.get(&record.key).is_none());
        store.prune();
        assert_eq!(store.inner.records().count(), 0);
    }

    #[test]
    fn publishing_validates_all_offers_before_any_network_write() {
        let now = unix_now();
        let identity = Identity::generate();
        let card = CapabilityDraft::new(vec!["water".into(), "x".repeat(129)], now, now + 60)
            .sign(&identity)
            .unwrap();
        assert!(matches!(records_for(&card), Err(Error::InvalidTag)));
        let card = CapabilityDraft::new(vec!["water".into(); 33], now, now + 60)
            .sign(&identity)
            .unwrap();
        assert!(matches!(records_for(&card), Err(Error::TooManyOffers)));
        let card = CapabilityDraft::new(vec!["water".into(), "water".into()], now, now + 60)
            .sign(&identity)
            .unwrap();
        assert_eq!(records_for(&card).unwrap().len(), 1);
    }
}
