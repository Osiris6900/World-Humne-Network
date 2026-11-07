//! Generate the published v0 JSON interoperability fixtures.
//! Run: cargo run --locked --quiet --example print_vectors

use serde_json::{json, Value};
use whn_core::card::{CapabilityCard, CapabilityDraft, NeedCard, NeedDraft};
use whn_core::crypto::Identity;

const T0: u64 = 1_730_000_000;
const T1: u64 = 1_732_600_000;

fn capability_vector(name: &str, card: CapabilityCard) -> Value {
    json!({
        "name": name,
        "id_payload_utf8": String::from_utf8(card.id_payload_bytes().unwrap()).unwrap(),
        "signing_payload_utf8": String::from_utf8(card.signing_payload_bytes().unwrap()).unwrap(),
        "card": card,
    })
}

fn need_vector(name: &str, card: NeedCard) -> Value {
    json!({
        "name": name,
        "id_payload_utf8": String::from_utf8(card.id_payload_bytes().unwrap()).unwrap(),
        "signing_payload_utf8": String::from_utf8(card.signing_payload_bytes().unwrap()).unwrap(),
        "card": card,
    })
}

fn main() {
    // Published secret for fixtures only; never use this identity on a real network.
    let identity = Identity::from_secret_bytes(&[7u8; 32]);
    let capability_minimal =
        CapabilityDraft::new(vec!["water-purifier".into(), "welding".into()], T0, T1)
            .sign(&identity)
            .unwrap();
    let mut cap = CapabilityDraft::new(vec!["water-purifier".into()], T0, T1);
    cap.region_hint = Some("IN-RJ".into());
    cap.capacity_note = Some("पानी 💧\n\"free\"\\shared\t\u{0001}".into());
    cap.contact_hint = Some("peer:example/जल".into());
    cap.pow_nonce = "42".into();

    let need_minimal = NeedDraft::new(vec!["drinking-water".into()], 1, T0, T1)
        .sign(&identity)
        .unwrap();
    let mut need = NeedDraft::new(
        vec!["drinking-water".into(), "solar-pump-repair".into()],
        5,
        T0,
        T1,
    );
    need.region_hint = Some("IN-RJ".into());
    need.note = Some("जल 💧\r\n\"urgent\"\\help\t\u{0000}".into());
    need.pow_nonce = "0007".into();

    // Exercise empty optionals and integers beyond JavaScript's safe-number range.
    let mut empty = NeedDraft::new(vec!["compute".into()], 3, 9_007_199_254_740_993, u64::MAX);
    empty.region_hint = Some(String::new());
    empty.note = Some(String::new());

    let out = json!({
        "profile": "whn-json-v0-field-order-1",
        "secret_key_hex_for_tests_only": "0707070707070707070707070707070707070707070707070707070707070707",
        "vectors": [
            capability_vector("capability_minimal", capability_minimal),
            capability_vector("capability_full_unicode", cap.sign(&identity).unwrap()),
            need_vector("need_minimal", need_minimal),
            need_vector("need_full_unicode", need.sign(&identity).unwrap()),
            need_vector("need_empty_optionals_large_timestamps", empty.sign(&identity).unwrap()),
        ],
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
