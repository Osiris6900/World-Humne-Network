//! Print fixed signed attestation/summary fixtures for cross-language clients.
use serde_json::json;
use whn_core::{
    attestation::{Attestation, Claim},
    crypto::Identity,
    ranking::{RankingPolicy, RankingSummary, SummaryEntry, TrustAnchors},
};

fn main() {
    let identity = Identity::from_secret_bytes(&[9; 32]);
    let attestation = Attestation::sign(
        &"a".repeat(64),
        Claim::VerifiedReal,
        1_800_000_000,
        &identity,
    )
    .unwrap();
    let policy = RankingPolicy::default();
    let mut anchors = TrustAnchors::default();
    anchors.set(&identity.public_key_b64(), 1000).unwrap();
    let summary = RankingSummary::sign(
        "water",
        "IN-RJ",
        &policy.fingerprint(&anchors).unwrap(),
        vec![
            SummaryEntry {
                card_id: "a".repeat(64),
                score_micros: 1_050_000,
            },
            SummaryEntry {
                card_id: "b".repeat(64),
                score_micros: -1_950_000,
            },
        ],
        1_800_000_000,
        &identity,
    )
    .unwrap();
    let out = json!({
        "profile": "whn-rank-json-v0-field-order-1",
        "secret_key_hex_for_tests_only": "0909090909090909090909090909090909090909090909090909090909090909",
        "policy": policy,
        "anchors_millis": {identity.public_key_b64(): 1000},
        "attestation": attestation,
        "attestation_id": attestation.id().unwrap(),
        "attestation_signing_payload_utf8": String::from_utf8(attestation.signing_payload_bytes().unwrap()).unwrap(),
        "summary": summary,
        "summary_signing_payload_utf8": String::from_utf8(summary.signing_payload_bytes().unwrap()).unwrap(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
