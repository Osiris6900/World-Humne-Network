//! Print a golden test vector (fixed secret, fixed fields) as JSON.
//!
//! Other-language clients can sign the same payload and must produce
//! the identical `id` and `signature`. Run: `cargo run --example print_vectors`

use whn_core::card::{CapabilityDraft, NeedDraft};
use whn_core::crypto::Identity;

fn main() {
    // Fixed, published secret — test vector only, never for real identities.
    let identity = Identity::from_secret_bytes(&[7u8; 32]);

    let mut cap_draft = CapabilityDraft::new(
        vec!["water-purifier".into(), "welding".into()],
        1_730_000_000,
        1_732_600_000,
    );
    cap_draft.region_hint = Some("IN-RJ".into());
    let cap = cap_draft.sign(&identity).unwrap();

    let mut need_draft = NeedDraft::new(vec!["drinking-water".into()], 4, 1_730_000_000, 1_732_600_000);
    need_draft.region_hint = Some("IN-RJ".into());
    let need = need_draft.sign(&identity).unwrap();

    let out = serde_json::json!({
        "secret_key_hex_for_tests_only": "0707070707070707070707070707070707070707070707070707070707070707",
        "capability_card": cap,
        "need_card": need,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
