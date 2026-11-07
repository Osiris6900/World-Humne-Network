use whn_core::card::{CapabilityDraft, NeedDraft};
use whn_core::crypto::Identity;

const T0: u64 = 1_730_000_000;
const T1: u64 = 1_732_600_000;

fn fixed_identity() -> Identity {
    Identity::from_secret_bytes(&[7u8; 32])
}

#[test]
fn capability_sign_and_verify() {
    let id = fixed_identity();
    let card = CapabilityDraft::new(vec!["water-purifier".into(), "welding".into()], T0, T1)
        .sign(&id)
        .unwrap();
    card.verify().unwrap();
    assert!(!card.is_expired(T0 + 10));
    assert!(card.is_expired(T1));
}

#[test]
fn need_sign_and_verify() {
    let id = fixed_identity();
    let card = NeedDraft::new(vec!["drinking-water".into()], 4, T0, T1)
        .sign(&id)
        .unwrap();
    card.verify().unwrap();
}

#[test]
fn signing_is_deterministic() {
    // Same secret + same fields must always produce the same id and signature.
    // This is the property cross-language test vectors rely on.
    let build = || {
        CapabilityDraft::new(vec!["water-purifier".into(), "welding".into()], T0, T1)
            .sign(&fixed_identity())
            .unwrap()
    };
    let (a, b) = (build(), build());
    assert_eq!(a.id, b.id);
    assert_eq!(a.signature, b.signature);
    assert_eq!(a.pubkey, b.pubkey);
}

#[test]
fn tampering_breaks_verification() {
    let id = fixed_identity();
    let mut card = CapabilityDraft::new(vec!["water-purifier".into()], T0, T1)
        .sign(&id)
        .unwrap();
    card.offers.push("free-money".into());
    assert!(card.verify().is_err());
}

#[test]
fn forged_signature_fails() {
    let alice = fixed_identity();
    let mallory = Identity::generate();
    let mut card = NeedDraft::new(vec!["solar-pump-repair".into()], 3, T0, T1)
        .sign(&alice)
        .unwrap();
    // Mallory re-signs content that still carries Alice's pubkey.
    card.signature = mallory.sign(b"whatever");
    assert!(card.verify().is_err());
}

#[test]
fn urgency_bounds_enforced() {
    let id = fixed_identity();
    assert!(NeedDraft::new(vec!["x".into()], 0, T0, T1)
        .sign(&id)
        .is_err());
    assert!(NeedDraft::new(vec!["x".into()], 6, T0, T1)
        .sign(&id)
        .is_err());
    assert!(NeedDraft::new(vec!["x".into()], 5, T0, T1)
        .sign(&id)
        .is_ok());
}
