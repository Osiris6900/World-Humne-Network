use serde_json::{json, Value};
use whn_core::card::{CapabilityCard, CapabilityDraft, NeedCard, NeedDraft};
use whn_core::crypto::Identity;
use whn_core::error::WhnError;

const T0: u64 = 1_730_000_000;
const T1: u64 = T0 + 100;

fn identity() -> Identity {
    Identity::from_secret_bytes(&[7; 32])
}

fn capability() -> CapabilityCard {
    CapabilityDraft::new(vec!["water".into()], T0, T1)
        .sign(&identity())
        .unwrap()
}

fn need() -> NeedCard {
    NeedDraft::new(vec!["water".into()], 4, T0, T1)
        .sign(&identity())
        .unwrap()
}

fn assert_schema_error(result: Result<(), WhnError>, field: &str) {
    let err = result.unwrap_err();
    let expected = match field {
        "spec" => matches!(err, WhnError::UnsupportedSpec(_)),
        "type" => matches!(err, WhnError::WrongCardType { .. }),
        "urgency" => matches!(err, WhnError::BadUrgency(_)),
        "offers" | "needs" => matches!(err, WhnError::InvalidTags(_)),
        "capacity_note" | "note" => matches!(err, WhnError::NoteTooLong(_)),
        "expires_at" => matches!(err, WhnError::InvalidValidityPeriod),
        _ => panic!("unknown test field"),
    };
    assert!(expected, "unexpected error for {field}: {err:?}");
}

#[test]
fn signed_invalid_capability_cards_are_rejected_on_receive() {
    let valid = serde_json::to_value(capability()).unwrap();
    let cases = [
        ("spec", json!("whn/99")),
        ("type", json!("need")),
        ("offers", json!([])),
        ("offers", json!(["water", " \t"])),
        ("capacity_note", json!("💧".repeat(281))),
        ("expires_at", json!(T0)),
        ("expires_at", json!(T0 - 1)),
    ];
    for (field, value) in cases {
        let mut wire = valid.clone();
        wire[field] = value;
        let mut card: CapabilityCard = serde_json::from_value(wire).unwrap();
        // Model an author who signs invalid content, rather than a damaged signature.
        card.id = blake3::hash(&card.id_payload_bytes().unwrap())
            .to_hex()
            .to_string();
        card.signature = identity().sign(&card.signing_payload_bytes().unwrap());
        assert_schema_error(card.verify(), field);
    }
}

#[test]
fn signed_invalid_need_cards_are_rejected_on_receive() {
    let valid = serde_json::to_value(need()).unwrap();
    let cases = [
        ("spec", json!("whn/99")),
        ("type", json!("capability")),
        ("needs", json!([])),
        ("needs", json!([""])),
        ("urgency", json!(0)),
        ("urgency", json!(6)),
        ("note", json!("💧".repeat(281))),
        ("expires_at", json!(T0)),
        ("expires_at", json!(T0 - 1)),
    ];
    for (field, value) in cases {
        let mut wire = valid.clone();
        wire[field] = value;
        let mut card: NeedCard = serde_json::from_value(wire).unwrap();
        card.id = blake3::hash(&card.id_payload_bytes().unwrap())
            .to_hex()
            .to_string();
        card.signature = identity().sign(&card.signing_payload_bytes().unwrap());
        assert_schema_error(card.verify(), field);
    }
}

#[test]
fn invalid_drafts_cannot_be_signed() {
    for tags in [
        vec![],
        vec![String::new()],
        vec!["water".into(), " \n".into()],
    ] {
        assert!(matches!(
            CapabilityDraft::new(tags.clone(), T0, T1).sign(&identity()),
            Err(WhnError::InvalidTags("offers"))
        ));
        assert!(matches!(
            NeedDraft::new(tags, 1, T0, T1).sign(&identity()),
            Err(WhnError::InvalidTags("needs"))
        ));
    }
    for expiry in [T0, T0 - 1] {
        assert!(matches!(
            CapabilityDraft::new(vec!["water".into()], T0, expiry).sign(&identity()),
            Err(WhnError::InvalidValidityPeriod)
        ));
        assert!(matches!(
            NeedDraft::new(vec!["water".into()], 1, T0, expiry).sign(&identity()),
            Err(WhnError::InvalidValidityPeriod)
        ));
    }
}

#[test]
fn note_limits_count_unicode_scalars_instead_of_bytes() {
    for length in [0, 280, 281] {
        let mut cap = CapabilityDraft::new(vec!["water".into()], T0, T1);
        cap.capacity_note = Some("💧".repeat(length));
        let mut need = NeedDraft::new(vec!["water".into()], 1, T0, T1);
        need.note = Some("💧".repeat(length));
        if length <= 280 {
            cap.sign(&identity()).unwrap().verify().unwrap();
            need.sign(&identity()).unwrap().verify().unwrap();
        } else {
            assert!(matches!(
                cap.sign(&identity()),
                Err(WhnError::NoteTooLong("capacity_note"))
            ));
            assert!(matches!(
                need.sign(&identity()),
                Err(WhnError::NoteTooLong("note"))
            ));
        }
    }
}

#[test]
fn live_verification_rejects_cards_exactly_at_expiry() {
    let cap = capability();
    let need = need();
    cap.verify_at(T1 - 1).unwrap();
    need.verify_at(T1 - 1).unwrap();
    for now in [T1, T1 + 1] {
        assert!(matches!(cap.verify_at(now), Err(WhnError::Expired)));
        assert!(matches!(need.verify_at(now), Err(WhnError::Expired)));
    }
    // Archival verification deliberately does not read the system clock.
    cap.verify().unwrap();
    need.verify().unwrap();
}

#[test]
fn unsupported_and_duplicate_wire_fields_are_rejected() {
    let mut cap = serde_json::to_value(capability()).unwrap();
    cap["unsigned_extension"] = json!(true);
    assert!(serde_json::from_value::<CapabilityCard>(cap).is_err());
    let mut wire_need = serde_json::to_value(need()).unwrap();
    wire_need["unsigned_extension"] = json!(true);
    assert!(serde_json::from_value::<NeedCard>(wire_need).is_err());
    let cap =
        serde_json::to_string(&capability())
            .unwrap()
            .replacen('{', "{\"spec\":\"whn/0.1\",", 1);
    assert!(serde_json::from_str::<CapabilityCard>(&cap).is_err());
    let need = serde_json::to_string(&need())
        .unwrap()
        .replacen('{', "{\"urgency\":4,", 1);
    assert!(serde_json::from_str::<NeedCard>(&need).is_err());
}

#[test]
fn null_optionals_and_reordered_wire_keys_preserve_canonical_bytes() {
    let cap = capability();
    let mut wire = serde_json::to_value(&cap).unwrap();
    wire["region_hint"] = Value::Null;
    wire["capacity_note"] = Value::Null;
    wire["contact_hint"] = Value::Null;
    let decoded: CapabilityCard = serde_json::from_value(wire).unwrap();
    assert_eq!(cap, decoded);
    decoded.verify().unwrap();

    let card = need();
    let mut wire = serde_json::to_value(&card).unwrap();
    wire["region_hint"] = Value::Null;
    wire["note"] = Value::Null;
    let decoded: NeedCard = serde_json::from_value(wire).unwrap();
    assert_eq!(card, decoded);
    decoded.verify().unwrap();
}
