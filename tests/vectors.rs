use serde_json::Value;
use whn_core::card::{CapabilityCard, NeedCard};

#[test]
fn published_vectors_fix_exact_payloads_ids_and_signatures() {
    let fixture: Value =
        serde_json::from_str(include_str!("../test-vectors/cards-v0.json")).unwrap();
    assert_eq!(fixture["profile"], "whn-json-v0-field-order-1");
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);
    for vector in vectors {
        let wire = vector["card"].clone();
        let (id_bytes, sign_bytes) = match wire["type"].as_str().unwrap() {
            "capability" => {
                let card: CapabilityCard = serde_json::from_value(wire).unwrap();
                card.verify().unwrap();
                (
                    card.id_payload_bytes().unwrap(),
                    card.signing_payload_bytes().unwrap(),
                )
            }
            "need" => {
                let card: NeedCard = serde_json::from_value(wire).unwrap();
                card.verify().unwrap();
                (
                    card.id_payload_bytes().unwrap(),
                    card.signing_payload_bytes().unwrap(),
                )
            }
            _ => panic!("unsupported vector type"),
        };
        assert_eq!(
            id_bytes,
            vector["id_payload_utf8"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            sign_bytes,
            vector["signing_payload_utf8"].as_str().unwrap().as_bytes()
        );
    }
}
