"""Independent Python checks for the fixed ranking object signing profile."""
import base64
import json
from pathlib import Path
from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from verify_vectors import b64, check_equal


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def main():
    fixture = json.loads((Path(__file__).resolve().parents[1] / "test-vectors/ranking-v0.json").read_text(encoding="utf-8"))
    check_equal(fixture["profile"], "whn-rank-json-v0-field-order-1", "profile")
    identity = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixture["secret_key_hex_for_tests_only"]))
    public = identity.public_key()
    key = b64(public.public_bytes(Encoding.Raw, PublicFormat.Raw))
    policy_fields = ["half_life_secs", "max_evidence_age_secs", "max_depth", "hop_discount_millis", "summary_ttl_secs", "max_future_skew_secs"]
    policy_body = {"profile": "whn-rank-v0-1", "policy": {name: fixture["policy"][name] for name in policy_fields}, "anchors": dict(sorted(fixture["anchors_millis"].items()))}
    check_equal(blake3(canonical(policy_body)).hexdigest(), fixture["summary"]["policy_id"], "policy fingerprint")
    profiles = [
        ("attestation", ["spec", "type", "target_card", "claim", "attestor_pubkey", "created_at"], "attestor_pubkey"),
        ("summary", ["spec", "type", "category", "region", "policy_id", "publisher_pubkey", "created_at", "entries"], "publisher_pubkey"),
    ]
    for name, fields, pubkey_field in profiles:
        obj = fixture[name]
        body = {field: obj[field] for field in fields}
        if name == "summary":
            body["entries"] = [{"card_id": entry["card_id"], "score_micros": entry["score_micros"]} for entry in obj["entries"]]
        payload = canonical(body)
        check_equal(key, obj[pubkey_field], f"{name} public key")
        check_equal(payload, fixture[name + "_signing_payload_utf8"].encode("utf-8"), f"{name} bytes")
        check_equal(b64(identity.sign(payload)), obj["signature"], f"{name} signature")
        public.verify(base64.urlsafe_b64decode(obj["signature"] + "=="), payload)
        if name == "attestation":
            check_equal(blake3(payload).hexdigest(), fixture["attestation_id"], "attestation id")
        print(f"PASS {name} canonical bytes and Ed25519 signature")
    print("PASS policy fingerprint")


if __name__ == "__main__":
    main()
