"""Independently reconstruct v0 JSON bytes, hash, sign and verify with Python."""

import base64
import json
from pathlib import Path

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def canonical_body(card, include_id):
    fields = ["spec", "type"] + (["id"] if include_id else []) + ["pubkey"]
    if card["type"] == "capability":
        fields += ["offers", "region_hint", "capacity_note", "contact_hint"]
    elif card["type"] == "need":
        fields += ["needs", "region_hint", "urgency", "note"]
    else:
        raise ValueError("unknown card type")
    fields += ["created_at", "expires_at", "pow_nonce"]
    body = {key: card[key] for key in fields if card.get(key) is not None}
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def check_equal(actual, expected, label):
    # Keep checks active even when Python runs with -O.
    if actual != expected:
        raise ValueError(f"vector mismatch: {label}")


def main():
    path = Path(__file__).resolve().parents[1] / "test-vectors/cards-v0.json"
    fixtures = json.loads(path.read_text(encoding="utf-8"))
    check_equal(fixtures["profile"], "whn-json-v0-field-order-1", "profile")
    identity = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixtures["secret_key_hex_for_tests_only"]))
    public_key = identity.public_key()
    for vector in fixtures["vectors"]:
        card = vector["card"]
        check_equal(b64(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)), card["pubkey"], "public key")
        id_body = canonical_body(card, include_id=False)
        signing_body = canonical_body(card, include_id=True)
        check_equal(id_body, vector["id_payload_utf8"].encode("utf-8"), "id bytes")
        check_equal(signing_body, vector["signing_payload_utf8"].encode("utf-8"), "signing bytes")
        check_equal(blake3(id_body).hexdigest(), card["id"], "BLAKE3 id")
        check_equal(b64(identity.sign(signing_body)), card["signature"], "Ed25519 signature")
        signature = base64.urlsafe_b64decode(card["signature"] + "==")
        public_key.verify(signature, signing_body)
        print(f"PASS {vector['name']}")
    print(f"Verified {len(fixtures['vectors'])} Rust vectors independently in Python.")


if __name__ == "__main__":
    main()
