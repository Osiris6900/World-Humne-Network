# v0 JSON card interoperability

`cards-v0.json` fixes five Capability/Need cards with expected public keys,
ids, signatures and the exact UTF-8 payload strings used for hashing/signing.
The published secret (`07` repeated 32 times) is test data only.

## Profile: `whn-json-v0-field-order-1`

This interim JSON profile preserves the original Rust v0 payload format.
It is neither RFC 8785 JSON canonicalization nor canonical CBOR.

1. Build the id body in this exact field order, omitting absent optional fields:
   - Capability: `spec`, `type`, `pubkey`, `offers`, `region_hint`,
     `capacity_note`, `contact_hint`, `created_at`, `expires_at`, `pow_nonce`.
   - Need: `spec`, `type`, `pubkey`, `needs`, `region_hint`, `urgency`,
     `note`, `created_at`, `expires_at`, `pow_nonce`.
2. Encode as compact JSON, UTF-8, no BOM, whitespace or trailing newline.
   Preserve array order. Do not sort keys or normalize Unicode.
   Null optionals are omitted; empty strings are included.
3. Strings escape quotes and backslashes, and use `\b`, `\t`, `\n`, `\f`,
   `\r` for their corresponding control characters. Other U+0000–U+001F
   characters use lowercase `\u00xx`. All other Unicode characters are literal
   UTF-8, including non-ASCII text; `/` is not escaped.
4. Integers use unsigned decimal notation, no fractions or exponents.
   Timestamps may span the full `u64` range. JavaScript clients must preserve
   these integers exactly using an appropriate parser, not round them through `Number`.
5. `id` is lowercase hex BLAKE3 of the id-body bytes (no `id` or `signature`).
6. The signing body has the same order, with `id` inserted immediately after
   `type`. Ed25519 signs these bytes directly, without a prehash.
   Keys (32 bytes) and signatures (64 bytes) use unpadded base64url.

The full `card` objects in the fixture are pretty-printed with sorted keys for
readability. Do not hash that display representation; reconstruct the payload
as above or inspect `id_payload_utf8` / `signing_payload_utf8`.
Input JSON key order does not matter when decoding a card.

## Verify independently

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/requirements-interop.txt
.venv/bin/python scripts/verify_vectors.py
```

The Python script reconstructs bytes independently, checks BLAKE3 ids, derives
the expected public key and signs/verifies through OpenSSL-backed `cryptography`.
It checks Rust/Python interoperability for these fixtures; it is not a complete
Python network client or a security review.

Rust regression tests load the fixed fixture and verify payloads/signatures:

```sh
cargo test --locked --all-targets
```

To check regeneration without replacing the baseline:

```sh
cargo run --locked --quiet --example print_vectors > /tmp/cards-v0.json
diff -u test-vectors/cards-v0.json /tmp/cards-v0.json
```

CI runs both implementations and the regeneration comparison. Fixture changes
require explicit review as protocol compatibility changes.
