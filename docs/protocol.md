# World-Humne-Network Protocol — Draft v0.1

Status: **draft; Phase 1 Rust core implemented with v0 JSON interoperability vectors.** Networking layers remain unimplemented. Language-neutral. Any client (Rust, Go, TypeScript, …) that satisfies this spec should be able to join the same network once those layers are built.

## 0. Layer overview

```
┌─────────────────────────────────────────────┐
│ 5. Application   local matcher, UI, ranking │
│ 4. Sync          CRDT card cache (offline)  │
│ 3. Discovery     DHT (capability lookup)    │
│ 2. Messaging     GossipSub need-topics      │
│ 1. Transport     P2P mesh (no central srv)  │
└─────────────────────────────────────────────┘
```

Layers 1–2 reuse mature libp2p building blocks. Layers 3–5 are defined here.

## 1. Identity

- Each node is an **Ed25519 keypair**. The public key (multihash-encoded) IS the identity (`PeerID`-compatible).
- Private keys never leave the device. There is no registration, no account server.
- Cards, attestations and revocations are signed with the node's private key. Verification requires only the public key carried in the object itself.

## 2. Core objects

All objects are canonical-CBOR (or canonical JSON for v0 interop testing) with a signature over the canonical bytes of every field except `signature`.

The current reference core uses the interim JSON profile documented in
[test-vectors/README.md](../test-vectors/README.md); canonical CBOR is not
implemented. For card ids, the canonical body excludes **both** `id` and
`signature`, avoiding a circular hash. Signing includes `id` and excludes only
`signature`. Field order, optional-field handling and string encoding are part
of that profile, not an unspecified JSON canonicalization convention.

### 2.1 Capability Card

```json
{
  "spec": "whn/0.1",
  "type": "capability",
  "id": "<blake3 of canonical body, hex>",
  "pubkey": "<ed25519 pubkey, base64url>",
  "offers": ["water-purifier", "welding"],
  "region_hint": "IN-RJ",
  "capacity_note": "free text, <= 280 chars",
  "contact_hint": "<optional reachability info>",
  "created_at": 1730000000,
  "expires_at": 1732600000,
  "pow_nonce": "<see §5>",
  "signature": "<ed25519 sig, base64url>"
}
```

### 2.2 Need Card

```json
{
  "spec": "whn/0.1",
  "type": "need",
  "id": "<blake3 of canonical body, hex>",
  "pubkey": "<ed25519 pubkey, base64url>",
  "needs": ["drinking-water", "solar-pump-repair"],
  "region_hint": "IN-RJ",
  "urgency": 4,
  "note": "free text, <= 280 chars",
  "created_at": 1730000000,
  "expires_at": 1732600000,
  "pow_nonce": "<see §5>",
  "signature": "<ed25519 sig, base64url>"
}
```

- `urgency`: integer 1–5, self-declared. Ranking may down-weight chronic max-urgency publishers (§6).
- `region_hint`: coarse, optional, self-chosen (ISO-3166-2 style). Never precise GPS by default.

#### v0 card validation

- `spec` must be `whn/0.1`; `type` must match the decoded card schema.
- `offers` / `needs` must contain at least one tag and no blank/whitespace-only tags.
- `note` / `capacity_note`, when present, are at most 280 Unicode scalar values
  (not bytes or grapheme clusters). No Unicode normalization is applied.
- `expires_at` must be greater than `created_at`; both are unsigned 64-bit Unix seconds.
- Unknown and duplicate JSON fields are rejected. Optional null fields are
  treated as absent; empty strings remain present and are signed.
- Live acceptance additionally rejects cards when `now >= expires_at`.
  The Rust API exposes this as `verify_at(now)`; `verify()` remains time-independent.
- Key/signature encodings are unpadded base64url. Ed25519 verification is strict,
  rejecting small-order public keys and signature points.

These checks do not yet implement PoW, rate limits or reputation. Region
format and future timestamp/clock-skew policy are not enforced in this core.

### 2.3 Attestation

```json
{
  "spec": "whn/0.1",
  "type": "attestation",
  "target_card": "<card id>",
  "claim": "fulfilled" | "verified-real" | "fraudulent",
  "attestor_pubkey": "<ed25519 pubkey>",
  "created_at": 1730000000,
  "signature": "<ed25519 sig>"
}
```

Attestations are the raw material of reputation. A `fraudulent` claim is a signed, public accusation — it costs the attestor reputation if contradicted by later attestations.

### 2.4 Revocation

A card author may revoke their own card by publishing a signed revocation object naming the card id. Revocations propagate on the same channels as cards and are kept in a CRDT grow-only set.

## 3. Discovery — DHT layout

Kademlia DHT keys:

```
/whn/0.1/cap/<offer-tag>/<card-id>     → Capability Card
/whn/0.1/need/<need-tag>/<card-id>     → Need Card (tombstoned on expiry)
/whn/0.1/att/<target-card-id>/<n>      → Attestations
```

- Nodes republish live cards before expiry; expired entries are dropped by stores.
- Lookup by tag returns a set; the local matcher filters and ranks.
- Records are self-certifying (signature + pubkey inside), so DHT stores cannot forge content.

## 4. Messaging — GossipSub topics

```
whn/0.1/need/<category>/<region>     need broadcast
whn/0.1/cap/<category>/<region>      capability announcements
whn/0.1/rank/<category>/<region>     ranking summaries (§6)
```

- Category taxonomy: small, versioned list in v0 (`water`, `food`, `shelter`, `energy`, `health`, `education`, `tools`, `transport`, `skills`, `compute`). Free tags allowed but canonical tags get the topics.
- Battery-constrained nodes MAY subscribe to few topics and lean on DHT pulls; relay-capable nodes SHOULD carry more.
- Polite mode: reduced fanout, longer heartbeat on mobile profiles.

## 5. Anti-spam

- **Proof-of-work per card:** `blake3(card_body || pow_nonce)` must have `d` leading zero bits. `d` is calibrated so a mid-range phone solves in ~2–5 s and adapts with observed network abuse.
- **Per-identity rate limits:** cards per hour scale with reputation; new identities start near zero.
- **Sybil resistance:** attestation weight is a function of the attestor's own received, non-reciprocal attestation graph depth. Fresh keypairs attest with ~zero weight.
- **Fraud path:** `fraudulent` attestations + revocation gossip quarantine bad cards quickly without any central moderator.

## 6. Ranking — "needs rise on their own"

Local score for a need card:

```
score(card) = urgency_prior
            × Σ_attestations  w(attestor) × decay(now - att.created_at)
            × freshness(now - card.created_at)
```

- `decay`: half-life ~7 days (configurable per category).
- `w(attestor)`: reputation weight from the attestation graph (§5).
- `urgency_prior`: tempered — chronic urgency-5 publishers regress toward the mean.
- **Gossip aggregation:** nodes periodically publish compact ranking summaries (top-k card ids + observed scores) on `whn/0.1/rank/...`. Receivers merge by weighted average. Global "what matters now" is emergent — computed by everyone, owned by no one.
- Ranking is always **scoped**: each node sees its own region/topics first. There is no single global leaderboard server.

## 7. Matching

Purely local:

1. Node pulls/subscribes to capability cards for its active need tags.
2. Matcher scores candidates: tag overlap, region proximity (coarse), counterparty reputation, freshness, capacity hints.
3. On a candidate match, the node opens a direct E2EE session to the counterparty (Noise handshake over the P2P transport). Negotiation content never touches the DHT or gossip.
4. Outcome → attestation (fulfilled / failed) feeds back into ranking.

## 8. Sync & offline

- Cards and attestations live in a local SQLite cache as CRDT state: grow-only sets for cards/attestations, last-writer-wins for mutable fields (none in v0 cards — cards are immutable; updates = new card + revocation).
- A node offline for days rejoins, exchanges CRDT digests with peers, and merges. Nothing central to catch up with.

## 9. Security notes

- Master private key only on the owner's device. No recovery service in v0 — document the trade-off.
- All gossip/DHT payloads are self-certifying; transport encryption is defense-in-depth, not the root of trust.
- Three local processes are NOT three independent hosts: multi-host validation is a release gate, not an assumption.

## 10. Open questions (v0.2)

- PoW function memory-hardness vs. low-end phones (Argon2-lite parameters?).
- Canonical tag governance: how do new categories ship without a center? (Signed tag-registry cards is the leading idea.)
- Browser client transport: WebRTC vs WebTransport reachability through symmetric NAT.
