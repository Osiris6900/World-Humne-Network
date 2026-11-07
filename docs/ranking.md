# Signed claims and locally weighted ranking

The node now gossips attestations and ranking summaries on
`whn/0.1/rank/<category>/<region>`. Each node selects its own trust policy and
computes scores from signed evidence. A signature proves who made a claim;
it does not prove that a need is real, fulfilled or fraudulent.

## Run the local demo

```sh
cargo test --locked --workspace --all-targets
cargo build --locked -p whn-net
python3 scripts/ranking_smoke.py
```

Three local processes exchange three live needs and two signed claims. Two
viewers explicitly select the same attestor as a local trust anchor. They both
rank the verified need above the unattested need and the flagged need below it.
A compatible signed summary is then merged using the publisher's locally
derived weight. Output records `independent_hosts: 1`; multi-host validation
remains deferred and issue #6 stays open.

## Local trust and CLI

There are **no default trust anchors**. With none configured, needs retain a small
baseline and fresh identities' attestation votes have zero weight. You may still
discover matching candidates. A trust anchor is a local operator decision, not
an account, global authority or key endorsed automatically by peers.

The `ready` event exposes the node's public key as `pubkey`. Choose a key you
intend to trust and configure it on each viewer (1000 means weight 1; 0 removes):

```text
{"op":"trust","pubkey":"PUBLIC_ED25519_KEY_BASE64URL","weight_millis":1000}
{"op":"subscribe","topic":{"kind":"rank","category":"water","region":"IN-RJ"}}
```

Use the need/capability subscriptions and registration commands from
[matching.md](matching.md) so the target card is known first. Create a claim:

```text
{"op":"create_attestation","target_card":"KNOWN_CARD_ID","claim":"verified-real"}
{"op":"register_attestation","category":"water","attestation":<returned signed object>}
{"op":"announce_attestation","category":"water","attestation":<returned signed object>}
{"op":"rank","category":"water","region":"IN-RJ"}
{"op":"announce_ranking","category":"water","region":"IN-RJ"}
```

Other claims are `fulfilled` and `fraudulent`. Register is local-only; announce
queues the object to connected subscribers, then retains it locally on success.
Queue success is not a remote delivery acknowledgement. Unknown targets cannot
be scoped, so incoming claims about them are ignored and must be rebroadcast
after the card is discovered. Self-attestations and claims predating their card
are rejected. The category remains caller-selected routing metadata; region is
bound to the signed target's hint.

The newest timestamp per signer/target wins. At equal timestamps, conflicting
claims choose fraudulent, then fulfilled, then verified-real. Replays do not add
votes. Local explicit claims survive rank-topic unsubscribe; remote claims and
summaries for that topic are dropped. Runtime evidence and trust configuration
are in memory; restart persistence/CRDT synchronization is future work.

## Reputation and scores

Positive claims create directed edges from attestor to the signed card author.
Self and reciprocal edges are removed. Starting at local anchors, propagation
walks outward in deterministic breadth-first layers. Each source distributes
at most half its current mass across distinct, previously unreached recipients.
Multiple cards by the same author cannot multiply one edge. Edge strength
decays; dividing by `max(1, sum(outgoing_strengths))` conserves the per-hop budget
even with many newly minted recipients. Disconnected identities start at zero.

This is a bounded experimental model, not proof of human identity or complete
Sybil resistance. Trust choices, incomplete evidence, partitions and clocks can
produce different local rankings. Evidence signatures and archived target proofs
remain checked independently of gossip transport signatures.

For a live need, with latest weighted evidence per signer:

```text
decay(age) = 2 ^ (-age_seconds / half_life_seconds)
verified_weight = sum(reputation(attestor) * decay(attestation_age)) for verified-real
fraudulent_weight = same for fraudulent
fulfilled_weight = same for fulfilled
prior = 1 + (urgency - 1) * 0.25
local_score = prior * decay(need_age)
              * (0.05 + verified_weight - 2 * fraudulent_weight)
              / (1 + 2 * fulfilled_weight)
```

If fraudulent weight exceeds verified weight, local score is capped below zero
and `quarantined` is true. Fulfilment reduces active priority rather than making
an already fulfilled need more urgent. Scores are bounded to ±64 and ties break
by card id. Urgency has a bounded prior, not a chronic-publisher history model.
Automatic penalties for false accusations/adjudication are not implemented.

The matcher applies `0.1 + 0.9 * reputation(author)` to its base score and omits
locally quarantined capabilities. This matching floor keeps new people discoverable;
it does not give them attestation voting weight. Reputation is computed within
the candidate's category/region. Remote summary hints cannot manufacture author
reputation or lift local quarantine.

## Summary gossip

Nodes automatically publish local top-32 scores on explicitly subscribed rank
topics every 30 seconds (90 in polite mode), or on `announce_ranking`. Automatic
messages never feed aggregated peer hints back as fresh local evidence.

Each signed summary includes its scope and a policy fingerprint. The fingerprint
hashes algorithm profile `whn-rank-v0-1`, policy fields in their declared order,
and the locally selected anchors sorted by public key, with integer weights in
thousandths. Compatible summaries expire after five minutes by default. There
is at most one latest summary per publisher/scope, with a deterministic signature
tie-break at equal timestamps.

For each known live need, the node merges its local score (weight 1) with peer
scores weighted by locally derived publisher reputation. An untrusted fresh key
has no vote, repeated packets do not add votes, and its own replayed summary is
excluded. A locally quarantined need can only stay at or below its local score.
Summaries are signed bounded opinions, not independently proven fulfilment facts.
Valid summaries with a different policy may be forwarded but are not local votes.

## Wire profile and limits

Signing uses compact, ordered UTF-8 JSON as in the card profile. All strings use
the same escaping rules, and signatures are strict Ed25519, unpadded base64url.

- Attestation signing order: `spec`, `type`, `target_card`, `claim`,
  `attestor_pubkey`, `created_at`. The derived local id is BLAKE3 of these bytes.
- Summary order: `spec`, `type`, `category`, `region`, `policy_id`,
  `publisher_pubkey`, `created_at`, `entries`. Type is `ranking-summary`.
- Each entry orders `card_id`, `score_micros`. Scores are signed integer
  millionths in `[-64000000, 64000000]`; repeated ids are invalid. No floats are
  signed on the wire. `signature` is excluded from both signing payloads.
- Policy fingerprint input orders `profile`, `policy`, `anchors`. Policy fields
  order `half_life_secs`, `max_evidence_age_secs`, `max_depth`,
  `hop_discount_millis`, `summary_ttl_secs`, `max_future_skew_secs`.

Defaults are seven-day half-life, 30-day evidence retention, depth 4, 0.5 hop
discount, five-minute summary TTL and up to 300 seconds future clock skew.
The API's `RankingPolicy` supports bounded configuration; CLI supports
`--ranking-half-life-seconds` and `--rank-gossip-seconds`.

Caches hold at most 1024 latest claims, 256 distinct signed historical target
proofs, 128 peer summaries and 16 local anchors. Rank messages are at most 16 KiB,
summaries at most 32 entries. Expired live cards stop ranking, while referenced
signed proofs preserve earned reputation until their evidence ages out. Unknown
target/order recovery, durable storage, PoW and identity rate limits remain
future work. See [fixed vectors](../test-vectors/README.md) for independent
Rust/Python signing checks.
