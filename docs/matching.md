# Gossip discovery and local matching

Nodes explicitly subscribe to `whn/0.1/need/<category>/<region>` or
`whn/0.1/cap/<category>/<region>`. Signed Need/Capability cards circulate through
GossipSub. Each node validates and caches cards, then computes candidates on its
own device. No central matcher is involved.

## Reproduce the local demonstration

```sh
cargo test --locked --workspace --all-targets
cargo build --locked -p whn-net
python3 scripts/matching_smoke.py
```

The script starts two local processes with different identities. Provider B
registers a `water` capability and subscribes to needs in `IN-RJ`. Requester A
subscribes to capabilities. B announces its capability; A announces a need.
Both nodes discover the expected candidate without a preconfigured capability
id. The output records the need id, candidate id, shared tags and score, with
`independent_hosts: 1` and receiver-confirmed delivery.

This is local integration evidence. Independent-machine demos are deferred;
Phase 3 issue #5 remains open. A candidate is not a completed or accepted match.
Application negotiation and actual fulfilment are not implemented. Signed
outcome claims and reputation-based candidate weights are described in
[ranking.md](ranking.md).

## CLI operations

Start nodes as described in [discovery.md](discovery.md). Add `--polite` to choose
the smaller mesh/subscription profile. Each command is one JSON input line;
responses are one JSON output line.

Subscribe before connecting, or subscribe on an already connected node:

```json
{"op":"subscribe","topic":{"kind":"need","category":"water","region":"IN-RJ"}}
{"op":"subscribe","topic":{"kind":"cap","category":"water","region":"IN-RJ"}}
```

Only explicitly subscribed topics are received. There are no automatic wildcard
subscriptions. The ten categories are `water`, `food`, `shelter`, `energy`,
`health`, `education`, `tools`, `transport`, `skills`, `compute`. A missing region
hint uses `global`; it is a literal topic, not an all-regions wildcard. To receive
other regions, subscribe to them explicitly.

Create a signed need (the existing `create` command creates capabilities):

```json
{"op":"create_need","needs":["water"],"urgency":4,"ttl_seconds":3600,"region_hint":"IN-RJ","note":"पानी चाहिए"}
```

Use the whole returned card object in the appropriate operation:

```text
{"op":"register_capability","category":"water","card":<capability card>}
{"op":"register_need","category":"water","card":<need card>}
{"op":"announce_capability","category":"water","card":<capability card>}
{"op":"announce_need","category":"water","card":<need card>}
```

Registration is local-only. Announcement queues the signed card for connected
subscribers and caches it locally on success. The returned `queued_message_id`
is not a delivery or fulfilment acknowledgement. With no subscribers, announcement
fails and does not register the card; use `register_*` when offline. Check the
`stats.gossip_subscribers` map before publishing, and confirm reception using
`known` on the receiver. Subscriptions propagate asynchronously after connecting.

```json
{"op":"known","category":"water"}
{"op":"matches","category":"water","need_id":"ID_FROM_KNOWN_OR_CREATE"}
{"op":"stats"}
{"op":"unsubscribe","topic":{"kind":"need","category":"water","region":"IN-RJ"}}
```

`known` returns live needs and capabilities in the chosen category. `matches`
compares a known need to live capabilities in that same category and returns at
most 100 candidates. Unsubscribe removes corresponding remote cached cards;
explicit local registrations stay until expiry. DHT `publish`/`resolve` remain
separate operations. Capability gossip supplies candidate ids/cards within active
topics; the DHT still does not support a global tag-prefix scan.

## Scoring and trust limits

Cards must have valid schema, ids, strict Ed25519 signatures and live expiry.
The matcher skips invalid capabilities and pairs with the same author public
key. It requires at least one exact shared tag; duplicates do not increase weight.
It does not infer that `drinking-water` matches `water-purifier`.

```text
tag_coverage = count(shared unique tags) / count(unique need tags)
region_affinity = 1.0 same hint, 0.6 same country prefix, 0.2 different, 0.4 missing
freshness = 1 / (1 + capability_age_seconds / 86400)
base_score = tag_coverage * (0.7 + 0.3 * region_affinity) * freshness
node_score = base_score * (0.1 + 0.9 * locally_derived_author_reputation)
```

Region is coarse self-declared text, not verified location or measured distance.
The pure core scorer keeps a neutral multiplier; the running node applies the
local reputation policy and removes locally quarantined capabilities. New
identities retain a 0.1 matching multiplier but zero attestation voting weight.
This is a candidate heuristic, not a verified trust claim. Urgency belongs to
the need and does not distinguish capabilities for that same need. Scores change
with time; ties at the same time break by capability id. No capacity amount is
inferred from free-text notes.

GossipSub envelopes are signed, but payload cards are independently verified
before acceptance/forwarding. Topic kind and region must match the signed card;
the category is explicit routing metadata, not authenticated card classification.
The cache is capped at 256 category/id entries and rejects new entries when full,
without evicting local registrations. Expired entries free space. Limits are
16 KiB/card, 32 tags/card, 128 bytes/tag; peer subscription requests and topic
counts are also bounded. This is not the later PoW/reputation rate-limit system.

Standard mode targets mesh size 6 with a 1-second heartbeat and 16 local topics.
Polite mode targets size 3 with a 3-second heartbeat and 4 local topics. These
settings reduce traffic budgets; battery/bandwidth benefits still need measurement.
Offline catch-up is not implemented: announcements missed while disconnected
require a later rebroadcast, DHT lookup of a known id, or future CRDT sync.
