# Roadmap

Each phase is tracked as a GitHub issue. Phases are sequential in dependency, but later-phase design discussion can start any time.

## Phase 1 — Cards & signing
Define and implement Capability/Need card schema, canonical serialization, Ed25519 sign/verify, card ids (blake3). Golden test vectors so other-language clients can verify interop.
**Done when:** two independent implementations (or a Rust impl + test vectors) produce identical ids and verify each other's signatures.

## Phase 2 — DHT discovery
Publish/resolve capability cards on a Kademlia DHT under the `/whn/0.1/` key layout, with expiry and republish. Self-certifying record validation.
**Done when:** a card published by one host is retrievable by another host after churn (nodes leaving/joining).

## Phase 3 — Gossip topics + local matcher
Need-topics on GossipSub, subscription model, and the first end-to-end moment: a need card published on one host surfaces as a match candidate on another host's local matcher.
**Done when:** the first recorded match demo on two independent machines.

## Phase 4 — Attestation & ranking
Attestation objects, reputation weighting, time-decay scoring, ranking-summary gossip. Fraudulent-claim path.
**Done when:** in a multi-host testnet, an attested need outranks an unattested one on all honest nodes, and a fraud-flagged card sinks.

## Phase 5 — Sync & anti-spam
CRDT cache + digest sync, per-card PoW, per-identity rate limits, revocation propagation.
**Done when:** a node offline 48h resyncs fully; a flood attempt from fresh identities is throttled without affecting established nodes.

## Phase 6 — Release gates
- Multi-host (2-host, then 3-host, independent machines) E2EE match runs — local processes do not count as independent hosts.
- Benchmarks: time-to-match, match success rate, search recall under 100-node churn, battery/bandwidth budget on Android.
- External security review of the protocol and reference implementation.
**Done when:** all gates pass and results are published in the repo.

## After v1
- TypeScript browser client (zero-install join via WebRTC/WebTransport).
- Signed tag-registry for category governance.
- Optional hosted convenience services (relay hosting) — protocol stays free.
