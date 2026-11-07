# World-Humne-Network

> **"What do you need, or what can you offer?"**

A decentralized, serverless network that connects **need** with **available capacity** — no VPS, no central server, no gatekeeper.

Where water is needed, water-making or water-carrying capacity connects. Where food is short, production and supply connect. Where an invention is stuck, knowledge, tools and people connect.

Most scarcity in the world is not a supply problem — it is a **matching problem**. World-Humne-Network is an open protocol that lets any node:

- **Advertise capability** — signed Capability Cards announce what you can offer.
- **Broadcast needs** — signed Need Cards circulate on topic channels.
- **Match locally** — every node matches needs to capabilities on its own device. No central matcher, no data harvest.
- **Surface what matters** — attestation-weighted, time-decayed ranking emerges from the swarm. Real needs rise on their own.

## Design principles

1. **No central server, ever.** The network itself is the database (DHT), the message bus (gossip) and the search engine (local matching).
2. **Self-sustaining.** Nodes keep each other alive — peer caches, relay failover, NAT traversal. No one rents a machine to belong.
3. **Trust without a center.** Identity = keypair. Reputation = signed attestations from other nodes, weighted and decayed. No KYC, no accounts.
4. **Phone-first.** Built for real devices on real networks — battery, bandwidth and churn are first-class constraints.
5. **Open protocol, many clients.** The spec is language-neutral. Reference core in Rust; browser client (zero-install) in TypeScript.

## Status

Phase 1 reference core is implemented in Rust: Capability/Need cards,
Ed25519 signing, BLAKE3 ids, schema validation and published v0 JSON vectors.
The vectors are independently checked in Python. DHT discovery, P2P transport,
gossip, matching, ranking and offline sync are not implemented yet.

- [docs/vision.md](docs/vision.md) — why this exists
- [docs/protocol.md](docs/protocol.md) — draft protocol specification (v0.1)
- [docs/roadmap.md](docs/roadmap.md) — build phases and release gates
- [test-vectors/README.md](test-vectors/README.md) — exact JSON bytes and cross-language verification

## Build and verify

```sh
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/requirements-interop.txt
.venv/bin/python scripts/verify_vectors.py
```

Use `card.verify_at(unix_seconds)` when accepting a live card; `card.verify()`
checks schema, id and signature without a wall clock, for archival verification.
Neither method checks proof-of-work or reputation; those belong to later phases.

## License

[AGPL-3.0](LICENSE) — if you run a modified version as a network service, you must share your source. Open stays open.
