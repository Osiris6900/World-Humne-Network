# Run capability discovery

`whn-net` is the Phase 2 reference node. It runs a real libp2p TCP transport
with authenticated Noise, Yamux, Identify and a namespaced Kademlia DHT.
It has no central service or hardcoded public bootstrap node.

## Build and reproduce the local churn test

```sh
cargo test --locked --workspace --all-targets
cargo build --locked -p whn-net
python3 scripts/dht_smoke.py
```

The smoke test starts publisher A and replica B, publishes a signed two-offer
card, shuts A down, then starts C. C connects to B and resolves both offer keys.
It prints a JSON result including `independent_hosts: 1`. Three local processes
are useful integration coverage, not three independent hosts.

Rust integration tests also check expiry, automatic republishing, wrong-peer
Noise authentication, failed publication without peers, malicious DHT inserts,
forged lookup responses and validated result caching.

## CLI

```sh
mkdir -p node-keys
./target/debug/whn-net --listen /ip4/0.0.0.0/tcp/4001 --identity-file node-keys/a.key
```

The first output is a JSON `ready` event with the PeerID and dial address.
Without `--identity-file`, the identity is ephemeral. A new key file is created
with mode 0600 on Unix; an existing file must contain exactly 32 raw secret
bytes and must not be accessible to other users. The file is not encrypted.
Do not publish it. The DHT cache is in memory and is lost on restart.

The default listener is `/ip4/127.0.0.1/tcp/0`. For another machine, use an
explicit reachable IP/TCP listener. Replace `0.0.0.0` in an advertised address
with the machine's reachable IP. This version does not implement DNS dialing,
NAT traversal, relays, public bootstrap management or browser transports.

Send one JSON command per input line. Each produces one response; failures
return `{"ok":false,"error":"..."}` and keep the node running.

Connect using the full reachable address and expected PeerID:

```json
{"op":"connect","address":"/ip4/REACHABLE_PEER_IP/tcp/4001/p2p/PEER_ID"}
{"op":"bootstrap"}
```

Create a signed capability, using the current Unix time and a lifetime in seconds:

```json
{"op":"create","offers":["water","water/जल"],"ttl_seconds":3600,"region_hint":"IN-RJ","capacity_note":"पानी 💧"}
```

Copy the returned `card` object into a publish command:

```text
{"op":"publish","card":<entire card object from create>}
```

Another connected node can resolve it with the returned id:

```json
{"op":"resolve","tag":"water","card_id":"CARD_ID_FROM_CREATE"}
{"op":"stats"}
{"op":"shutdown"}
```

`create` signs only; `publish` writes the records. Publishing is successful only
after one remote Kademlia acknowledgement per distinct offer. That acknowledgement
does not prove a hostile peer will retain the data. A failed publication can leave
partial/local records; retrying the same immutable card is safe. Live locally held
publisher records are retried automatically by republishing, until signed expiry.

## Key and storage rules

Keys are `/whn/0.1/cap/<percent-encoded-offer>/<card-id>`. Ordinary `water`
stays `water`; `/` inside a tag becomes `%2F`. Resolution needs **both tag and id**.
Kademlia has no prefix scan, so this does not yet provide tag-only search.
Gossip/index discovery of candidate ids belongs to the next phase.

Each received record and lookup result must pass core schema, BLAKE3 id,
strict Ed25519 signature, signed expiry and key-to-offer/id binding checks.
Limits: 16 KiB/card, 32 offers, 128 UTF-8 bytes/tag, 1024 records/store, 128 pending
operations and a bounded command channel. DHT expiry cannot exceed signed expiry.
Records are pruned periodically and hidden from reads after expiry. Need,
attestation and provider records are not implemented by this store.
PoW and reputation-based rate limits remain future work.

Default record TTL is one hour; replicas are refreshed by replication every
minute and publisher republishing every five minutes. Target replication factor
is three. The API can configure these for tests; intervals must satisfy
`0 < replication < republish < record_ttl`, with TTL at most one year and query
timeout in `(0, 300s]`. Sparse networks may record automatic republish quorum
failures because the full three-copy target was not met, even with partial writes.
The metrics distinguish those from full-target successes.

## Independent-host acceptance run — pending

On two actual machines with mutually reachable TCP addresses:

1. Start replica B and publisher A. Record their machine identities, network
   locations, commit SHA, timestamps and explicit dial addresses.
2. Connect A to B, bootstrap, create and publish a live card on A. Save the
   complete signed card and responses. Resolve it on B.
3. Stop A. Restart A with an empty in-memory cache, connect to B, and resolve
   the old card by tag and id. The original publisher process must be absent;
   the result must come from B's retained replica. Optionally use a third
   independent machine C as the newcomer instead.
4. Repeat with expiry and network interruptions; retain outputs and elapsed
   times. Do not count the local smoke test as this evidence.

This gate has not been run here. Phase 2 issue #3 stays open until independent-host
churn evidence is recorded. Application matching/E2EE sessions, benchmarks,
Android battery measurements and external security review remain later gates.
