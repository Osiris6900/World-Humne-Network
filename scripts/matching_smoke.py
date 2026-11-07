"""Two local processes discover and match signed cards over GossipSub."""

import json
import sys
import time
from pathlib import Path
from dht_smoke import Node


def wait_for(predicate, description):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {description}")


def main():
    root = Path(__file__).resolve().parents[1]
    binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "target/debug/whn-net"
    nodes = []
    try:
        requester = Node(binary)
        nodes.append(requester)
        provider = Node(binary)
        nodes.append(provider)
        need_topic = {"kind": "need", "category": "water", "region": "IN-RJ"}
        cap_topic = {"kind": "cap", "category": "water", "region": "IN-RJ"}
        provider.command(op="subscribe", topic=need_topic)
        requester.command(op="subscribe", topic=cap_topic)
        requester.command(op="connect", address=provider.ready["address"])
        wait_for(lambda: requester.command(op="stats")["stats"]["gossip_subscribers"].get("whn/0.1/need/water/IN-RJ"), "need subscriber")
        wait_for(lambda: provider.command(op="stats")["stats"]["gossip_subscribers"].get("whn/0.1/cap/water/IN-RJ"), "capability subscriber")
        cap = provider.command(op="create", offers=["water"], ttl_seconds=120, region_hint="IN-RJ", capacity_note="पानी 💧")['card']
        provider.command(op="register_capability", category="water", card=cap)
        provider.command(op="announce_capability", category="water", card=cap)
        wait_for(lambda: requester.command(op="known", category="water")["cards"]["capabilities"], "capability announcement")
        need = requester.command(op="create_need", needs=["water"], urgency=4, ttl_seconds=120, region_hint="IN-RJ")['card']
        requester.command(op="announce_need", category="water", card=need)
        wait_for(lambda: provider.command(op="known", category="water")["cards"]["needs"], "need announcement")
        candidates = provider.command(op="matches", category="water", need_id=need["id"])["candidates"]
        if len(candidates) != 1 or candidates[0]["capability_id"] != cap["id"]:
            raise RuntimeError(f"unexpected candidates: {candidates}")
        requester_candidates = requester.command(op="matches", category="water", need_id=need["id"])["candidates"]
        if len(requester_candidates) != 1 or requester_candidates[0]["capability_id"] != cap["id"]:
            raise RuntimeError("requester did not discover the same matching capability")
        print(json.dumps({"result": "pass", "processes": 2, "independent_hosts": 1, "discovery": "gossipsub", "need_id": need["id"], "candidate": candidates[0], "delivery_confirmed_by_receiver": True}, ensure_ascii=False))
    finally:
        for node in reversed(nodes):
            node.close()


if __name__ == "__main__":
    main()
