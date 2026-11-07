"""Three local processes gossip claims and merge locally weighted rankings."""
import json
import sys
from pathlib import Path
from dht_smoke import Node
from matching_smoke import wait_for


def main():
    root = Path(__file__).resolve().parents[1]
    binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "target/debug/whn-net"
    nodes = []
    try:
        a = Node(binary)
        nodes.append(a)
        b = Node(binary)
        nodes.append(b)
        attestor = Node(binary)
        nodes.append(attestor)
        need_topic = {"kind": "need", "category": "water", "region": "IN-RJ"}
        rank_topic = {"kind": "rank", "category": "water", "region": "IN-RJ"}
        for node in (a, b):
            node.command(op="subscribe", topic=need_topic)
            node.command(op="subscribe", topic=rank_topic)
            node.command(op="trust", pubkey=attestor.ready["pubkey"], weight_millis=1000)
        attestor.command(op="connect", address=a.ready["address"])
        attestor.command(op="connect", address=b.ready["address"])
        a.command(op="connect", address=b.ready["address"])
        for name in ("whn/0.1/need/water/IN-RJ", "whn/0.1/rank/water/IN-RJ"):
            wait_for(lambda: attestor.command(op="stats")["stats"]["gossip_subscribers"].get(name, 0) >= 2, "both scoped subscribers")
        needs = []
        for label in ("verified", "plain", "flagged"):
            card = b.command(op="create_need", needs=["water"], urgency=4, ttl_seconds=120, region_hint="IN-RJ", note=label)["card"]
            needs.append(card)
            b.command(op="register_need", category="water", card=card)
            attestor.command(op="announce_need", category="water", card=card)
        for node in (a, b):
            wait_for(lambda: len(node.command(op="known", category="water")["cards"]["needs"]) == 3, "three live needs")
        for index, claim in ((0, "verified-real"), (2, "fraudulent")):
            evidence = attestor.command(op="create_attestation", target_card=needs[index]["id"], claim=claim)["attestation"]
            attestor.command(op="announce_attestation", category="water", attestation=evidence)
        for node in (a, b):
            wait_for(lambda: node.command(op="stats")["stats"]["ranking_attestations"] == 2, "both signed claims")
            ranks = node.command(op="rank", category="water", region="IN-RJ")["ranking"]
            if [entry["card_id"] for entry in ranks] != [card["id"] for card in needs]:
                raise RuntimeError(f"incorrect ranking: {ranks}")
            if not (ranks[0]["local_score"] > ranks[1]["local_score"] > ranks[2]["local_score"] and ranks[2]["quarantined"]):
                raise RuntimeError("verified/plain/flagged ordering failed")
        wait_for(lambda: b.command(op="stats")["stats"]["gossip_subscribers"].get("whn/0.1/rank/water/IN-RJ"), "ranking subscriber")
        b.command(op="announce_ranking", category="water", region="IN-RJ")
        ranks = wait_for(lambda: [row for row in a.command(op="rank", category="water", region="IN-RJ")["ranking"] if row["summary_weight"] > 0], "trusted summary merge")
        print(json.dumps({"result": "pass", "processes": 3, "independent_hosts": 1, "shared_explicit_anchor": attestor.ready["pubkey"], "verified_need": needs[0]["id"], "plain_need": needs[1]["id"], "flagged_need": needs[2]["id"], "both_nodes_agree_on_order": True, "summary_weight": ranks[0]["summary_weight"], "local_quarantine_preserved": True}, ensure_ascii=False))
    finally:
        for node in reversed(nodes):
            node.close()


if __name__ == "__main__":
    main()
