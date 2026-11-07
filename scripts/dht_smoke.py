"""Three local processes over real TCP/Noise; not independent-host validation."""

import json
import queue
import subprocess
import sys
import threading
from pathlib import Path


class Node:
    def __init__(self, binary):
        self.process = subprocess.Popen(
            [str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=None, text=True, encoding="utf-8",
        )
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self.read_lines, daemon=True)
        self.reader.start()
        try:
            self.ready = self.receive()
            if self.ready.get("event") != "ready":
                raise RuntimeError(f"node did not start: {self.ready}")
        except Exception:
            self.process.kill()
            self.process.wait(timeout=5)
            self.reader.join(timeout=1)
            self.process.stdin.close()
            self.process.stdout.close()
            raise

    def read_lines(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def receive(self):
        line = self.lines.get(timeout=50)
        if line is None:
            raise RuntimeError(f"node exited: {self.process.poll()}")
        return json.loads(line)

    def command(self, **command):
        self.process.stdin.write(json.dumps(command, ensure_ascii=False) + "\n")
        self.process.stdin.flush()
        result = self.receive()
        if not result.get("ok"):
            raise RuntimeError(f"{command['op']} failed: {result}")
        return result

    def close(self):
        if self.process.poll() is None:
            try:
                self.command(op="shutdown")
                self.process.wait(timeout=5)
            finally:
                if self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=5)
        self.process.stdin.close()
        self.reader.join(timeout=1)
        self.process.stdout.close()


def main():
    root = Path(__file__).resolve().parents[1]
    binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "target/debug/whn-net"
    nodes = []
    try:
        publisher = Node(binary)
        nodes.append(publisher)
        replica = Node(binary)
        nodes.append(replica)
        publisher.command(op="connect", address=replica.ready["address"])
        publisher.command(op="bootstrap")
        card = publisher.command(op="create", offers=["water", "water/जल"], ttl_seconds=120, capacity_note="पानी 💧")['card']
        publisher.command(op="publish", card=card)
        if replica.command(op="stats")["stats"]["stored_records"] != 2:
            raise RuntimeError("replica did not store both signed offer records")
        publisher.close()
        newcomer = Node(binary)
        nodes.append(newcomer)
        newcomer.command(op="connect", address=replica.ready["address"])
        for tag in card["offers"]:
            resolved = newcomer.command(op="resolve", tag=tag, card_id=card["id"])["card"]
            if resolved != card:
                raise RuntimeError("resolved card differs from the publisher's signed card")
        print(json.dumps({
            "result": "pass", "transport": "tcp-noise-yamux",
            "processes": 3, "independent_hosts": 1,
            "publisher_stopped_before_newcomer_started": True,
            "resolved_offers": card["offers"], "card_id": card["id"],
        }, ensure_ascii=False))
    finally:
        for node in reversed(nodes):
            node.close()


if __name__ == "__main__":
    main()
