# Vision

> *"The greatest invention may not be a machine at all, but a network that connects need with available capacity."*

## The problem

The world does not lack things. It lacks **connections**.

- Enough food is grown to feed everyone — yet hunger persists, because production and need never meet.
- Water technology exists — rainwater harvesting, desalination, atmospheric generation — but it does not reach the places running dry.
- Countless inventions stall not for lack of brilliance, but because the right tool, the right expert, or the right backing sits unused three thousand kilometres away.

Scarcity is often a **discovery and coordination failure**, not a supply failure. Centralized platforms (marketplaces, gig apps) solved this by becoming the center — and then became the biggest extractors themselves. They own the match, the data, and the rules.

## The idea

A protocol — not a company — where:

1. **Anyone can declare capacity.** A signed Capability Card says: "I can offer X." Water purification. Welding. Python tutoring. A spare room. Truck space on Tuesdays.
2. **Anyone can broadcast a need.** A signed Need Card says: "I need Y." It circulates on topic channels to those who subscribed to exactly that kind of need.
3. **Matching happens at the edge.** Every node runs its own matcher against its own needs. There is no central order book to own, censor, or leak.
4. **Real needs rise by themselves.** Nodes attest to what they have verified. Attestation weight, decayed over time, aggregated through gossip, produces an emergent ranking — no trending server, no editorial hand.

## What makes it different

| Property | Central platforms | World-Humne-Network |
|---|---|---|
| Server | Required (theirs) | None — the network is the server |
| Trust | Platform reputation, locked in | Portable signed attestations |
| Ranking | Engagement-optimized | Attestation + time-decay, emergent |
| Data | Harvested centrally | Stays on the nodes; matching is local |
| Cost to join | Account, often payment | A keypair and a phone |

## Non-goals

- Not a payments platform (v1 carries no money; exchange terms are agreed peer-to-peer).
- Not a social network. Cards are about needs and capabilities, not feeds and followers.
- Not anonymous-by-default: identity is a stable keypair so reputation can accumulate. Privacy comes from what you *don't* reveal, not from being no one.

## Who it is for

The person whose need is real and whose money is short. The skilled person whose capacity sits idle. The inventor stuck for want of one tool. If the network works for the cheapest Android phone on a flaky connection, it works for everyone.
