# Distributed Authority Graph — Design

**Phase:** 4 (6–12 months)
**Status:** Design stub — not yet implemented.

---

## Problem

The current `OwnershipRegistry` is in-process and single-node. Multi-agent deployments
across separate processes, containers, or hosts require the authority graph to be
consistent across instances without a central coordinator becoming a single point of failure.

---

## Requirements

| Requirement | Description |
|---|---|
| R1: Partition tolerance | Authority graph must remain queryable under network partition |
| R2: Eventual consistency | Revocations propagate within a bounded window; no stale grants after TTL |
| R3: Monotonic claims | Claims only shrink (attenuation), never amplify, across sync |
| R4: Verifiable snapshots | Each node can produce a snapshot with a proof of validity |
| R5: No single coordinator | No node is a mandatory participant for every verify() call |

---

## Proposed Architecture

```
Node A (registry shard A)
  │  gossip protocol: claim delta + signature
  ▼
Node B (registry shard B)
  │  gossip protocol: revocation events + vector clock
  ▼
Node C (registry shard C)
```

Each node maintains:
- A local claim store (indexed, as in single-node registry)
- A vector clock for causal ordering
- A signed revocation log (append-only)
- A bloom filter for fast "is this claim revoked?" lookups

---

## Formal Properties Required

1. **Monotonic revocation**: Once revoked, a claim cannot be re-activated by gossip.
2. **Bounded staleness**: Any claim accepted by Node A but revoked on Node B becomes
   invalid on Node A within `max_sync_interval` time.
3. **Attenuation preservation**: Merging two registry shards never creates a claim
   wider than the narrowest original claim.

---

## Open Questions

- CRDTs vs consensus (Raft/Paxos) for revocation log?
- How to handle cross-shard delegation chains?
- What is the acceptable staleness window for security-critical deployments?

---

## Next Steps

1. Define the wire protocol for claim gossip
2. Prove monotonic revocation under gossip (CRDT model)
3. Implement a 2-node prototype with conflict test suite
