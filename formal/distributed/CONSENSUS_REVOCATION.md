# Consensus-Backed Revocation — Design

**Phase:** 4 (6–12 months)
**Status:** Design stub — not yet implemented.

---

## Problem

In a distributed deployment, a revocation issued on Node A must be honored by Node B
before Node B issues a PERMITTED verdict for the revoked claim. Without consensus,
a revoked claim can still be exercised within the sync window.

---

## Options

### Option 1: Strong consistency (Raft/Paxos)

Every revocation is committed to a Raft log before taking effect. Verify() blocks
until the log is committed. Guarantees zero-window residual risk for revocations.

**Cost:** Latency per verify() increases to O(network round-trip). Availability
drops during leader election.

### Option 2: Optimistic consistency (TTL + gossip)

Claims carry a TTL. Revocation sets TTL = 0. Gossip propagates this within
`max_sync_interval`. Verify() uses local state — no blocking.

**Cost:** Claims can be exercised for up to `max_sync_interval` after revocation.
This is the current residual risk documented in THREAT_MODEL.md §5 ATK-005.

### Option 3: Hybrid (local verify + revocation fence)

Claims are verified locally. A separate revocation fence service is queried
only for high-risk capabilities (CREDENTIAL_READ, REGISTRY_MODIFY, POLICY_MODIFY).

**Cost:** Two round-trips for critical capabilities. Low latency for routine operations.

---

## Recommendation

Option 3 for production deployments with heterogeneous risk profiles.
Option 1 for high-security environments where latency is acceptable.
Option 2 for current single-node and development deployments.

---

## Open Questions

- What is the target max_sync_interval for regulated deployments?
- How does the revocation fence handle network partition?
- Should PERMITTED signatures carry a "revocation epoch" that expires them?
