# Byzantine Fault Assumptions — Design

**Phase:** 4 (6–12 months)
**Status:** Design stub — not yet implemented.

---

## Problem

The current threat model assumes Adversary D (runtime compromise) requires OS-level access.
In a multi-node distributed deployment, a Byzantine node (one that deviates arbitrarily from
the protocol) must be considered.

---

## Byzantine Assumptions for This System

| Component | Byzantine assumption |
|---|---|
| Kernel instances | Each kernel is honest-but-potentially-compromised. A compromised kernel can emit false PERMITTED results, but the ed25519 signature allows detection by an external auditor. |
| Registry gossip nodes | Up to f < n/3 nodes may be Byzantine; requires BFT consensus (e.g. PBFT, HotStuff) for revocation log if f-Byzantine tolerance is required. |
| Human principals | Assumed non-Byzantine (out of threat model by design). A malicious principal is Adversary B (covered in THREAT_MODEL.md). |
| Attestation PKI | Assumed honest-but-failible. Compromise of the PKI is the fundamental TCB assumption. |

---

## Minimum Byzantine Tolerance for Revocation

To tolerate `f` Byzantine revocation nodes out of `n` total:
- Use BFT consensus with `n ≥ 3f + 1`
- Each revocation event requires signatures from `2f + 1` nodes

This is a significant operational burden. Deployments should assess whether f=0
(crash-fault tolerance only) is sufficient before implementing full BFT.

---

## Open Questions

- Is f=1 Byzantine tolerance sufficient for most deployments?
- Which BFT protocol fits the latency budget?
- How does Byzantine revocation interact with the existing audit log?
