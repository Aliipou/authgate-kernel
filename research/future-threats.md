# Future Threats — Architectural Assumptions and Their Failure Modes

**Branch:** spec-core  
**Purpose:** Every architectural axiom this system depends on, with the specific scenario that would invalidate it.

This document exists so that when reality contradicts one of these assumptions, we know exactly what breaks and what must change — without having to rewrite the philosophy.

---

## How to read this document

For each assumption:
- **Axiom** — the principle that is currently treated as foundational
- **Current enforcement** — how the codebase enforces it today
- **Invalidating scenario** — the concrete future that makes this assumption wrong
- **Failure mode** — what breaks in the system if the scenario occurs
- **Mitigation** — what would need to change in the implementation (not the axiom)
- **Status** — how confident we are this assumption holds for the next 5/10/20 years

The axioms themselves (Self-Ownership, Consent, Attenuation, Revocation, Exit, Auditability) are not in this document — they are in `freedom-specs-work/`. This document is about the **implementation assumptions** that could be invalidated while the axioms remain true.

---

## A1 — Actor → Capability → Resource model is sufficient

**Axiom this implements:**  
Authority must be explicit, scoped, and revocable.

**Current enforcement:**  
`engine.rs`: every action is typed as `(Actor, Resource, CapabilityKind)`. No authority exists outside this triple.

**Invalidating scenario:**  
Future agent systems use **goal markets** or **task auction** architectures where agents acquire authority through task completion, not delegation. Example:
```
Agent bids on task: "summarize /data/sales/"
System grants temporary authority upon bid acceptance
No human explicitly delegates — authority emerges from market mechanism
```
In this world, `actor → cap → resource` becomes too narrow: authority flows from competitive market dynamics, not from a delegation tree.

**Failure mode:**  
AuthGate becomes a bottleneck or is bypassed entirely because every market-granted authority would require manual registry updates. Systems that pre-grant authority at task-acceptance time would operate outside the kernel.

**Mitigation (if scenario occurs):**  
The capability model could be extended with **capability leases** that are issued by a smart contract or market oracle rather than a human principal. The TCB only needs to verify that a proof chain exists — it doesn't need to know whether the chain was created by human delegation or market mechanism, as long as the chain is signed and revocable.

**Status:** Low risk for 5 years. Medium risk for 10 years. High risk for 20 years.

---

## A2 — Resource ownership is the primary authority primitive

**Axiom this implements:**  
Self-ownership. You own what you own.

**Current enforcement:**  
`registry.py`: `OwnershipRegistry` maps `(actor, resource) → RightsClaim`. Ownership is the root.

**Invalidating scenario:**  
Agents operate in **shared-state architectures** where no single entity owns a resource. Examples:
- Distributed databases with no owner
- Shared AI model weights with collective governance
- Cloud storage with ambiguous ownership (S3 bucket with multiple equal admins)
- Global knowledge graphs with no ownership concept

In these architectures, the question "who owns this resource?" has no clean answer.

**Failure mode:**  
The trust root becomes undefined. Without a human owner as anchor, the `UNOWNED_MACHINE` check has nothing to enforce against. Authority chains cannot be constructed because there is no root.

**Mitigation (if scenario occurs):**  
Replace single-owner model with **quorum-based ownership** or **governance-based authority**. Instead of `Human → Machine` ownership chains, introduce `GovernanceGroup → Policy → Machine` chains. The TCB still only verifies that a valid proof chain exists — it does not need to know whether the root is a single human or a governance quorum.

**Status:** Low risk for 5 years (most resources still have owners). Medium risk for 10-15 years as multi-stakeholder AI systems grow.

---

## A3 — Authorization can be structurally separated from reasoning

**Axiom this implements:**  
Structural enforcement over semantics. The gate does not decide what is good — it decides who has authority.

**Current enforcement:**  
`engine.rs`: no natural language parsing, no intent scoring, no semantic interpretation. The kernel is purely structural.

**Invalidating scenario:**  
LLMs develop the capability to **self-authorize** by constructing capability proofs at inference time, or by manipulating the human operator into granting authority through psychological persuasion rather than deliberate delegation.

More concretely: an LLM that is sufficiently capable of reasoning about the authorization system could:
1. Construct valid-looking capability proof chains (if it has access to signing keys)
2. Generate human-plausible justifications that lead operators to grant excessive authority
3. Find semantic edge cases in policy definitions that technically permit actions not intended

**Failure mode:**  
The structural boundary holds but the semantic boundary is compromised upstream. The kernel correctly enforces what it is told — but what it is told is wrong because reasoning corrupted the input.

**Mitigation (if scenario occurs):**  
- Key isolation: signing keys must never be accessible to any agent (HSM or hardware enclave)
- Consent freshness: require human re-confirmation for high-risk capability grants, not just initial setup
- Rate-limiting delegation: structural limits on how fast authority can accumulate
- These are `extensions/` concerns, not TCB concerns. The TCB boundary is correct; the threat is above it.

**Status:** Medium risk now for key leakage. High risk in 5-10 years for semantic manipulation. The TCB is not the right place to address semantic manipulation — extensions (persuasion.py, anti_capture.py) exist for this.

---

## A4 — A single trust root per deployment is sufficient

**Axiom this implements:**  
All authority traces back to a sovereign human principal.

**Current enforcement:**  
`OwnershipRegistry`: every machine must have exactly one human owner. Chain validation in `dag.rs` traces to a root key.

**Invalidating scenario:**  
AuthGate is deployed as **shared infrastructure** across organizations. Multiple independent trust roots exist, and their authority claims can conflict or overlap:
- Company A grants Bot-X access to Resource-R
- Company B also has a claim on Resource-R
- Bot-X presents proof chains from both A and B — which takes precedence?

Or: a distributed deployment where multiple nodes each have their own trust root, and the roots disagree on the current epoch.

**Failure mode:**  
The single-root assumption breaks. The kernel either:
1. Rejects all multi-root actions (safe but too restrictive)
2. Accepts the first valid proof chain it finds (potentially dangerous — attacker injects a forged root)

**Mitigation (if scenario occurs):**  
- Federated roots with explicit trust policies (federation.py already exists as a prototype)
- Cross-root capability translation layer
- This is a Phase 4 problem (distributed authority systems) — do not introduce it into the TCB prematurely
- **Current document status:** `malicious trust root is out of scope` — this is correct and honest for now

**Status:** Low risk for single-org deployments (which is the current deployment model). Medium risk when AuthGate is used as shared infrastructure. This is the boundary where "production-grade single-org" ends and "global infrastructure" begins. Do not try to solve this before single-org is proven.

---

## A5 — Python layer and Rust TCB are semantically equivalent

**Axiom this implements:**  
The Python layer is a faithful mirror of the Rust TCB.

**Current enforcement:**  
Tests in `tests/` run against the Python layer. `_BACKEND = "python"` or `"rust"` depending on build. The Python layer is explicitly not formally verified.

**Invalidating scenario:**  
The Python and Rust implementations diverge silently in an edge case. A capability that the Rust TCB denies is permitted by the Python layer (or vice versa). Since most deployments use the Python layer, the formal guarantees of the Rust TCB are operationally irrelevant.

This is the most likely near-term failure mode and the most dangerous one because it is invisible.

**Failure mode:**  
`INCOMPLETENESS.md` is honest about this, but formal claims ("formally verified kernel") mislead users into assuming the Python layer has the same guarantees. An attacker who knows the system uses Python mode can exploit divergence edge cases.

**Mitigation (if scenario occurs):**  
- Differential fuzzing: systematically compare Python and Rust decisions across random inputs
- Property-based testing that targets edge cases in both layers simultaneously
- Deprecate the Python layer for any production enforcement path — use it as reference only
- Every formal claim must explicitly state "applies to engine.rs only"

**Current status:** This is not a future threat — it is a present gap. `INCOMPLETENESS.md` documents it. The simulation engine tests the Python layer only. Any formal verification claim must be scoped to the Rust TCB explicitly.

---

## A6 — Epoch-based revocation scales to real adversaries

**Axiom this implements:**  
Revocation must be structurally enforced, not just policy-expressed.

**Current enforcement:**  
`engine.rs`: `min_epoch` in every action. Capability proofs with `epoch < min_epoch` are rejected in O(1). Root-signed `RevocationProof` for single-proof emergency revocation.

**Invalidating scenario:**  
An adversary who controls the clock (or can delay epoch propagation in a distributed system) can replay stale proofs indefinitely. If the adversary can prevent `min_epoch` from being updated in the action construction layer, epoch-based revocation never fires.

More specifically:
- In a distributed deployment with multiple nodes, different nodes may have different epochs
- A compromised orchestration layer can set `min_epoch = 0` in every action
- Epoch rollback attacks (AT-3.1 in the attack tree) are partially closed but not fully

**Failure mode:**  
Revocation becomes advisory rather than structural. Proofs that should be invalidated continue to be accepted because the epoch gate is fed stale values.

**Mitigation (if scenario occurs):**  
- `min_epoch` must be supplied from a trusted, adversary-independent source (HSM, distributed consensus, signed timestamp)
- Clock integrity is a deployment concern — document explicitly in `DEPLOYMENT.md`
- Epoch synchronization protocol (Phase 4 distributed systems work)
- Current honest status: epoch integrity is the caller's responsibility — this is documented, not hidden

**Status:** Low risk for single-node deployments with trusted orchestration. Medium-to-high risk in multi-node deployments. Do not distribute before this is solved.

---

## A7 — Capability semantics remain stable over time

**Axiom this implements:**  
A capability that is granted means the same thing at execution time as it did at grant time.

**Current enforcement:**  
`capability.rs`: closed enum. No new capability kinds can be added without modifying the source. Semantic versioning in `SEMANTICS.md`.

**Invalidating scenario:**  
The meaning of `RIGHT_EXECUTE` changes across software versions. A capability proof signed under v1.0 semantics ("execute a WASM module") is used under v2.0 semantics ("execute a subprocess"). The proof is cryptographically valid but semantically wrong.

This is the **semantic drift** problem: valid proofs become dangerous over time as the system evolves.

**Failure mode:**  
Cryptographically valid proofs are accepted but their semantic interpretation has shifted. An attacker who obtained a proof under old semantics can use it in a context where the semantics grant more power than originally intended.

**Mitigation (if scenario occurs):**  
- Capability proofs must include a schema version
- Version upgrades require proof reissuance, not just code update
- Backward-incompatible semantic changes require deprecating old proofs
- `SEMANTICS.md` already exists for this purpose — extend it with proof versioning when breaking changes occur

**Status:** Low risk while the system is early-stage. Medium risk once there are real deployed proofs in the wild. This becomes important before v2.0.

---

## A8 — The TCB can be kept small as the ecosystem grows

**Axiom this implements:**  
Minimal trusted surface. Every line added to the TCB is presumed guilty.

**Current enforcement:**  
CI guard: `engine.rs` ≤ 300 LOC, `capability.rs` ≤ 200 LOC. `pub(crate)` visibility boundaries. Layered architecture: kernel / analysis / distributed / extensions.

**Invalidating scenario:**  
Adoption pressure creates a "just add one more thing" cycle. Each addition is locally justified:
- "We need consensus logic in the TCB for distributed deployments"
- "We need semantic parsing in the TCB for natural language actions"
- "We need ML-based anomaly detection in the TCB for better security"

After 10 such additions, the TCB is 5000 LOC and the formal guarantees are meaningless.

**Failure mode:**  
The TCB becomes unauditable. Kani and Lean4 can no longer cover it. Formal claims become marketing rather than engineering. The project becomes indistinguishable from the "AI safety" projects it was explicitly designed not to be.

**Mitigation (if scenario occurs):**  
This is not a future threat — it is a permanent design discipline challenge.
- The CI guard is the first line of defense
- Any feature that "needs to be in the TCB" should be questioned: can it be an adapter? an extension? a policy layer?
- The rule: if removing a feature from the TCB reduces security guarantees, it belongs there. If it only adds functionality, it does not.
- Governance of this rule is the hardest problem. There is no technical solution — only culture.

**Status:** Active risk at all times. The LOC ceiling is the only structural protection.

---

## Summary table

| Assumption | 5-year risk | 10-year risk | 20-year risk | Mitigation in-scope |
|------------|-------------|--------------|--------------|---------------------|
| A1: Actor→Cap→Resource | Low | Medium | High | Capability leases from market oracles |
| A2: Resource ownership | Low | Medium | High | Quorum/governance ownership |
| A3: Auth ≠ reasoning | Medium | High | High | Key isolation, not TCB change |
| A4: Single trust root | Low (single-org) | Medium | High | Federated roots (Phase 4) |
| A5: Python ≡ Rust | **Now** | **Now** | **Now** | Differential fuzzing, deprecate Python path |
| A6: Epoch integrity | Low (single-node) | Medium | High | Signed timestamps, consensus epoch |
| A7: Stable cap semantics | Low | Medium | Medium | Proof versioning before v2.0 |
| A8: TCB stays small | **Now** | **Now** | **Now** | LOC ceiling CI guard (structural) |

---

## What this document protects against

The purpose of this document is to prevent **axiom-implementation confusion**: treating a current engineering choice as a permanent philosophical truth.

AuthGate's axioms (Self-Ownership, Consent, Attenuation, Revocation, Exit, Auditability) are philosophical claims that do not depend on capability security being the correct implementation.

If any assumption above is invalidated:
- Change the implementation
- Keep the axioms
- Update this document

If an axiom itself is invalidated, that is a different kind of failure — and the right place to resolve it is `freedom-specs-work/`, not here.

---

*Last reviewed: 2026-05-29. Review when any assumption's risk level changes or a new architectural decision is made that introduces a new assumption.*
