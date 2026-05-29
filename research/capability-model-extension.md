# Capability Model Extension — Surviving Goal Markets and Reputation Systems

**Branch:** spec-core  
**Threat addressed:** A1 from future-threats.md  
**Question:** If the world moves to Goal Markets / Reputation Systems / Economic Contracts / Multi-Agent Swarms, does AuthGate break?

---

## The specific threat

Today's model:
```
Human  →  delegates  →  Machine  →  requests  →  Resource
           RightsClaim                Action
```

Possible future model (Goal Markets):
```
Task posted → Agents bid → Winner gets temporary authority → Executes → Authority expires
```

Possible future model (Reputation Systems):
```
Agent earns reputation → Reputation grants access scope → No explicit delegation
```

Possible future model (Economic Contracts):
```
Agent holds token → Token grants right → Right expires when token transferred
```

In all three futures, the `Actor → Capability → Resource` model has the same structure — but the **source of capability proofs** changes. Instead of a human signing a delegation, a market, contract, or reputation system signs it.

**The good news:** the TCB itself does not need to change.

---

## Why the TCB survives

The Rust TCB (`engine.rs`) does exactly one thing:

```
verify(action, root_key, now) → Decision
```

It checks:
1. Binding hash intact (IR not tampered)
2. Capability proof chain valid (signatures, epochs, attenuation)
3. Required rights ≤ granted rights

**None of these checks care where the capability proof came from.**

A capability proof signed by a smart contract is structurally identical to one signed by a human. The TCB just checks that the signature is valid and the chain is intact.

---

## What changes and what doesn't

| Component | Changes? | Notes |
|-----------|----------|-------|
| `engine.rs` / TCB | No | Verifies proofs regardless of their origin |
| `capability.rs` / RightsClaim | No | Same capability kinds |
| `dag.rs` / delegation chain | No | Chain validation is source-agnostic |
| **Trust root** | **Yes** | Currently: human pubkey. Future: smart contract address, DAO vote, reputation oracle |
| **Capability issuance** | **Yes** | Currently: human signs `RightsClaim`. Future: market oracle signs lease |
| **Revocation** | **Possibly** | Currently: epoch + RevocationProof. Future: token burn or contract state |

**The TCB boundary is the right boundary.** The parts that need to change are all *outside* the TCB.

---

## Extension design: Authority Source Adapters

Instead of hard-coding "humans sign capabilities," introduce an `AuthoritySource` abstraction:

```
AuthoritySource (interface)
  ├── HumanDelegation       ← current model (OwnershipRegistry)
  ├── MarketOracle          ← goal market grants temporary leases
  ├── ReputationGate        ← reputation threshold → access scope
  └── SmartContract         ← token holding → capability proof
```

Each `AuthoritySource` produces a signed `CapabilityProof` (or a chain of them). The TCB receives and verifies those proofs — it doesn't know or care which source produced them.

```
GoalMarket
  ↓  task won, lease issued
MarketOracle.sign(CapabilityProof {
    subject: winning_agent_id,
    resource: task_target,
    rights: RIGHTS_EXECUTE,
    expiry: now + 3600,   // 1-hour lease
    epoch: current_epoch,
})
  ↓  proof passed to agent
Agent constructs CanonicalAction with proof
  ↓
CallGate.execute(action) → engine::verify(action, oracle_pubkey, now) → Permit
```

The only change to the TCB: `root_key` becomes "the issuer's pubkey" rather than "Alice's pubkey." The verification logic is identical.

---

## Extension design: Reputation-based capability

Reputation systems are more complex because reputation is continuous, not binary. The extension:

```
ReputationGate:
  score ≥ threshold → issue CapabilityProof (valid for N minutes)
  score < threshold → deny issuance

The TCB receives the issued proof (normal proof chain).
The TCB does NOT receive the reputation score — it never sees heuristics.
```

This preserves the core invariant: **the TCB only evaluates typed authority constraints, never scores or heuristics.** The reputation system is an `AuthoritySource` adapter, not a TCB component.

---

## Extension design: Multi-Agent Swarms

Swarms introduce a new challenge: authority granted to a swarm, not an individual agent. The current model is single-actor. The extension:

```
SwarmCapability:
    subject: [agent_1, agent_2, ..., agent_n]   // set of actors
    resource: shared_workspace
    rights: READ | WRITE
    threshold: 3/5   // 3 of 5 agents must co-sign to execute
```

This requires changes to:
- `types.rs`: add `SwarmAction` alongside `CanonicalAction`
- `engine.rs`: add `verify_swarm` function (new, does not change existing `verify`)
- `dag.rs`: multi-party attenuation rules

The existing `verify()` function and all its proofs are unchanged. `verify_swarm()` is an extension that calls into the same chain validation logic.

---

## What this means for the 20-year plan

The `Actor → Capability → Resource` model is **not going to break** — it is going to be generalized:

```
Year 0-5:   Human → signs → Machine → uses → Resource
Year 5-10:  (Human | Market | Contract) → signs → Machine → uses → Resource
Year 10-20: (Any Authority Source) → signs → Agent → uses → (Resource | Swarm | Contract)
```

The TCB handles all of these with the same `verify()` function because the structural invariants are the same:
- proof chain must be valid
- rights must not exceed parent
- epoch must be fresh
- subject must match actor

**The dangerous scenario (capability model breaks entirely) does not happen** as long as:
1. Goal markets produce signed capability proofs
2. Reputation systems produce signed capability proofs  
3. Economic contracts produce signed capability proofs

If any of these future systems produces authority through a mechanism that *does not* produce signed, revocable, scoped proofs — that is when the TCB needs to be reconsidered. But that would also violate the philosophical axioms (Consent, Attenuation, Revocation), not just the implementation.

---

## Concrete action items for future-proofing

These belong on the roadmap, not in the TCB:

1. **`AuthoritySource` interface** (integration/ branch, 1-2 years)  
   Abstract the "who signs capabilities" layer. Current `OwnershipRegistry` becomes one implementation.

2. **Proof versioning** (spec-core branch, before v2.0)  
   Every `CapabilityProof` includes the schema version it was issued under.

3. **Multi-issuer support** (tcb-core branch, Phase 4)  
   `root_key` becomes a set, with explicit trust policies between issuers.

4. **`SwarmAction` prototype** (adversarial-lab branch, exploratory)  
   Model multi-party authorization without changing the existing `verify()` path.

None of these require touching `engine.rs` or invalidating existing proofs.

---

## One-sentence summary

The capability model does not break when Goal Markets and Reputation Systems arrive — those systems simply become new `AuthoritySource` adapters that produce signed capability proofs. The TCB is source-agnostic by design.
