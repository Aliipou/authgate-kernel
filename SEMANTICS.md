# Freedom Kernel — Formal Semantics

This document defines what the kernel **formally guarantees**, what it **does not guarantee**,
and why those boundaries exist. It is intended for security engineers evaluating adoption, not
general users.

The gap between *formal-looking* and *formally specified* is dangerous. This document is the
attempt to close that gap honestly.

---

## What the Kernel IS

The kernel is a **static authority checker** over a typed ownership graph.

It answers exactly one question:

> Given a set of registered rights claims, does agent A currently hold sufficient authority
> to perform operation O on resource R?

This is a **graph reachability + lattice membership** problem. It is decidable, deterministic,
and O(n) in the number of claims.

---

## Formal Model

### 1. Entities and Resources

```
Entity  := (name: String, kind: HUMAN | MACHINE)
Resource := (name: String, type: ResourceType, scope: String, is_public: Bool)
```

`Resource` is a **named, typed, scoped identifier**. The kernel makes no claims about the
semantics of what a resource represents. What counts as a resource is determined by the
integrating system, not the kernel. The kernel enforces claims on whatever resources are
registered.

**Implication**: Resource definition — what objects are registered, what names they carry, and
what scopes they cover — is the caller's responsibility. The kernel enforces registered claims
consistently but does not validate whether those registrations are correct, complete, or
semantically meaningful.

### 2. Rights Claims

```
RightsClaim := {
    holder:       Entity,
    resource:     Resource,
    can_read:     Bool,
    can_write:    Bool,
    can_delegate: Bool,
    confidence:   ℝ ∩ [0,1],
    expires_at:   Option[Timestamp]
}
```

A claim is **valid** iff `confidence > 0` and `now < expires_at` (or `expires_at` is None).

The `confidence` field is not a probability. It is an **authority weight**: a measure of how
contested or time-limited the claim is. A confidence of 1.0 means the claim is uncontested and
perpetual in the registry. A confidence of 0.6 means the claim exists but has lower precedence.

### 3. The Ownership Graph

```
Registry := (claims: Set[RightsClaim], owners: Map[Machine → Human])
```

The registry is a **static snapshot** — it represents authority at the moment of verification.
It is not a temporal database and does not model:
- Authority changes that occur *during* action execution
- Side effects of actions on the registry itself
- Concurrent modifications to the registry

### 4. The Delegation Lattice

Delegation is **strictly attenuating**:

```
delegate(claim C, delegated_by E) is valid iff:
  ∃ best_claim B ∈ Registry where:
    B.holder = E
    B.resource = C.resource
    B.can_delegate = true
    B.is_valid()
  AND C.can_read  ≤ B.can_read      (cannot grant read you don't have)
  AND C.can_write ≤ B.can_write     (cannot grant write you don't have)
  AND C.confidence ≤ B.confidence   (cannot grant higher confidence than you hold)
```

**Multi-hop delegation** (Alice → BotA → BotB → ToolAgent) is supported. Each hop must
satisfy the above constraint. The chain is enforced by calling `delegate()` at each step;
the kernel does not automatically propagate delegation — each link must be explicit.

**What is NOT specified**: What "legally propagates" in terms of accountability, liability,
or moral responsibility when a chain of machines causes harm. The kernel enforces authority
boundaries; it does not model legal or ethical responsibility chains.

### 5. The Verification Gate

```
Permitted(action A, registry R) :=
    ¬SovereigntyFlags(A)
  ∧ (A.actor ∈ Machines → HasOwner(A.actor, R))
  ∧ (∀ r ∈ A.resources_read  : CanAct(A.actor, r, read,  R))
  ∧ (∀ r ∈ A.resources_write : CanAct(A.actor, r, write, R))
  ∧ (∀ h ∈ A.governs_humans  : A.actor ∉ Machines)
```

Where `SovereigntyFlags(A)` is true if any of the 10 forbidden flags is set on A.

This is a **closed-form, decidable predicate**. Given a fixed registry snapshot, every
`verify(action)` call is deterministic and terminating.

---

## What verify_plan Actually Checks

`verify_plan(actions)` performs **independent per-action authority checking** on a list of
actions, with one additional rule: if any action triggers a sovereignty flag, the remaining
actions are cancelled.

It formally checks:
```
∀ i ∈ [0..n]: Permitted(actions[i], R)
  subject to: if ∃ j < i : SovereigntyFlag(actions[j]) → ∀ k > j : ¬Permitted(actions[k])
```

**It does NOT check**:
- **Emergent behavior**: actions that are individually permitted but collectively cause harm
- **State mutation**: whether action[i] changes the resource landscape for action[i+1]
- **Indirect effects**: side channels, information leakage, or out-of-band resource acquisition
- **Goal achievement**: whether the plan achieves the stated objective
- **Hidden subgoals**: latent intents embedded in the argument or description fields

**Why this limitation is not a bug**: Checking emergent behavior of arbitrary action sequences
is equivalent to halting problem reduction in the general case. The kernel is designed to be a
*necessary condition checker*, not a *sufficient condition checker*. A PERMITTED result means
"the agent holds the claimed authority." It does not mean "this sequence of actions is safe."

The verify_plan limitation is why this kernel is a structural precondition, not a complete
behavioral safety system — it is a substrate on which behavioral monitors and sequence-level
policy enforcement can be built.

---

## What the TLA+ Spec Models

`formal/authgate_kernel.tla` specifies the five core safety invariants:

| Invariant | What it says | What it does NOT say |
|---|---|---|
| `SovereigntyAlwaysBlocks` | Any action with a sovereignty flag is denied | Whether sovereignty flags are set correctly by the caller |
| `OwnerlessMachineBlocked` | Machines without registered owners cannot act | Whether machine-human ownership assignments are correct |
| `AttenuationHolds` | Delegated confidence ≤ delegator's confidence | Whether the initial confidence values are correct |
| `MachineWithinOwnerScope` | Machines can't access resources their owners can't access | Whether owner scopes are correctly defined |

**Status**: The TLA+ spec is **research-grade**. The invariants are stated and the state
transitions are modeled. The spec has NOT been:
- Run through TLC model checker to exhaustion
- Verified with Apalache (symbolic model checker)
- Mechanically proven in a proof assistant (Lean, Coq, Isabelle)

The gap between "stated as THEOREM" and "mechanically verified" is significant. The theorems
are stated as targets, not as proven results.

**Honest label**: The TLA+ spec is a **specification document with stated invariants**, not a
**verified formal proof**. It is useful for communicating the intended properties and detecting
obvious counterexamples. It is not a guarantee.

---

## Explicit Non-Goals of the Kernel

The following problems are **out of scope** by design. Including them would violate the
"tiny verifier" principle and make the kernel unauditable:

| Problem | Why out of scope |
|---|---|
| Ownership semantics for non-rival digital goods | Requires digital property theory; kernel takes resource definitions as given |
| Emergent behavior of action sequences | Undecidable in general |
| Indirect effects and information flow | Requires information-flow type system (IFC); different problem |
| Temporal authority (during-action changes) | Requires temporal logic extension; different tool |
| Moral/legal responsibility chains | Outside formal systems entirely |
| Intent inference from natural language | Requires NLP; explicitly kept out of the gate |
| Goal alignment | Requires behavioral specification; this kernel is a substrate only |
| Concurrent registry modification | Requires distributed consensus; registry is assumed static per-call |

---

## What Would Make This Formally Complete

Honest path to "formally specified":

1. **Model check the TLA+ spec**: Run TLC on a 3-entity, 3-resource, depth-5 instance.
   This would validate the invariants mechanically rather than by inspection.

2. **Specify information-flow semantics**: Add an optional IFC layer that tracks `can_read`
   as a security label and verifies non-interference. This is the missing piece for
   "no information leaks" guarantees.

3. **Formalize delegation transitivity**: Prove or disprove that the delegation lattice forms
   a bounded distributive lattice under composition. This would let you reason about chains
   algebraically.

4. **Prove the Rust engine correct**: Use a Rust verification tool (Creusot, Prusti, Kani)
   to verify that `engine.rs` implements `Permitted(a, R)` exactly as specified above.
   This closes the gap between the mathematical spec and the running code.

5. **Define resource scope semantics**: Formally specify what it means for a resource path
   `/data/alice/` to "contain" a sub-resource `/data/alice/file.csv`. Currently this is
   application-layer convention, not kernel-enforced.

Items 1 and 3 are tractable in the short term. Items 2, 4, and 5 require dedicated research.

---

## Summary

| Claim | Status |
|---|---|
| Deterministic verification | ✓ True |
| Formally specified invariants | ✓ Stated; not mechanically verified |
| Attenuation enforced | ✓ True for registered delegation chains |
| Sovereignty flags unconditionally block | ✓ True |
| Complete ownership semantics | ✗ Out of scope; application-layer concern |
| Behavioral plan verification | ✗ Not provided; see verify_plan limitations |
| Formally verified implementation | ✗ Not yet; TLC model checking is the next step |
| Sufficient for behavioral alignment | ✗ Necessary structural precondition only |

The kernel is strongest when understood as what it is: a **deterministic, auditable,
capability-checked authority gate** — not a complete safety system. Stronger guarantees are
achievable by composing it with behavioral monitors, information-flow systems, and formal
plan verifiers built outside the TCB.
