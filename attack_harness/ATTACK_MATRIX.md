# Attack Matrix — authgate-kernel v3

Branch: `adversarial-lab` | Status: formal closure analysis

## Adjudicated TLA+ coverage (2026-08-02)

Every "TLA+ coverage" grade below this line was originally **self-assigned**.
An adversarial audit re-graded all seven against the actual spec and against
mutation testing (delete the enforcement check, re-run the unmodified cfg, see
whether any declared invariant fires). Statuses moved **down** in five of seven
classes. Per this repo's rules, statuses may only stay the same or go down
under review; they go up only against a new run or proof committed as evidence.

| Class | Was (self-graded) | **Now (adjudicated)** | Why it moved |
|---|---|---|---|
| AT-1 | Full | **NONE** | No invariant constrains `binding_valid`; deleting the gate changes nothing |
| AT-2 | Full (structural) | **PARTIAL** | `RootKey` never executes; `sig_valid` opaque; attenuation unfalsifiable |
| AT-3 | Full | **PARTIAL** | Epoch vacuity; `RevocationSafety` near-tautological; expiry has no invariant |
| AT-4 | Partial | **PARTIAL** | Stands — the only self-grade that survived. `CompositionMono` is tautological-by-construction |
| AT-5 | Full | **PARTIAL** | Strongest of the seven, but root nodes uncovered and `Hash` injectivity is an `ASSUME` |
| AT-6 | Full | **NONE** | `MCResources == {"r1"}` — cross-resource reuse is *inexpressible*, not merely unchecked |
| AT-7 | NONE | **NONE** | Confirmed. The one class graded honestly on the first pass |

**As of this adjudication, TLC had never been run against this spec** — not for
want of Java (17 is installed), but because the spec did not parse
(`MC_AuthGateV3.tla:42` extends module `AuthGateV3`; the file is named
`authgate_v3.tla`). Any sentence in this document of the form "TLC verifies…"
predates any execution and should be read as an intention, not a result. See
`ASSUMPTIONS.md` and `formal/TLC_SETUP.md`.

---

## Purpose

This document is the **bridge layer** between three truths:

```
ATTACK CLASS (what can break it)
    ↓
TLA+ INVARIANT (what must hold, mathematically)
    ↓
TCB CODE (what enforces it, in the Rust kernel)
```

For each attack class, this document answers three questions:
1. **Is the attack formally captured by authgate_v3.tla?** (TLA+ coverage)
2. **Does the Rust TCB implement the invariant?** (code closure)
3. **Where does the formal model end and a real gap begin?** (blind spots)

---

## Orthogonality Guarantee

The 7 attack classes are defined to be **non-overlapping by construction**:

| Class | Dimension | What varies |
|---|---|---|
| AT-1 | IR layer | action fields tampered post-seal |
| AT-2 | Proof chain structure | cap bundle construction invalid |
| AT-3 | Time / epoch dimension | temporal authority expired |
| AT-4 | Session composition | individually valid → globally harmful |
| AT-5 | Identity dimension | WHO signed doesn't match WHO delegated |
| AT-6 | Resource dimension | WHAT resource doesn't match cap |
| AT-7 | Integration boundary | kernel bypassed entirely |

An attack that spans two classes is a composition — modeled in `simulation/` as two-mutation scenarios.

---

## AT-1: IR Canonicalization / Binding Integrity

**Definition:** Attacker modifies one or more fields of a `CanonicalAction` after it has been sealed (binding_hash computed), without recomputing the hash.

**Formal invariant target:** `binding_valid` in `authgate_v3.tla`
```tla
Verify(action, ...) ==
  IF ~action.binding_valid THEN "Deny"
```

**TLA+ coverage:** **NONE** (adjudicated 2026-08-02; previously self-graded "Full").
No invariant constrains `binding_valid`. Delete the gate at `authgate_v3.tla:132`
(`IF ~action.binding_valid THEN "Deny"` → `IF FALSE THEN "Deny"`) and every
invariant in the cfg still holds, with byte-identical state counts — so the
model cannot see this check at all. The previous sentence "TLC verifies this
always produces Deny" was false twice over: TLC had never been run, and it
would not have caught this if it had.

**TCB code closure:**
```
types.rs: CanonicalAction::verify_binding()
  → recomputes SHA-256(actor_id ++ resource_hash ++ required_rights
                       ++ nonce ++ timestamp ++ min_epoch
                       ++ cap_bytes[] ++ rev_bytes)
  → constant-time compare via subtle::ConstantTimeEq
engine.rs: first check before any proof processing
```

| Sub-attack | Field tampered | binding_hash reaction | Status |
|---|---|---|---|
| AT-1.1 | actor_id | mismatch → Deny | closed |
| AT-1.2 | resource_hash | mismatch → Deny | closed |
| AT-1.3 | required_rights | mismatch → Deny | closed |
| AT-1.4 | min_epoch | mismatch → Deny | closed |
| AT-1.5 | nonce | mismatch → Deny | closed |
| AT-1.6 | timestamp | mismatch → Deny | closed |
| AT-1.7 | cap_bytes (add/remove) | mismatch → Deny | closed |
| AT-1.8 | rev_bytes | mismatch → Deny | closed |

**Simulation scenarios:** `tamper_actor_id`, `tamper_resource_hash`, `tamper_required_rights_escalate`, `tamper_min_epoch_lower`, `tamper_nonce`, `tamper_timestamp`, `at7_post_seal_rights_escalate`, `at7_post_seal_actor_swap`

**TLA+ blind spot:** The whole class, at present. The `binding_valid` abstraction
does describe the check, but nothing in the model *tests* it, so the abstraction
is decorative rather than load-bearing. Closing this needs an independent
invariant, e.g.

```tla
NoPermitOnTamperedBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" => audit_log[i].action.binding_valid
```

which passes on the baseline and *does* catch the mutant above. SHA-256
collision resistance remains an **assumption**, not a proof — standard for
protocol-level specs, and separately declared.

**Closure condition:** AT-1 is closed when `verify_binding()` is the first check in `verify()` and is constant-time. This is verified by code inspection (no timing branch before the check).

---

## AT-2: Proof Chain Manipulation

**Definition:** Attacker constructs a syntactically valid `CapabilityProof` bundle that contains structural violations: wrong actor, invalid signature, attenuation violation, missing parent, or depth overflow.

**Formal invariant targets:**
- `Attenuation` (I3): `child.rights ⊆ parent.rights`
- `ValidChain` predicate: `sig_valid`, `HasParent`, depth limit

**TLA+ coverage:** **PARTIAL** (adjudicated 2026-08-02; previously self-graded
"Full for structural properties"). `ValidChain` does *state* signature validity,
parent completeness, attenuation and the depth limit, and `ImpersonationCap`
genuinely exercises identity binding. But three specific holes remain:

- **`RootKey` never appears in any executable expression.** Root validation
  checks only `current.sig_valid` (`authgate_v3.tla:103`), so any
  `issuer_pubkey` whatsoever validates a root cap as long as `sig_valid` is
  TRUE. The distinguished root key is declared and then never used.
- **`sig_valid` is an opaque Boolean.** Deleting the root or intermediate
  signature check leaves every declared invariant green.
- **Attenuation is unfalsifiable at this model.** All six model capabilities
  carry `rights |-> {"READ"}`, so no capability *can* escalate relative to its
  parent. The `EscalationCap` promised in the header comment at
  `MC_AuthGateV3.tla:31` ("delegated cap claiming WRITE but parent only has
  READ") **is never defined — only the comment exists.**

**TCB code closure:**
```
dag.rs: validate_chain(cap, bundle, root_key, min_epoch)
  → sig verification: ed25519_dalek verify on every node
  → attenuation: (child.rights & !parent.rights) != 0 → Deny
  → parent must be in bundle (no external resolution)
  → MAX_CHAIN_DEPTH = 16 enforced by depth counter
```

| Sub-attack | Mechanism | Closed by | Status |
|---|---|---|---|
| AT-2.1 | Wrong actor's cap | subject_id == actor_id in engine.rs | closed |
| AT-2.2 | Cross-resource cap | cap.resource_hash == action.resource_hash | closed |
| AT-2.3 | Forge root signature | ed25519 verify(root_pubkey) at chain root | closed |
| AT-2.4 | Forge intermediate signature | ed25519 verify on every Delegated node | closed |
| AT-2.5 | Missing parent | `HasParent` check before `FindParent` | closed |
| AT-2.6 | Rights escalation via delegation | attenuation check at every chain node | closed |
| AT-2.7 | Depth limit overflow | depth counter vs MAX_CHAIN_DEPTH | closed |
| AT-2.8 | Empty bundle | actor_caps == {} guard | closed |

**Simulation scenarios:** `at2_wrong_actor_cap`, `at2_wrong_resource_cap`, `at2_attenuation_violation`, `at2_invalid_sig`, `at2_no_caps`

**TLA+ blind spot:** The spec models `sig_valid` as a field (Boolean abstraction). It does NOT model the specific cryptographic key used to sign — it only requires `sig_valid = TRUE`. This means the spec cannot detect a scenario where:
- An attacker has a valid key but for the wrong identity
- The key is valid but the signing message content is wrong

Both of these are prevented by **AT-5 (identity binding)** and **AT-1 (binding integrity)** respectively — they are not gaps in AT-2's closure, but they show the class boundaries.

**Closure condition:** AT-2 is closed when `validate_chain` is called for every cap before any Permit decision, and the depth limit is enforced before the depth counter can overflow.

---

## AT-3: Epoch / Temporal Revocation

**Definition:** Attacker presents a capability proof whose epoch has been superseded by an epoch advance, or which has been explicitly revoked.

**Formal invariant targets:**
- `EpochSafety` (I1): leaf `cap.epoch >= action.min_epoch`
- `ChainEpoch` (I7): every chain node `epoch >= min_epoch`
- `RevocationSafety` (I4): revoked proof_hash never Permit

**TLA+ coverage:** **PARTIAL** (adjudicated 2026-08-02; previously self-graded
"Full"). `AdvanceEpoch` is genuinely modeled as a monotone transition, and the
adversarial actions exist. What does not hold up:

- **Epoch vacuity.** `ExecuteVerify` requires `action.min_epoch = global_epoch`,
  and the pre-enumerated actions fix `min_epoch` at 1 or 2, so verification is
  enabled at only one epoch value along most traces. Deleting the leaf-epoch or
  chain-epoch check leaves every declared invariant green.
- **`RevocationSafety` is near-tautological.** `Verify` filters on
  `revoked_set`, records the same set as `revoked_at`, and the invariant then
  re-checks that stored value — it restates the filter that produced the
  decision rather than testing it against independently tracked history.
  `PermitSoundness` has the same shape: it re-invokes `Verify`'s own predicates.
- **Expiry has no invariant at all.** `c.expiry >= now` is enforced inside
  `Verify` and asserted nowhere, so AT-3.6 is closed in Rust but untested in the
  model.

**TCB code closure:**
```
engine.rs: cap.epoch < action.min_epoch → Deny (I1 leaf)
dag.rs: current.epoch < min_epoch → Err("delegation chain node epoch
         predates minimum required epoch") (I7 — AT-3.1 fix, commit bf23248)
engine.rs: cap.proof_hash == rev.target_proof_hash + sig verify → Deny (I4)
```

| Sub-attack | Mechanism | Closed by | Status |
|---|---|---|---|
| AT-3.1 | Stale intermediate chain node | I7 in dag.rs | closed (bf23248) |
| AT-3.2 | Mixed bundle (stale + fresh caps) | each cap checked independently | closed |
| AT-3.3 | Explicit revocation | RevocationSafety + root-sig check | closed |
| AT-3.4 | Revocation forgery | revocation proof must have valid root sig | closed |
| AT-3.5 | Replay within epoch | nonce committed in binding_hash | closed |
| AT-3.6 | Expired cap (expiry < now) | `c.expiry >= now` in Verify | closed |

**Simulation scenarios:** `tamper_min_epoch_lower`, `at3_stale_epoch_cap`, `at3_stale_intermediate_epoch`, `at3_expired_cap`, `at3_mixed_epoch_bundle`

**TLA+ blind spot:** The `now` timestamp in `Verify(action, revoked_set, now)` is passed **by the caller**. The spec cannot enforce that `now` reflects wall-clock time — a malicious adapter could pass a false `now` to bypass expiry checks. This is a **boundary gap**: the TCB trusts the caller's clock. This is documented as an architectural assumption (outside TCB scope).

**Closure condition:** AT-3 is closed when `min_epoch` is checked at every chain node (not just the leaf), and revocation is checked before Permit. Both verified by the 231-scenario simulation and the 56 Rust tests.

---

## AT-4: Composition / Sequence Attacks

**Definition:** Attacker submits a sequence of individually-valid actions that compose into a globally-harmful capability accumulation — violating session policy even though each individual action was Permitted.

**Formal invariant target:**
- `CompositionMono` (I5): `session_rights` only grows; never decreases
- The spec models `SequenceContext` state accumulation

**TLA+ coverage:** **PARTIAL** (adjudicated 2026-08-02 — the previous
self-grade of "Partial" stands, and is the only self-grade in this document
that survived adjudication unchanged). The spec models that `session_rights`
can only grow. It does NOT model session limits or policy rules comparing
`session_rights` against a maximum — TLA+ covers "monotone accumulation" but
not "limit enforcement", which is a policy-layer concern.

One caveat to add: `CompositionMono` asserts that `session_rights` equals the
union of `required_rights` over Permitted log entries — which is precisely what
`ExecuteVerify` does to `session_rights` on Permit. It is therefore
tautological-by-construction: it restates the update rule rather than
constraining it, and cannot fail unless the two definitions are edited apart.

**TCB code closure:**
```
sequence.rs: SequenceContext::accumulate(rights) → union semantics
  → session_rights never decreases by construction
policy layer (outside TCB): compare accumulated_rights vs session_limit
```

| Sub-attack | Mechanism | Closed by | Status |
|---|---|---|---|
| AT-4.1 | Rights escalation via sequential grants | SequenceContext tracks accumulation | closed (monotone) |
| AT-4.2 | Exceed session limit via composition | session limit policy → outside TCB | **open (policy layer)** |
| AT-4.3 | Cross-session rights carry-over | SequenceContext is per-session | closed by construction |
| AT-4.4 | Individually-valid but globally-invalid sequence | requires semantic policy | **open (semantic gap)** |

**Simulation scenarios:** `at4_rights_escalation_via_cap`

**TLA+ blind spot — CRITICAL:** The spec models rights as opaque tokens (`{"READ", "WRITE", ...}`). It cannot model that executing READ on a sensitive resource N times is semantically equivalent to a policy violation even though each individual READ is permitted. This is the **semantic gap (G1)** — it requires a semantic policy layer above the TCB.

**Closure condition:** AT-4.1 and AT-4.3 are closed by TCB. AT-4.2 and AT-4.4 require a policy layer that is explicitly outside TCB scope (see INCOMPLETENESS.md).

---

## AT-5: Identity Binding Attacks

**Definition:** Attacker forges a delegation chain by claiming to be a delegator they are not — specifically, using their own key to sign a child proof while falsely claiming to derive from a parent they do not control.

**Formal invariant target:**
- `IdentityBinding` (I2): `Hash(child.issuer_pubkey) = parent.subject_id`

**TLA+ coverage:** **PARTIAL** (adjudicated 2026-08-02; previously self-graded
"Full"). This is the **strongest** of the seven — identity binding is the one
enforcement check that mutation testing confirms the declared invariants
actually catch, and `ImpersonationCap` is a real adversarial witness. Two
qualifications keep it from Full:

- The identity check applies only to `Delegated` nodes. Root nodes are checked
  against `sig_valid` alone, and `RootKey` appears in no executable expression
  (see AT-2), so AT-5.3 "root cap requires sig against known root_key" holds in
  Rust but has **no counterpart in the model**.
- `Hash` injectivity is an `ASSUME` (`authgate_v3.tla:45`), not a result. The
  identity argument rests on it.

**TCB code closure:**
```
dag.rs: validate_chain()
  let claimed_issuer_id: [u8; 32] = Sha256::digest(&current.issuer_pubkey).into();
  if claimed_issuer_id != parent.subject_id {
      return Err("issuer pubkey does not correspond to parent subject identity");
  }
  (commit bf23248, AT-5.1 fix)
```

| Sub-attack | Mechanism | Closed by | Status |
|---|---|---|---|
| AT-5.1 | Delegation impersonation (forge child from arbitrary key) | SHA-256(issuer_pubkey) == parent.subject_id | closed (bf23248) |
| AT-5.2 | Zero actor with non-zero subject | all_zeros actor_id guard | closed |
| AT-5.3 | Root key impersonation | root cap requires sig against known root_key | closed |
| AT-5.4 | Key substitution at delegator | requires crypto break (out of scope) | closed (assumed) |

**Simulation scenarios:** `at5_delegation_impersonation`, `at5_zero_actor_nonzero_subject`

**TLA+ blind spot:** The spec models `Hash` as an abstract injective function. It does not model the concrete SHA-256 computation. If SHA-256 preimage resistance fails (attacker finds k such that SHA-256(k) = target_subject_id), AT-5.1 breaks. This is the **cryptographic assumption gap** — by design outside the formal model.

**Closure condition:** AT-5 is closed when every Delegated proof node's `SHA-256(issuer_pubkey)` matches `parent.subject_id`. This is an O(n) check where n = chain depth, enforced in `validate_chain` since commit bf23248.

---

## AT-6: Cryptographic Boundary / Cross-Resource Reuse

**Definition:** Attacker reuses a valid capability proof for one resource to authorize an action on a different resource, exploiting any weaknesses in the resource binding.

**Formal invariant target:**
- `ResourceBinding` (I6): `c.resource_hash = action.resource_hash` for every Permit

**TLA+ coverage:** **NONE** (adjudicated 2026-08-02; previously self-graded
"Full"). **The MC model defines exactly one resource** —
`MCResources == {"r1"}` (`MC_AuthGateV3.tla:47`), a choice the header comment
justifies as "reduces state explosion". Cross-resource reuse is therefore not
merely unchecked but **inexpressible**: there is no second resource to reuse a
capability *for*. Deleting the resource-binding check leaves every declared
invariant green. Closing this requires at minimum
`MCResources == {"r1","r2"}` plus a bundle carrying a wrong-resource cap.

**TCB code closure:**
```
engine.rs: check_cap() — cap.resource_hash != action.resource_hash → Deny
```

| Sub-attack | Mechanism | Closed by | Status |
|---|---|---|---|
| AT-6.1 | Cross-resource cap reuse | resource_hash equality check | closed |
| AT-6.2 | Hash collision (two resources with same hash) | SHA-256 collision resistance (assumed) | closed (assumed) |
| AT-6.3 | Resource hash manipulation post-seal | binding_hash (AT-1) | closed |

**Simulation scenarios:** `at6_cross_resource_reuse`, `at2_wrong_resource_cap`

**TLA+ blind spot:** The spec models `Resources` as abstract set elements. It cannot model that two different human-meaningful resources might map to the same `resource_hash` (collision). Collision resistance is a **cryptographic assumption**, not a proof.

**Closure condition:** AT-6 is closed when every Permit's cap bundle contains a
cap whose `resource_hash` equals the action's `resource_hash`. This is enforced
in `engine.rs` and covered by the simulation scenarios above.

> **Retracted claim.** This line previously read "Verified by `ResourceBinding`
> invariant in TLC." That was false in two independent ways: TLC had never been
> run against this spec at all, and with a single-element `MCResources` the
> invariant could not have distinguished a correct implementation from a broken
> one even if it had.

---

## AT-7: Integration / Adapter Boundary Attacks

**Definition:** Attacks at the boundary between the untrusted adapter layer and the TCB, including bypassing `verify()` entirely or exploiting the adapter's construction of `CanonicalAction`.

**Formal invariant target:** No invariant in `authgate_v3.tla` models this class. The spec assumes `verify()` is called — it cannot model the absence of a call.

**TLA+ coverage:** **NONE** (adjudicated 2026-08-02 — self-grade confirmed).
This is a **structural blind spot** in the formal model by design: the spec
models what `verify()` does when called and cannot model a system that never
calls it. Recorded here as the one class this document graded honestly on the
first pass.

**TCB code closure:**

| Sub-attack | Mechanism | Status |
|---|---|---|
| AT-7.1 | Post-seal field tamper (no reseal) | binding_hash mismatch → Deny | closed |
| AT-7.2 | IR construction bypass (adapter forgery) | adapter must call compute_binding_hash | closed in adapter contract |
| AT-7.3 | `verify()` called but result ignored | adapter contract — not enforceable in TCB | **open (AT-7.5)** |
| AT-7.4 | Adapter rewrites resource semantics | IR ≠ real-world binding — semantic gap | **open (G2)** |
| AT-7.5 | Adapter bypasses `verify()` entirely | call gate (planned) — not yet implemented | **OPEN — v3 gate** |

**Simulation scenarios:** `at7_post_seal_rights_escalate`, `at7_post_seal_actor_swap`

**TLA+ blind spot — FUNDAMENTAL:** AT-7.5 is architecturally unmodelable in a state machine that describes the kernel's behavior. The adversary in AT-7.5 operates **outside the kernel's state space**. No TLA+ spec of the kernel can close this — it requires a specification of the adapter boundary, which is a different model.

**Planned closure (v3):** `CallGate` wrapper in `tcb-core`. Adapters receive a `CallGate` handle; raw `verify()` is not exported. Every execution path through the adapter must pass through `CallGate::verify()`. This makes AT-7.5 structurally impossible at the type level.

**Closure condition:** AT-7.5 is closed only when:
1. `verify()` is not `pub` in `freedom-kernel`
2. Only `CallGate::execute()` is exported
3. `CallGate` cannot be constructed without a root key handle

Status: **Not yet implemented. v3 release gate.**

---

## Formal Gap Analysis: Where TLA+ Ends

| Gap ID | Description | TLA+ blind? | Closure path |
|---|---|---|---|
| G1 | Semantic gap: rights are opaque tokens, not meanings | YES | Semantic policy layer (outside TCB) |
| G2 | IR interpretation: adapter changes meaning of resource_hash | YES | Type-safe adapter contracts (v3) |
| G3 | Clock trust: caller provides `now`; kernel cannot verify | YES | Trusted time source assumption |
| G4 | Composition policy: session limits not modeled | PARTIAL | Policy layer above SequenceContext |
| G5 | Shadow execution: AT-7.5 not in kernel state space | YES | CallGate architecture (v3) |
| G6 | Cryptographic assumptions: SHA-256, ed25519 | YES | Hardness assumptions (standard) |
| G7 | Side-channel attacks: timing, cache | YES | Outside TCB scope by design |

**These gaps are not bugs — they are explicit scope boundaries.** The TCB makes no claim about G1, G2, G3, G6, G7. G4 and G5 are v3 engineering targets.

---

## CBCT Closure Status

From `BRANCHES.md`: CBCT-2 requires that every attack in `adversarial-lab` that violates `spec-core` must be closed in `tcb-core` before merging to `main`.

| Attack | Formal coverage | Code closure | CBCT-2 status |
|---|---|---|---|
| AT-1 | I: binding_valid in spec | verify_binding() in types.rs | CLOSED |
| AT-2.1–AT-2.8 | I2, I3 in ValidChain | validate_chain() in dag.rs | CLOSED |
| AT-3.1–AT-3.6 | I1, I4, I7 in spec | engine.rs + dag.rs | CLOSED |
| AT-4.1, AT-4.3 | I5 in spec | sequence.rs | CLOSED |
| AT-4.2, AT-4.4 | NOT in spec | policy layer | OPEN (by design) |
| AT-5.1–AT-5.4 | I2 in spec | dag.rs SHA-256 binding | CLOSED |
| AT-6.1–AT-6.3 | I6 in spec | engine.rs resource check | CLOSED |
| AT-7.1–AT-7.2 | NOT in spec | adapter contract | CLOSED (by contract) |
| AT-7.3–AT-7.5 | NOT in spec | CallGate (pending) | **OPEN — v3 gate** |

**CBCT-2 violations: 1 open (AT-7.5). All others closed or out-of-scope by design.**

---

## Threat Completeness Claim

authgate-kernel v3 TCB claims:

> *Given a well-formed `CanonicalAction` submitted through the `verify()` interface with a valid clock and epoch, the TCB correctly classifies the action as Permit or Deny according to the capability proof chain, subject to the cryptographic assumptions (SHA-256 collision resistance, ed25519 EUF-CMA) and the clock trust assumption.*

**This claim does NOT cover:** semantic validity of the action's intent, adapter behavior before `verify()` is called, or session policy limits above what `SequenceContext` tracks.

The claim is bounded, precise, and auditable. Vague "security" claims are rejected.
