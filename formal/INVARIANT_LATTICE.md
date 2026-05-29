# Invariant Lattice — authgate-kernel v3

Branch: `spec-core` | Companion spec: `authgate_v3.tla`

## What This Is

An invariant lattice is not a list — it is the **dependency structure** between
invariants. It answers:

1. Which invariants imply others? (lattice order)
2. Which are independent? (orthogonal dimensions)
3. What is the minimal set that generates all safety properties? (basis)
4. How do invariants compose? (conjunction theorem)

Without this structure, a list of 8 invariants is just 8 separate claims with
no relationship to each other and no guarantee that together they close the
attack space.

---

## The 8 Invariants

| ID | Name | State touched | What it says |
|---|---|---|---|
| I1 | EpochSafety | audit_log | Leaf cap.epoch ≥ min_epoch for every Permit |
| I2 | IdentityBinding | audit_log | SHA-256(issuer_pubkey) = parent.subject_id at every delegation node |
| I3 | Attenuation | audit_log | child.rights ⊆ parent.rights at every delegation node |
| I4 | RevocationSafety | audit_log, revoked_at | No Permit's cap was in revoked_set at decision time |
| I5 | CompositionMono | session_rights | Accumulated rights never decrease |
| I6 | ResourceBinding | audit_log | Cap resource = action resource for every Permit |
| I7 | ChainEpoch | audit_log | Every chain node epoch ≥ min_epoch (stronger than I1) |
| I8 | ChainComplete | audit_log | Every Delegated cap's parent is in the bundle |

---

## Lattice Structure (Hasse Diagram)

```
                          BigSafety
                    (conjunction of all)
                   /    |    |    |    \
                  I7   I4   I5   I6   (I2∧I3 require I8)
                  |                    /       \
                  I1                  I2        I3
                  ↑                   \        /
            (implied by I7)            I8 (prerequisite)
```

**Reading the diagram:**
- An arrow A → B means "A implies B" (A is stronger)
- I7 → I1: chain-wide epoch check implies leaf epoch check
- I2 and I3 depend on I8: without chain completeness, FindParent is undefined
- I4, I5, I6 are independent of each other and of I1–I3, I7–I8

---

## Dependency Proofs (Informal)

### T1: I7 ⟹ I1 (ChainEpoch implies EpochSafety)

**Claim:** If ChainEpoch holds, EpochSafety holds.

**Proof sketch:**
- ChainEpoch states: for every Permit, for every cap in the bundle,
  `ValidChain(c, bundle, action.min_epoch)` holds.
- `ValidChain(c, bundle, mep)` calls `WalkChain(c, 0, mep)`.
- `WalkChain` immediately checks `current.epoch < mep` for the leaf node `c`.
- If this check fails, `ValidChain` returns FALSE → cap not in `valid_caps` → no Permit.
- Therefore: every Permit has leaf cap.epoch ≥ min_epoch, which is exactly I1.

**Consequence:** I1 is a redundant invariant in the minimal generating set.
It is kept because: (a) it is clearer, (b) it corresponds to an explicit check
in `engine.rs` before `validate_chain` is called (early exit optimization).

### T2: I2 and I3 presuppose I8 (ChainComplete)

**Claim:** I2 and I3 are only well-defined when I8 holds.

**Proof sketch:**
- I2 says: `Hash(c.issuer_pubkey) = parent.subject_id` where `parent = FindParent(c, bundle)`.
- I3 says: `c.rights ⊆ parent.rights` where `parent = FindParent(c, bundle)`.
- `FindParent(c, bundle) = CHOOSE p \in bundle : p.proof_hash = c.issuer.parent_hash`.
- If no such `p` exists (`HasParent(c, bundle) = FALSE`), `CHOOSE` returns an
  arbitrary element — the invariants become meaningless (vacuously trivial or
  undefined behavior in TLC).
- I8 (ChainComplete) ensures HasParent holds for every Delegated cap in a Permit,
  making I2 and I3 well-defined.

**Consequence:** I8 is a hidden prerequisite. Without it, the other chain
invariants are stated over undefined values.

### T3: I4, I5, I6 are mutually independent

**Claim:** None of I4, I5, I6 implies or depends on any other.

**Proof by counterexample for each pair:**

- I4 independent of I5: a system with monotone session_rights but where revoked
  caps are permitted (revoked_at check broken) satisfies I5 but not I4.
- I4 independent of I6: a system that checks revocation but allows wrong-resource
  caps satisfies I4 but not I6.
- I5 independent of I6: accumulated session_rights and resource binding check are
  on different fields of different state variables.
- All three independent of I1–I3, I7–I8: I4 operates on `revoked_at` (a snapshot),
  I5 on `session_rights`, I6 on `resource_hash` comparison — none overlap with
  epoch or chain structure fields.

### T4: ValidChain ≡ (I2 ∧ I3 ∧ I7 ∧ I8) for the chain

**Claim:** `ValidChain(leaf, bundle, mep)` holds if and only if the conjunction
of I2, I3, I7, I8 holds for every node on the path from leaf to root.

**Proof by unfolding ValidChain:**
```tla
WalkChain(current, depth, mep) ==
  IF depth > MaxChainDepth THEN FALSE        (* depth limit — no corresponding I *)
  ELSE IF current.epoch < mep THEN FALSE     (* I7: chain epoch at this node *)
  ELSE CASE current.issuer.type = "Root" ->
             current.sig_valid               (* signature *)
           [] current.issuer.type = "Delegated" ->
               /\ current.sig_valid          (* signature *)
               /\ HasParent(current, bundle) (* I8: parent in bundle *)
               /\ LET parent == FindParent(current, bundle) IN
                  /\ Hash(current.issuer_pubkey) = parent.subject_id  (* I2 *)
                  /\ current.rights \subseteq parent.rights           (* I3 *)
                  /\ WalkChain(parent, depth + 1, mep)    (* recurse *)
```

Each check in `WalkChain` corresponds exactly to one invariant:
- `current.epoch < mep` → I7
- `HasParent` → I8
- `Hash(issuer_pubkey) = parent.subject_id` → I2
- `current.rights ⊆ parent.rights` → I3

**Consequence:** `ValidChain` is the mechanization of the I2∧I3∧I7∧I8 conjunction
for a specific chain. ChainEpoch states this holds for every Permit.

---

## Minimal Generating Set

**Claim:** The minimal set that generates all safety properties is:

```
G = {I2, I3, I4, I5, I6, I7, I8}
```

**Why I1 is excluded:** I7 implies I1 (T1). Adding I1 to G is redundant.

**Why I8 is included:** I8 is a prerequisite for I2 and I3. Without I8, the
chain invariants are undefined. It must be in the generating set.

**Formal statement (Theorem T5 in the spec):**
```tla
THEOREM Spec => [](IdentityBinding /\ Attenuation /\ RevocationSafety /\
                   CompositionMono /\ ResourceBinding /\ ChainEpoch /\ ChainComplete
                   => BigSafety)
```

---

## Composition Theorem

**The core security claim:** Individual Permit decisions compose safely.

```
∀ Permit decisions d1, d2, ..., dn ∈ audit_log:
  BigSafety holds
  ⟺
  PermitSoundness holds for each di
  ∧ CompositionMono holds for session_rights
```

**Why this matters:** A system that checks each action independently but allows
harmful compositions is "locally safe but globally broken." This system closes
the composition gap via:

1. `PermitSoundness` — every Permit was issued with a genuinely valid cap
2. `CompositionMono` — accumulated session_rights can only grow, never shrink
   (prevents privilege yo-yoing: grant → revoke → grant higher)
3. `RevocationSafety` — uses `revoked_at` snapshot so future revocations do not
   retroactively change past Permits (preserves audit integrity)

**What the composition theorem does NOT close:**
- Session limit enforcement (AT-4.2): requires a policy layer above `session_rights`
- Semantic composition (AT-4.4): requires a semantic policy layer
- Both are explicitly outside TCB scope — see `formal/INCOMPLETENESS.md`

---

## The Bug We Found and Fixed

**Bug in original `RevocationSafety`:**
```tla
(* WRONG — checks current revoked_set, not revoked_set at decision time *)
RevocationSafety ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      ...
        c.proof_hash \notin revoked_set  (* live state — wrong *)
```

**Why it's wrong:** After any `Revoke(h)` transition, every past Permit with
`proof_hash = h` would be marked as a violation — even though that Permit was
legitimate when issued. Revocation is prospective, not retroactive.

**Fix:** Record `revoked_set` as a snapshot (`revoked_at`) in each audit_log
entry at decision time. Check `\notin audit_log[i].revoked_at` instead.

**Significance:** This is exactly the kind of bug that TLA+ is designed to catch.
The naive formulation "looks right" in isolation but fails as soon as you compose
it with the `Revoke` transition. Finding this by inspection of the invariant
structure (not by running TLC) demonstrates the value of explicit lattice analysis.

---

## Attack Surface Closure via Lattice

| Attack class | Closed by invariants | Gap |
|---|---|---|
| AT-1 (IR tamper) | binding_valid (canonical gate, not an invariant) | none |
| AT-2 (chain manip) | I2 ∧ I3 ∧ I8 via ValidChain / ChainEpoch | none |
| AT-3 (epoch) | I1 ∧ I7 (leaf + chain nodes) ∧ I4 (revocation) | clock trust (G3) |
| AT-4 (composition) | I5 (monotone) | session limits (G4) |
| AT-5 (identity) | I2 via ValidChain | crypto assumption (G6) |
| AT-6 (resource) | I6 | crypto assumption (G6) |
| AT-7 (integration) | binding_valid (AT-7.1/2) | AT-7.5 (G5, CallGate pending) |

The invariant lattice provides complete coverage for AT-2, AT-3, AT-5, AT-6
within the TCB scope. AT-1 and AT-7.1/2 are closed by the binding_valid gate
(not a state invariant — it's checked before any state change). AT-4, AT-7.5
have documented partial coverage with known open gaps.

---

## What Comes After the Lattice

The invariant lattice is Layer 1. It defines what MUST hold.

Layer 2 (next) is the **Composition Theorem** — proving that the conjunction of
all invariants is preserved under all transitions, not just stated as a claim.
This requires either:
- TLC exhaustive verification (mechanized, bounded)
- TLAPS / Lean proof (symbolic, unbounded)

The TLC configuration (`MC_AuthGateV3.cfg`) is already wired to check all 10
invariants (I1–I8 + BigSafety + PermitSoundness) exhaustively over the bounded
model. Running it turns this from a design claim into a verified property.
