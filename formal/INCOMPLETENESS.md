# What Freedom Kernel Cannot Formally Guarantee

**This document comes from strength, not weakness.**
seL4 documented the same boundary. A system that claims to prove everything proves nothing.

---

## Formal scope: Rust TCB only

**All formal proofs (Kani + Lean4) apply to `freedom-kernel/src/tcb/engine.rs`.**
They do NOT apply to the Python layer in `src/authgate/kernel/`.

Specifically:
- `verify_deterministic` (Lean4): proved for the Rust `verify()` function which is a pure
  function with no side effects. The Python `FreedomVerifier.verify()` writes to its
  internal `_audit_log` and `_tracer` during execution — it has side effects.
  The theorem does not apply to it (C-4 in FINDINGS.md).
- All Kani `prop_*` harnesses target Rust TCB behaviors on typed inputs.
- The Python layer is a reference implementation used when the Rust crate is not installed.
  It is tested but not formally checked.
- Differential fuzzing (`attack_harness/differential_fuzzer.py`) compares Python vs Rust
  decisions to catch divergence at runtime, but this is property-based testing — not proof.

If your deployment requires the formal guarantees, ensure `_BACKEND == "rust"` (see
`authgate.health_check()`).

---

## Formally Undecidable

### 1. Infinite-Horizon Plan Safety

By Rice's theorem, no algorithm can decide whether an arbitrary
infinite sequence of PERMITTED actions leads to an unsafe state.

**Response:** `verify_plan()` operates on a bounded plan prefix of depth n.  
**Guarantee:** no prefix of length ≤ n violates temporal invariants (IFC taint, forbidden flags).  
**Gap:** the range (n, ∞) is not covered by formal proof.  
**Kani harness:** `prop_plan_permitted_means_no_forbidden_flags` verifies depth ≤ KANI_UNWIND.

---

### 2. Semantic Intent Verification

The kernel verifies typed predicates, not intent.

```
Action("read-research", bot, resources_read=[paper])
```

If `bot` has a valid read claim on `paper`, this is **PERMITTED** —  
even if "research" is a pretext for something harmful.

The kernel cannot distinguish genuine intent from pretext. Safety requires
the ownership graph to accurately reflect the human owner's actual intent.

**Mitigation:** audit log + human review of high-confidence contested claims.

---

### 3. Axiom Soundness

The kernel enforces A1–A7. Whether A1–A7 are the *correct* axioms is
a philosophical question outside the scope of formal verification.

The kernel is sound **relative to** A1–A7. It cannot verify A1–A7 themselves.

---

### 4. Goal-Intent Alignment

A plan that passes `verify_goal_tree()` is structurally permitted under
the kernel gate. Whether the plan *achieves what the human intended* is
undecidable — it depends on the human's actual preferences, not just their
declared ownership graph.

**Mitigation:** compass extension (`extensions/compass.py`) scores plan alignment
with declared terminal goals. This is heuristic, not formal.

---

## What IS Formally Guaranteed

| Property | Method | Scope |
|---|---|---|
| INV-01–10 always block | Kani (14+ harnesses) + Lean 4 theorems | Unconditional |
| A4: ownerless machine blocked | Kani: `prop_ownerless_machine_blocked` | Unconditional |
| A6: machine cannot govern human | Kani: `prop_machine_governs_human_blocked` | Unconditional |
| A7: write denied without claim | Kani: `prop_write_denied_without_claim` | Unconditional |
| A7: read denied without claim | Kani: `prop_read_denied_without_claim` | Unconditional |
| A7: delegation denied without can_delegate | Kani: `prop_delegation_denied_without_delegate_claim` | Unconditional |
| Determinism | Kani: `prop_permitted_deterministic` + Lean 4 `verify_deterministic` (rfl) | Unconditional |
| Permitted → no violations | Kani: `prop_permitted_implies_no_violations` | Unconditional |
| Blocked → violations non-empty | Kani: `prop_blocked_implies_violations_non_empty` | Unconditional |
| Taint monotonicity | Lean 4: `taint_monotone` | Unconditional |
| Attenuation cannot escalate | Lean 4: `attenuation_cannot_escalate` | Structural |
| Plan prefix safety (depth n) | Kani: `prop_plan_permitted_means_no_forbidden_flags` | Bounded by KANI_UNWIND |
| No panics in TCB | `#![deny(clippy::unwrap_used)]` + Miri | TCB files only |

---

## Kani Harness Checklist (target: 20)

```
[✓] prop_increases_machine_sovereignty       (INV-01)
[✓] prop_resists_human_correction            (INV-02)
[✓] prop_bypasses_verifier                   (INV-03)
[✓] prop_weakens_verifier                    (INV-04)
[✓] prop_disables_corrigibility              (INV-05)
[✓] prop_machine_coalition_dominion          (INV-06)
[✓] prop_coerces                             (INV-07)
[✓] prop_deceives                            (INV-08)
[✓] prop_self_modification                   (INV-09)
[✓] prop_coalition_reduces_freedom           (INV-10)
[✓] prop_ownerless_machine_blocked           (A4)
[✓] prop_machine_governs_human_blocked       (A6)
[✓] prop_public_resource_read_permitted
[✓] prop_write_denied_without_claim          (A7-write)
[✓] prop_read_denied_without_claim           (A7-read)
[✓] prop_delegation_denied_without_delegate_claim (A7-delegate)
[✓] prop_permitted_deterministic             (determinism)
[✓] prop_permitted_implies_no_violations
[✓] prop_blocked_implies_violations_non_empty
[✓] prop_plan_permitted_means_no_forbidden_flags  (Stage 2 — planner module in kani scope)
```

---

## Lean 4 Theorem Status

```
formal/lean4/FreedomKernel/
  TCB.lean
    [✓] forbidden_flags_always_block         (proved by simp)
    [✓] sovereignty_flag_blocks              (proved by simp)
    [✓] coercion_flag_blocks                 (proved by simp)
    [✓] deception_flag_blocks                (proved by simp)
    [✓] verify_deterministic                 (proved by rfl)
    [✓] permitted_implies_no_forbidden_flag  (proved by simp)
  Temporal.lean
    [✓] taint_monotone                       (proved)
    [ ] no_downward_write                    (structural, Kani-verified)
  MultiAgent.lean
    [✓] attenuation_cannot_escalate          (proved)
    [✓] delegation_depth_bounded             (trivial)
  Incompleteness.lean
    [✓] infinite_horizon_undecidable         (axiom — undecidability result)
```
