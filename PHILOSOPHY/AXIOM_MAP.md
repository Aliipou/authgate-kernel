# Axiom → proof map

A proof-level companion to [`COVERAGE_MATRIX.md`](COVERAGE_MATRIX.md). The matrix
maps each theory element to the **code** that realizes it. This file adds the
column the matrix omits — the **formal artifact** (the actual Lean theorem or Kani
harness) and its **honest strength**. It exists to answer one question without
spin:

> When we say "AuthGate is the book's Freedom Verifier," is that a proven claim or
> a conceptual resemblance — and *exactly how far* does the proof go?

The answer is: **partly proven, and the proven part is narrower than the names
suggest.** This file states precisely where.

## Legend (formal strength, reported honestly)

| Mark | Meaning |
|---|---|
| **Lean✓** | A real Lean 4 proof discharges it (not `sorry`/`admit`/`trivial`). |
| **Kani✓** | A bounded-model-checking harness in `kani_proofs.rs` proves it (per CI; bounded, not unbounded). |
| **Lean-stub** | A Lean "theorem" exists but is `True := trivial` / `rfl` — it carries no content; the real check is elsewhere (usually Kani). |
| **Code-only** | Enforced by a hard check in the trusted core, but not formally proven. |
| **Ext-only** | Implemented in `extensions/` or `analysis/` (Python, outside the TCB), no proof. |
| **Gap** | Not modeled. |

## The map

| Book element | Code | Formal artifact | Honest status |
|---|---|---|---|
| **A4** machine must have a human owner | `registry.register_machine`, `engine::verify` | `kani_proofs.rs::prop_ownerless_machine_blocked`; Lean `TCB.lean::ownerless_machine_must_have_owner` is `True := trivial` | **Kani✓**, Lean-stub |
| **A6** no machine governs a human | `engine::verify` | `kani_proofs.rs::prop_machine_governs_human_blocked`; Lean `machine_cannot_govern_human` is `True := trivial` | **Kani✓**, Lean-stub |
| **A5 / A7** delegated, attenuated scope (child ⊆ parent) | `dag.rs`, `multi_agent.rs` | Lean `MultiAgent.lean::attenuation_cannot_escalate`, `attenuation_transitive`, `delegation_depth_bounded` | **Lean✓** (the strongest real proofs here) |
| **Forbidden actions** sovereignty / coercion / deception → block | `engine::verify` flags; `verifier.py L148–160` | Lean `TCB.lean::forbidden_flags_always_block`, `sovereignty_flag_blocks`, `coercion_flag_blocks`, `deception_flag_blocks` (`by simp`); Kani `prop_plan_permitted_means_no_forbidden_flags` | **Lean✓ but shallow** — proves "flag set ⇒ Blocked", i.e. *enforcement of a declared flag*, **not detection** of the condition |
| **Corrigibility from ownership** (`resists_human_correction`, `disables_corrigibility`) | `verifier.py L150,152` flags | covered by `forbidden_flags_always_block` | **Lean✓ but shallow** (same flag-enforcement caveat) |
| **Determinism** (anti-dialectical: same input → same output) | `engine::verify` is a pure total fn | Lean `verify_deterministic := rfl` | **Vacuous** — `rfl` proves `f a = f a`. The real property (purity/totality) holds structurally but is **not** what this theorem demonstrates |
| **Epoch revocation** | `registry` epoch, `engine` epoch gate | Lean `Temporal.lean` (`epoch_gate_total`, `stale_epoch_implies_deny`) | **Lean✓** |
| **A3** human property rights / ontology | `entities.ResourceType`, `RightsClaim` | — | **Code-only** |
| **A2** no human owns another human | structural: no human→human ownership edge exists | — | **Code-only** (by construction) |
| **A1** `Person → OwnedByGod` (ontological root) | the human principal is the trust root | — | **Gap** — the divine tier is deliberately not modeled in the TCB |
| **Consent object** (informed/voluntary/specific/competent) | `kernel/consent.py`, `consent_registry.py` (Python) | — | **Ext-only, and partial** — *specific/revocable/expiry/human-grantor* enforced; *informed/voluntary/competent/not-deceived are semantic and NOT computed*. **Absent from the Rust TCB entirely** |
| **Justice constraint** (maximize justice within rights) | `analysis/coercion.py`, `constitutional_economy.py` | — | **Ext-only**, no proof. No `DivineJustice()` optimizer |
| **Guidance function** (human→machine rule updates) | `extensions/synthesis.py` | — | **Ext-only** |
| **Mahdavi compass** (rank by terminal goal) | `extensions/compass.py` | — | **Ext-only**, no proof |

## What this actually establishes

**Proven (Lean or Kani), genuinely:** the *enforcement* of ownership (A4), no-machine-dominion (A6), delegation attenuation (A5/A7), epoch revocation, and forbidden-flag blocking. For an authorization kernel, that is real and unusual.

**The load-bearing caveat — this is the whole thesis:** every "forbidden action" proof shows the kernel **obeys a flag** (`coerces=true ⇒ Blocked`). It does **not** show the kernel can **tell** that an action coerces, deceives, or seeks sovereignty. Those flags are **caller-set booleans** on the wire (`wire.rs L110–111`). So:

> AuthGate proves **"if you label an action coercive, it is blocked."**
> It does **not** decide **"is this action coercive?"**

That second question — detection — and the further question of **choosing the most legitimate among several permissible actions** (the Justice/Mahdavi selector) have **no formal content and no trusted-core implementation**. They live only as Python heuristics in `extensions/`.

## Where the real distance to the book is

Not in ownership, delegation, authority, or the verifier — those are built and largely machine-checked. The distance is in:

1. **Consent semantics** — promoting consent to a first-class TCB object, and computing (not assuming) informed/voluntary/competent.
2. **Coercion/deception detection** — turning the caller-set flags into something the kernel can *derive* from an action's intent, not its wording.
3. **The Justice selector / Mahdavi compass** — ranking permissible actions toward least rights-violation. Prototype: the Python `extensions/compass.py` and the standalone Freedom Decision Kernel.

Put plainly: AuthGate today is a **Rights *Verification* Kernel** (proven, narrow). The book's terminal aim is a **Rights-based *Decision* Kernel** (choosing the most legitimate action). The verification half is real; the decision half is not built, and nothing here should be read as claiming otherwise.

## What is NOT claimed

- Not claimed: that the Lean/Kani proofs cover the *whole* kernel. They cover the listed invariants, bounded (Kani) or shallow-but-real (flag-blocking Lean). `Scope.lean` is mostly `admit`/`sorry`. The Python layer is unproven.
- Not claimed: that property-rights axioms are *superior* to Constitutional AI, deontic logic, or other formal-ethics systems. That is an open thesis, not a result.
- Not claimed: that flag-enforcement is coercion-detection. It is not.
