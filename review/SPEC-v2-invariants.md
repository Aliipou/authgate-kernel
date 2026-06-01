# SPEC-v2-invariants.md — The De-theologized, Decidable Invariant Set

**Status:** Normative for the TCB. Replaces the *book's* theological A1–A7 as the **machine** axioms. (The book's axioms survive as optional *motivation* in `THEORY-APPENDIX`, never as enforced kernel logic.)

**Design rule (non-negotiable):** A predicate may live in the TCB **only if it is decidable from cryptographic facts and registry lookups in bounded time, with no natural-language interpretation.** Everything else is an *oracle*: it lives outside the TCB, is supplied by an (untrusted, fallible) upstream evaluator, and at most triggers **escalation to a human**, never an autonomous "permit."

This is the line the kernel's `AXIOMATIC_FOUNDATION.md` and `formal/INCOMPLETENESS.md` already draw. This spec makes it the headline, adds the four invariants the panels found missing, and pins each to enforcement.

---

## Legend

- **[TCB]** — decidable; enforced in the trusted core (`freedom-kernel/src/tcb/`). Machine-checkable (Kani/Lean).
- **[ORACLE]** — undecidable/semantic; supplied from outside; may only **DENY** or **ESCALATE**, never grant. Lives in `analysis/` or `extensions/`.
- **[POLICY]** — a configurable choice an adopter sets; decidable once set.

---

## Part 1 — Core structural invariants (these ARE the solution)

These are the existing, proven kernel axioms, restated as the canonical set. They are decidable and already enforced.

### I1 — Action Integrity (canonical binding) **[TCB]**
Every action is sealed by a binding hash over **all** fields; any post-seal mutation is detected before any other check.
*Enforced:* `tcb/engine.rs:35` (Layer 1), `tcb/types.rs:compute_hash`. *Proof:* AT-1.* mutation suite.

### I2 — No Ambient Authority (default-deny) **[TCB]**
Access requires a registered, valid capability for *this* actor over *this* resource. No applicable capability ⇒ deny. There is no "open by default" mode.
*Enforced:* `tcb/engine.rs:51,85`. *Proof:* `prop_read_denied_without_claim`, `prop_write_denied_without_claim`.

### I3 — Cryptographic Identity **[TCB]**
An actor's identity is `SHA-256(public_key)`. Name equality is not identity equality. Impersonation requires key compromise.
*Enforced:* `tcb/dag.rs:95`. *Proof:* C-1 identity-binding suite.

### I4 — Signed, Time-bounded, Epoch-gated Capabilities **[TCB]**
A capability is valid only if its signature verifies, it has not expired, and its epoch ≥ the action's `min_epoch`. Authority has provenance, lifetime, and a revocation epoch — never bare assertion.
*Enforced:* `tcb/engine.rs:60-69` + `tcb/dag.rs:62,72`. *Admitted axiom:* `sig_euf_cma` (ed25519). *Proof:* `stale_epoch_implies_deny`, `prop_epoch_check`.

### I5 — Attenuation: child ⊆ parent **[TCB]**
A delegated capability's rights are a bitwise subset of the delegator's. No delegation grants rights the delegator lacked ("cannot grant up").
*Enforced:* `tcb/dag.rs:101`. *Proof:* `attenuation_cannot_escalate`, `prop_attenuation_two_node`.

### I6 — No Ownerless Machine **[TCB]**
Every machine actor's capability chain must root in a registered trust anchor (a human owner today; a registered `AuthoritySource` in future). No chain to root ⇒ no authority.
*Enforced:* implicit in `dag.rs` chain validation to `root_key`. *Proof:* `prop_ownerless_machine_blocked`.

### I7 — No Machine Dominion Over a Human **[TCB]**
No chain may yield a machine capability whose resource is a human principal. Machine→human governance is structurally impossible, independent of any rights bits.
*Enforced:* `dag.rs` machine-dominion check + Python `verify()`. *Proof:* `prop_machine_governs_human_blocked`.

---

## Part 2 — The invariants the panels found MISSING (add these)

### I8 — Non-Transferable Human Override **[TCB]** *(NEW — the formal home of "inalienable rights")*
There exists a reserved right `OVERRIDE` (interrupt / shutdown / audit / revoke) that:
1. is **always** held by the root principal over every descendant capability in its tree;
2. **cannot be attenuated away, delegated away, or expired** — no capability, consent token, or policy can produce a state in which the root cannot interrupt a descendant;
3. is checked **before** any `min_epoch`/expiry logic, so a revoked-but-cached agent still yields to override.

This is decidable (it is a structural property of the delegation DAG) and is the **secular, pluralism-safe replacement** for the book's "inalienable rights" / A1 inalienability. It needs no theology.
*Enforce at:* `tcb/dag.rs` (reject any chain that drops `OVERRIDE` reachability from root) + `tcb/engine.rs` (new Layer 0.5: root-signed override short-circuits to Deny-execution/Permit-interrupt). *Prove:* new Kani harness `prop_override_unattenuable` + Lean `override_reachable_from_root`.

### I9 — Bounded Delegation Depth **[TCB/POLICY]** *(NEW)*
Each capability carries a `depth` counter; delegation decrements a `max_depth` budget; a chain exceeding the policy bound is denied. Prevents unbounded delegation explosion and "feudal" sub-sub-sub-delegation.
*Enforce at:* `tcb/dag.rs` chain walk (add depth accumulation). *Prove:* `prop_delegation_depth_bounded`.

### I10 — Coalition / Aggregate-Authority Bound **[TCB/POLICY]** *(NEW — partial)*
A set of capabilities held by colluding actors must not, in aggregate, exceed a declared ceiling over a protected resource class. The *decidable* part: the verifier can enforce per-resource aggregate caps and refuse the N-th grant that would breach a declared threshold. The *undecidable* part (detecting *intent* to collude) stays an **[ORACLE]**.
*Enforce at:* `registry` aggregate accounting + `engine.rs` ceiling check. *Boundary:* only declared, quantitative ceilings — not semantic "is this a conspiracy."

### I11 — Mandatory, Tamper-Evident Audit **[TCB]**
Every decision (permit/deny/override/escalate) appends to an append-only, hash-chained log binding action + actor + capability chain + decision + reason. Non-optional.
*Enforce at:* existing audit path; promote to invariant (a permit that fails to audit is a deny).

---

## Part 3 — The oracle boundary (these are NOT kernel axioms — say so)

The following are the predicates the **book** treats as axioms and the **panels** proved undecidable. They are explicitly **outside** the TCB. The kernel never autonomously evaluates them; an upstream evaluator may pass a *claim*, but a claim can only **lower** authority (deny/escalate), never raise it.

| Predicate | Status | Where it lives | Max effect on TCB |
|---|---|---|---|
| `coerced`, `deceived`, `informed`, `voluntary`, `competent` | **[ORACLE]** | `analysis/consent/` | DENY or ESCALATE |
| `increases_machine_sovereignty` (semantic) | **[ORACLE]** | `analysis/` | DENY or ESCALATE |
| `moves_toward_final_order` / any terminal-goal score | **[ORACLE]** | `extensions/` (opt-in) | advisory only |
| manipulation / cognitive-sovereignty erosion | **[ORACLE — currently UNSOLVED]** | `analysis/manipulation/` (stub) | ESCALATE; see I12 |
| "is this action ethical / good" | **out of scope** | — | none |

### I12 — Cognitive-Sovereignty Boundary **[ORACLE — declared open]** *(NEW — honesty requirement)*
The framework **does not** detect manipulation that respects every structural boundary (a permitted action that nonetheless engineers the human's preferences). Per Panel F this is the central blind spot of *all* property/consent kernels. We do not pretend to solve it. We **declare it**, route suspected cases to human escalation, and scope it out in `SCOPE-AND-LIMITATIONS.md`. Closing it is a research dependency, not a kernel feature.

---

## Part 4 — Naming changes required in code

The theological/eschatological identifiers must leave the enforcement path (they are adoption-blockers and imply semantics the TCB does not have):

| Current | Rename to | Rationale |
|---|---|---|
| `DivineJustice` / `divine_justice` | `ConstrainedObjective` | It is constrained optimization, not theology |
| `MahdaviCompass` / `mahdavi_compass` | `InvariantCompass` (advisory, `extensions/`) | Remove confessional terminal goal from any enforced path |
| `OwnedByGod` / A1-as-machine-axiom | (delete from TCB; keep in `THEORY-APPENDIX` as motivation for I7/I8) | Not runtime-enforceable; decorative as mechanism |
| `forbidden(A) :- increases_machine_sovereignty` (semantic) | split: structural flag check **[TCB]** vs. semantic score **[ORACLE]** | Only the boolean-flag form is decidable |

The **structural** sovereignty/corrigibility flags (the 10 hard boolean flags already in the Python verifier) **stay** — they are decidable field checks, not semantic interpretation. Only the *semantic-scoring* pretension is removed.

---

## Part 5 — The consistency claim, stated honestly

**What is consistent and proven:** I1–I7 (and, once implemented, I8–I11) form a consistent, machine-checkable authorization calculus. "Consistent" here means: the kernel's decision function is deterministic, total, and free of derivable permit/deny contradictions within this scope (Lean `verify_deterministic`, `epoch_gate_total`).

**What "consistent" does NOT buy** (per C3): it does not confer jailbreak-immunity, alignment, or safety of the *content* of permitted actions. Consistency is a property of the authorization theory; safety of a learned agent is not.

This is the entire correction the panels asked for: **keep the consistent authorization kernel; stop claiming consistency implies aligned AI.**
