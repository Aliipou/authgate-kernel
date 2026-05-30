# TCB Discipline — The Three Hard Rules

> "The biggest risk to this project is not technical. It is falling in love with your own ideas."
> — Project architect review, 2026-05-30

This document exists because almost every security infrastructure project that died
did not die from a shortage of ideas. It died from a surplus of ideas.

## What the kernel is

A capability-constrained authorization engine for autonomous agent tool execution.

It answers exactly one question:

> "Does this actor hold a valid, unrevoked, sufficient capability proof for this resource?"

That is everything it does. Anything else lives outside the TCB.

---

## Rule 1 — Anything removable belongs OUTSIDE the TCB

If you can delete code from the TCB without breaking a security invariant,
delete it. Move it to `analysis/`, `extensions/`, or `adapters/`.

The TCB is judged by what it *cannot* do, not by what it can.

**Test:** for every line in `src/tcb/`, ask "what attack becomes possible if I delete this?"
If the answer is "none", the line does not belong in the TCB.

---

## Rule 2 — No semantic concept enters the TCB

Forbidden inside `src/tcb/`:

| Banned term | Why |
|------------|-----|
| `manipulation_score` | requires interpretation |
| `coercion` | semantic |
| `sovereignty_metric` | normative |
| `constitutional` | political |
| `recursive_governance` | semantic |
| `persuasion_score` | heuristic |
| `ethics` | not provable |
| `alignment_score` | undefined |
| `trustworthiness` | subjective |

Permitted inside `src/tcb/`:

| Permitted term | Why |
|---------------|-----|
| `signature` | mathematically defined |
| `capability_chain` | structurally defined |
| `rights` | bitmask, finite |
| `attenuation` | provable invariant |
| `epoch` | integer comparison |
| `binding_hash` | deterministic |
| `subject_id` | cryptographic identity |

The CI guard `TCB v2 purity` enforces this list. Adding a new banned term
requires updating CI and writing a justification.

---

## Rule 3 — Every new TCB line needs a test, a proof, or an invariant

A new line in `src/tcb/` is merged only if it carries one of:

1. **A test** that fails without the new line and passes with it
2. **A Kani proof** (`#[kani::proof]`) that mechanically verifies a property
3. **A Lean theorem** in `formal/lean4/` that proves a structural invariant

PRs that add to the TCB without one of these are rejected. No exceptions.

---

## The three filter questions

Before any change touches `src/tcb/`, the PR author must answer all three:

### Q1: Does this code run on the Permit/Deny path?
If NO → it belongs outside the TCB.

### Q2: Can I write an invariant for this code?
If NO → it belongs outside the TCB.

### Q3: Does a real customer pay for this code?
If NO → it is research. Open a research/ branch, do not merge to TCB.

---

## The hard ceilings

| File | LOC limit | Enforced by |
|------|-----------|-------------|
| `engine.rs`     | ≤ 500 | CI |
| `call_gate.rs`  | ≤ 500 | CI |
| `dag.rs`        | (counted in total) | CI |
| `sequence.rs`   | (counted in total) | CI |
| `types.rs`      | (counted in total) | CI |
| **TCB v2 total**| **≤ 1500** | CI |

Raising any ceiling requires:
1. A PR explaining what attack the new code prevents
2. Sign-off from at least one maintainer
3. A test/proof/invariant per new LOC (Rule 3)

---

## Why this matters

History of security systems that died from semantic contamination:

| System | Initial scope | Final scope | Status |
|--------|---------------|-------------|--------|
| (many AGI safety frameworks) | "ethics" | "civilization governance" | abandoned |
| (many capability prototypes)| capability check | ML-augmented policy | unverifiable |

History of security systems that survived because they refused contamination:

| System | What they did | Status |
|--------|---------------|--------|
| seccomp | syscall allowlist, that's it | in every Linux kernel |
| OpenSSL | cryptography, nothing else | runs the internet |
| SQLite | embedded SQL, no daemons | most-deployed database ever |
| seL4 | microkernel formal verification, narrow scope | first formally verified OS kernel |

**The pattern is identical: solve one problem perfectly. Never solve two.**

---

## What this project IS

> "Cryptographically verifiable capability enforcement layer for autonomous agents."

## What this project IS NOT

- An AGI alignment framework
- A constitutional governance system
- An ethics engine
- A civilization-scale safety layer
- A theory of freedom
- A semantic interpreter

If a contribution makes the project look more like the second list,
it is rejected. No exceptions.

---

## When in doubt

Delete the code.

If the project survives the deletion, the code didn't belong.

---

*Maintained by: TCB Guardian (E-01 per TEAM.md). Reviewed quarterly.*
