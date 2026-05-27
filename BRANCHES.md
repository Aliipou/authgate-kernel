# Branch Strategy — authgate-kernel

## Dual Reality Architecture

This repository maintains three separate **truths** that must remain consistent
but never contaminate each other:

```
Execution Truth   ──  main / tcb-core       what actually runs in production
Mathematical Truth ─  spec-core             what the formal model says must hold
Adversarial Truth ──  adversarial-lab       what can break everything
```

Each truth requires a different mode of reasoning. Merging them without proof
produces **self-justifying security** — the most dangerous failure mode.

---

## Branch Map

```
main  (ground truth — immutable baseline)
 ├── spec-core        Mathematical Truth
 │     TLA+ state machine, Lean4 proofs, THREAT_MODEL, COVERAGE
 │     → merges to main only when TLC-verified or Lean-discharged
 │
 ├── tcb-core         Execution Truth
 │     Minimal Rust TCB: engine.rs, dag.rs, types.rs, sequence.rs
 │     Hard LOC gate: ≤ 600 LOC total
 │     → merges to main only when CI passes + attack regression green
 │
 ├── adversarial-lab  Adversarial Truth
 │     Attack harness, simulation engine, mutation grammar
 │     Findings inform spec-core; never merge directly to main
 │
 └── integration      Execution Truth (adapter layer)
       Python model (test oracle), MCP gate, LangGraph adapter
       → merges to main when TCB contract is satisfied
```

---

## Merge Rules — NO CROSS-CONTAMINATION WITHOUT PROOF

```
ALLOWED:
  adversarial-lab  →  spec-core      (new attack class → formal threat model)
  spec-core        →  tcb-core       (proven invariant → Rust implementation)
  tcb-core         →  main           (CI green + regression clean)
  integration      →  main           (TCB contract satisfied)

FORBIDDEN:
  adversarial-lab  →  main           (attack finding ≠ production change)
  adversarial-lab  →  tcb-core       (no proof → no code change)
  spec-core        →  adversarial-lab (backflow breaks independence)
  research         →  main (direct)   (no shortcut past formal + CI)
```

---

## Cross-Branch Consistency Theorem (CBCT)

The system is consistent when all three truths agree:

```
CBCT-1 (Soundness):    ∀ Permit in main  → valid under spec-core model
CBCT-2 (Completeness): ∀ attack in adversarial-lab that breaks spec-core
                            → closed in tcb-core before merging to main
CBCT-3 (Independence): spec-core and adversarial-lab are derived independently
                            from main — no circular self-validation
```

A violation of CBCT-2 is a **known gap** — documented explicitly in
`formal/THREAT_MODEL.md` until closed.

---

## Current Status (2026-05-28)

| Branch | Last commit | Status |
|---|---|---|
| `main` | bf23248 | v2 TCB, AT-5.1 + AT-3.1 closed |
| `spec-core` | 965ac3f | authgate_v3.tla + THREAT_MODEL.md |
| `tcb-core` | 740e374 | TCB_CONSTRAINTS.md, LOC gate defined |
| `adversarial-lab` | current | 231 scenarios, 0 violations |
| `integration` | b0244c8 | Python mirror, BRANCHES.md |

---

## Open Gaps (CBCT-2 violations)

| Gap | Class | Status | Branch |
|---|---|---|---|
| AT-7.5 shadow execution | AT-7 | OPEN | tcb-core (call gate) + integration |
| TLC model-check instance | formal | OPEN | spec-core |
| TLAPS proofs for I1–I7 | formal | OPEN | spec-core |

---

## Per-Branch Guides

### `main` — Ground Truth

The only branch that deploys. Must satisfy:
- All Rust TCB tests pass (`cargo test --lib`)
- Python attack harness clean (`attack_tree_coverage.py`)
- No open CBCT-2 violations without documented known-gap entry

### `spec-core` — Mathematical Truth

What to find here: `formal/authgate_v3.tla`, `formal/THREAT_MODEL.md`,
`formal/COVERAGE.md`, `formal/INCOMPLETENESS.md`

Work here is **never** compiled or deployed. It is the authoritative reference
for what properties tcb-core must satisfy. Correctness is established by:
- TLC model checking (state enumeration)
- TLAPS / Lean4 proof discharge

To add a new invariant: define it in `authgate_v3.tla`, add it to the
invariant table in `THREAT_MODEL.md`, write a TLC configuration entry.

### `tcb-core` — Execution Truth (Rust kernel)

What to find here: `freedom-kernel/src/tcb/` — engine.rs, dag.rs, types.rs,
sequence.rs, call_gate.rs (pending)

Hard rules (enforced by TCB_CONSTRAINTS.md):
- engine.rs ≤ 120 LOC, dag.rs ≤ 120 LOC, total ≤ 600 LOC
- No IO, no network calls, no panics, no unsafe
- Every public function maps to at least one invariant in spec-core

### `adversarial-lab` — Adversarial Truth

What to find here: `attack_harness/` — mutation_attacks.py, sequence_attacks.py,
canonicalization_attacks.py, attack_tree_coverage.py, simulation/

This branch runs **independently** from spec-core. It probes the kernel from
the outside: craft a structurally invalid action, run it through check_action,
verify it was denied. A "violation" = kernel returned Permit for invalid input.

See `attack_harness/simulation/README.md` for simulation engine details.

### `integration` — Execution Truth (adapters)

What to find here: Python model (test oracle only, NOT co-TCB),
MCP gate, LangGraph adapter, OpenAI / Anthropic framework adapters

The Python model in integration **must match** tcb-core behavior on all
inputs. Divergence = integration test failure, not a kernel change.

---

## Dependency Order for New Features

```
1. Define in spec-core (TLA+ invariant or THREAT_MODEL entry)
2. Verify formal property (TLC or Lean proof)
3. Implement in tcb-core (Rust)
4. Close in adversarial-lab (attack scenario must be denied)
5. Mirror in integration (Python oracle updated)
6. Merge to main (all CI green)
```

Skipping steps 1–2 is tech debt. Skipping step 4 is an unclosed CBCT-2 gap.
