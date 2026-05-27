# Branch Strategy — authgate-kernel

```
main
 ├── spec-core        research — TLA+ formal spec, Lean4 proofs, threat model
 ├── tcb-core         production — minimal Rust TCB, hardening, size gate
 ├── adversarial-lab  research — attack harness, fuzzing, simulation engine
 └── integration      production — Python adapters, MCP gate, LangGraph bindings
```

## Rules

| Branch | Merges into | Who reviews |
|---|---|---|
| `spec-core` | `main` (when TLC-verified or Lean-discharged) | formal verification track |
| `tcb-core` | `main` (when CI passes + attack regression green) | production track |
| `adversarial-lab` | `adversarial-lab` only; attacks inform `spec-core` and `tcb-core` | research track |
| `integration` | `main` (when TCB contract is satisfied) | adapter track |

## Invariant: spec-core drives tcb-core

A change to `tcb-core` that violates a stated invariant in `spec-core/formal/authgate_v3.tla`
or `spec-core/formal/THREAT_MODEL.md` must not merge to `main`.

The Python mirror in `integration` is a **test oracle only** — not a TCB component.

## Current status (2026-05-28)

- `main`: v2 TCB complete, AT-5.1 + AT-3.1 closed (commit bf23248)
- `spec-core`: authgate_v3.tla + THREAT_MODEL.md added (commit 965ac3f)
- `tcb-core`: branched from main — LOC gate and TCB constraint file pending
- `adversarial-lab`: branched from main — simulation engine skeleton pending
- `integration`: branched from main — Python mirror separation pending

## Open gaps (as of main @ bf23248)

| Gap | Branch responsible | Priority |
|---|---|---|
| AT-7.5 shadow execution | tcb-core (call gate) + integration (adapter contract) | high |
| TLC model-check instance | spec-core | medium |
| TLAPS proofs for I1–I7 | spec-core | medium |
| Adversarial simulation engine | adversarial-lab | medium |
| LOC gate for TCB (≤ 800 LOC) | tcb-core | low |
