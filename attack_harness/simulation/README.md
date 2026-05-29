# AuthGate Adversarial Simulation

Systematically generates and runs **231 adversarial scenarios** across all 7 attack classes. Used as ground-truth for what the Rust TCB must enforce.

## Architecture

```
engine.py
  AttackSpec        — one scenario: label, attack class, expected outcome, run()
  KernelHarness     — thin wrapper around verify_action() for test use
  SimulationEngine  — registers all 231 scenarios, runs them, returns SimulationSummary

run_simulation.py   — CLI runner with --verbose and --class filter
```

**Design principle:** "attack as a typed program" — each scenario is a
`(seed state → mutation → verify → assert outcome)` triple. No mocks, no monkeypatching.
The engine drives the same Python verify model that mirrors engine.rs.

## Scenario distribution

| Class | Count | What it covers |
|-------|-------|---------------|
| Baseline | 30 | Valid positive cases — every right type, nonce patterns, delegation |
| AT-1: IR Mismatch | 40 | Each binding_hash field mutated after sealing (8 fields × 5 variants) |
| AT-2: Proof Chain | 36 | No caps, cross-actor, cross-resource, attenuation escalation, bad sig, expired |
| AT-3: Epoch/Revocation | 30 | Stale epoch, AT-3.1 parent epoch, valid/forged revocation, mixed bundles |
| AT-4: Composition | 25 | Session limit exceeded, high-water mark, multi-actor, stepwise creep |
| AT-5: Identity | 25 | AT-5.1 delegation impersonation, zero-actor, actor substitution |
| AT-6: Crypto | 27 | Cross-context reuse, nonce uniqueness, timestamp boundaries |
| AT-7: Integration | 18 | AT-7.5 shadow execution (KNOWN-GAP), post-verify mutation, adapter replay |
| **Total** | **231** | |

## Outcome codes

| Outcome | Meaning |
|---------|---------|
| `PASS` | Attack blocked — security property holds |
| `KNOWN-GAP` | Attack succeeds but is documented; requires architectural fix |
| `FAIL` | Security regression — invariant violated |

## Running

```bash
cd attack_harness

# Run all 231 scenarios
python simulation/run_simulation.py

# Verbose: see every scenario name and outcome
python simulation/run_simulation.py --verbose

# Filter by attack class
python simulation/run_simulation.py --class "AT-1"
python simulation/run_simulation.py --class "AT-5"
python simulation/run_simulation.py --class "Baseline"
```

## Known gaps

**AT-7.5 — Shadow execution** is the only `KNOWN-GAP`.
An adapter that calls a tool *without* invoking `verify()` completely bypasses the kernel.
Fix: mandatory call gate at the integration boundary (v3 release gate, tracked in TODO.md E1/E2).

## Relationship to Rust TCB

These scenarios run against the **Python verify model** (mirrors `engine.rs`).
They are the ground truth: any scenario that currently `PASS`es must also pass
when the same logic runs through the Rust TCB.

Divergence between Python and Rust outcomes = a refinement gap that must be investigated.
