# Attack Harness — adversarial-lab

Black-box attack harness for the authgate-kernel TCB. Probes the kernel from the outside using crafted inputs; never reads source code or internal state.

## What this is

A systematic battery of adversarial tests covering 7 orthogonal attack classes. Each test constructs a structurally invalid or malformed action, calls the Python oracle (which mirrors Rust TCB behavior), and asserts the result is Deny. A "violation" means the kernel returned Permit for an invalid input.

## Current results

```
Mutation attacks:         42 tests — 42 PASS, 0 FAIL
Canonicalization attacks:  5 tests —  5 PASS, 0 FAIL
Sequence attacks:          5 tests —  5 PASS, 0 FAIL
Attack tree coverage:     21 tests — 21 PASS, 0 FAIL (KNOWN-GAP: 2)
Simulation engine:       231 scenarios — 0 violations
```

**CBCT-2 open violations: 0.** All attack classes are closed or explicitly documented as out-of-scope.

## Attack classes

| Class | Description | Status |
|---|---|---|
| AT-1 | IR tampering / canonicalization | Closed (L1 binding hash) |
| AT-2 | Proof chain manipulation | Closed (dag.rs validate_chain) |
| AT-3 | Epoch / revocation abuse | Closed (epoch gate + revocation check) |
| AT-4 | Composition / session accumulation | Closed (SequenceContext) |
| AT-5 | Identity binding (delegation impersonation) | Closed (AT-5.1: SHA-256(pubkey) == subject_id) |
| AT-6 | Crypto boundary / context reuse | Closed (resource_hash binding) |
| AT-7 | Integration boundary / shadow execution | Closed (AT-7.5: CallGate structural closure) |

### Known semantic gaps (out-of-scope by design)

| Gap | Why out-of-scope |
|---|---|
| G1: semantic gap | Kernel doesn't parse natural language — intent verification is a separate layer |
| G3: clock trust | Clock integrity is the caller's responsibility; no hardware clock in scope |
| G6: crypto assumptions | ed25519 break requires NIST-level quantum threat; out of scope |

## Files

| File | Contents |
|---|---|
| `mutation_attacks.py` | 20 mutation tests — each mutates one field and expects Deny |
| `canonicalization_attacks.py` | 5 tests for the canonical binding hash gate (Layer 1) |
| `sequence_attacks.py` | 5 tests for SequenceContext composition safety |
| `attack_tree_coverage.py` | 21 tests drawn from the full AT-1 through AT-7 attack tree |

## Running the harness

```bash
python attack_harness/mutation_attacks.py
python attack_harness/canonicalization_attacks.py
python attack_harness/sequence_attacks.py
python attack_harness/attack_tree_coverage.py
```

All four must report 0 FAIL before any merge to main.

## Principles

- **Independence**: the harness derives tests from the threat model and attack tree, never from the kernel source. This preserves CBCT-3.
- **Black-box only**: tests construct inputs, call the oracle, check the output. No internal state inspection.
- **Exact reason strings**: where a test expects Deny, it asserts the exact denial reason — this confirms the right check fired, not just any check.
- **No false positives**: KNOWN-GAP tests assert the gap is still open, not closed. When a gap is closed, the test is promoted to a PASS test.
