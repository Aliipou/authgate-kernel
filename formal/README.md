# Formal Specification — authgate-kernel

Branch: `spec-core` | Track: Mathematical Truth

## What This Is

The authoritative formal specification of authgate-kernel's security properties.
No code here compiles or deploys. Correctness is established by model checking
(TLC) and/or proof assistant discharge (Lean4, TLAPS).

**Rule:** Every invariant that tcb-core enforces must appear here first.

---

## Files

| File | Purpose |
|---|---|
| `authgate_v3.tla` | TLA+ state machine — the canonical formal model |
| `THREAT_MODEL.md` | Attack taxonomy (AT-1 through AT-7), invariant mapping, open gaps |
| `COVERAGE.md` | Which invariants have TLC instances / Lean proofs |
| `INCOMPLETENESS.md` | Known limits of the formal model (Gödel budget) |
| `FreedomKernel.lean` | Lean4 proof sketches |
| `plan_semantics.md` | Denotational semantics for capability plan IR |
| `distributed/` | Distributed epoch / multi-node extension (research) |
| `kani/` | Rust Kani verification stubs |
| `lean4/` | Lean4 proof modules |
| `proofs/` | TLAPS proof scripts |

---

## TLA+ Spec Overview (`authgate_v3.tla`)

### State Variables

| Variable | Type | Meaning |
|---|---|---|
| `global_epoch` | Nat | Current system epoch; revoked caps have epoch < this |
| `revoked_set` | Set[ProofHash] | Explicitly revoked capability proof hashes |
| `session_rights` | Actor → Rights | Accumulated rights in current session (SequenceContext) |
| `audit_log` | Seq[Entry] | Append-only record of all Permit decisions |

### Key Predicates

```tla
ValidChain(leaf, bundle, min_epoch_val)
  ─ recursive chain validity: sig, attenuation, epoch, subject binding

Verify(action, revoked_set, now)
  ─ pure function mirroring engine.rs: returns Permit or Deny
```

### Invariants (I1–I7)

| Invariant | Name | Enforces |
|---|---|---|
| I1 | EpochSafety | No Permit for cap with epoch < global_epoch |
| I2 | IdentityBinding | SHA-256(issuer_pubkey) == parent.subject_id at every chain node |
| I3 | Attenuation | Child rights ⊆ parent rights at every chain node |
| I4 | RevocationSafety | No Permit for explicitly revoked proof hash |
| I5 | CompositionMono | session_rights only grows monotonically |
| I6 | ResourceBinding | Cap resource must match action resource |
| I7 | ChainEpoch | Every chain node epoch ≥ min_epoch_val |

### Formal Closure Conditions (THEOREMs)

```tla
THEOREM EpochSafetyThm  == [][EpochSafety]_vars
THEOREM IdentityThm     == [][IdentityBinding]_vars
THEOREM AttenuationThm  == [][Attenuation]_vars
THEOREM RevocThm        == [][RevocationSafety]_vars
THEOREM ComposThm       == [][CompositionMono]_vars
```

Status: declared, **not yet TLC-verified** (open gap — see COVERAGE.md).

---

## Running TLC (when Java available)

```bash
# Download TLA+ tools
curl -L https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar -o tla2tools.jar

# Run model checker
java -jar tla2tools.jar -tool MC_AuthGateV3
```

TLC configuration file (`MC_AuthGateV3.tla`) — **pending creation**.

---

## Cross-Branch Consistency Theorem (CBCT)

This branch is the **single source of truth** for what properties the system must
satisfy. The CBCT (defined in BRANCHES.md) requires:

```
CBCT-1: Every Permit decision in main is valid under this spec.
CBCT-2: Every attack in adversarial-lab that violates this spec
         must be closed in tcb-core before merging to main.
CBCT-3: This spec and adversarial-lab are derived independently from main.
```

---

## Adding a New Invariant

1. Define in `authgate_v3.tla` under the `INVARIANTS` section.
2. Add a THEOREM declaration referencing it.
3. Add a row to the invariant table in `THREAT_MODEL.md`.
4. Add a TLC configuration entry in `MC_AuthGateV3.tla`.
5. Update `COVERAGE.md` status (open → checked → proved).

**Do not open a PR to tcb-core until step 4 is done.**
