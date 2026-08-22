# Formal Specification — authgate-kernel

Branch: `spec-core` | Track: Mathematical Truth

**CI:** `.github/workflows/formal.yml` runs TLC + Lean 4 `lake build` on every PR (green on `with-legitimacy`, Aug 2026).

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
| `MC_AuthGateV3.tla` + `.cfg` | Bounded TLC instance |
| `tlc_run.log` | TLC log — completed with no error found (2026-08-20, bounded) |
| `THREAT_MODEL.md` | Attack taxonomy (AT-1 through AT-7), invariant mapping, open gaps |
| `COVERAGE.md` | Which invariants have TLC instances / Lean proofs |
| `INCOMPLETENESS.md` | Known limits — proved vs `sorry` vs axioms (Gödel budget) |
| `TLC_SETUP.md` | How to install `tla2tools.jar` and re-run TLC |
| `lean4/FreedomKernel/` | Lean 4 modules (TCB, Scope, Temporal, MultiAgent, Incompleteness) |
| `plan_semantics.md` | Denotational semantics for capability plan IR |
| `distributed/` | Distributed epoch / multi-node extension (research) |
| `kani/` | Rust Kani verification stubs |
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

Status: **bounded TLC green** (2026-08-20, `Len(audit_log)≤1`, ~4227 distinct states) — see `tlc_run.log` and `COVERAGE.md`. **Re-run in CI:** `formal.yml`. TLAPS / full refinement proofs remain open.

### Lean 4 (FreedomKernel)

Build locally:

```bash
cd formal/lean4/FreedomKernel && lake build
```

| Module | Status |
|--------|--------|
| `TCB.lean` | Proved (forbidden flags, determinism) |
| `Temporal.lean` | `taint_monotone` proved |
| `MultiAgent.lean` | `attenuation_cannot_escalate` proved |
| `Scope.lean` | T-SC3/T-SC4 proved; T-SC1/T-SC5 have 1 `sorry` each |
| `Proofs.lean` | 2 crypto axioms (`sig_euf_cma`, `forged_revocation_harmless`) |

Do not claim “all theorems verified” without the split in `INCOMPLETENESS.md`.

---

## Running TLC (when Java available)

```bash
# Download TLA+ tools (see TLC_SETUP.md)
curl -L https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar -o tla2tools.jar

# Run bounded model checker
java -jar tla2tools.jar -config MC_AuthGateV3.cfg MC_AuthGateV3.tla
```

TLC instance: `MC_AuthGateV3.tla` + `MC_AuthGateV3.cfg` (present; re-run anytime).

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
