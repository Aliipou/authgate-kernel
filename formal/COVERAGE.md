# Formal Verification Coverage

## TLA+ Model Checking

**Status as of 2026-08-06: RUN AND GREEN AT BOUND 1.** Every cell below was
produced by an actual TLC run whose log is committed under `formal/tlc_runs/`.
Read the bound in the same sentence as the result, every time: a completing TLC
run is an exhaustive check of a *finite* model, not a proof for arbitrary N.

```bash
cd formal && ./run_tlc.sh MC_AuthGateV3_b1 <label>
```

| Bound (cfg) | Constraint | Result | Evidence |
|---|---|---|---|
| **1** (`MC_AuthGateV3_b1.cfg`) | `Len(audit_log) <= 1 /\ MCRevBound` | **COMPLETED — no violation.** 2,263,930 states generated, 59,241 distinct, 0 left on queue, depth 6, 113s | `tlc_runs/20260806-220818_fresh_verify_b1.log` |
| 2 (`MC_AuthGateV3_b2.cfg`) | `Len(audit_log) <= 2 /\ MCRevBound` | NOT ESTABLISHED — no completing run committed | — |
| 3 (`MC_AuthGateV3.cfg`, shipped) | `Len(audit_log) <= 3 /\ MCRevBound` | **DOES NOT COMPLETE** (~10^9 states). Never cite a result at this bound | `TLC_SETUP.md:130` |

The bound-1 run checks **36 invariants**, all green — not the ten this table
previously listed. The full list is `MC_AuthGateV3_b1.cfg:22-63`; it is the ten
original invariants plus `CompositionMono`, thirteen independent
witness/signature invariants added on `tlc-remediation`, and eleven
deny-completeness invariants. `PermitSoundness` and `BigSafety` are both among
them and both hold.

> Historical note: the rows this table carried until 2026-08-06 named
> `I1 CanonicalBinding` and `I3 ExpiryGate`, which exist in **no `.tla` file in
> this repository**, and marked all eleven `PENDING TLC` long after TLC had been
> run. Both defects are recorded rather than quietly deleted.

### The green run is not vacuous

A suite that never reaches a Permit satisfies every deny-completeness invariant
trivially. Four probe invariants assert "no Permit is reachable" and are
**expected to fail**; their failure is the proof of reachability. All four
reproduce at HEAD:

| Probe | Result | Evidence |
|---|---|---|
| `NeverPermits` | VIOLATED — Permits reachable | `tlc_runs/20260806-221621_fresh_probe_NeverPermits.log` |
| `NeverPermitsAtEpoch2` | VIOLATED — reachable at `MCMaxEpoch` | `tlc_runs/20260806-221646_fresh_probe_NeverPermitsAtEpoch2.log` |
| `NeverPermitsOnR2` | VIOLATED — reachable on a second resource | `tlc_runs/20260806-221702_fresh_probe_NeverPermitsOnR2.log` |
| `NeverPermitsMixedBundle` | VIOLATED — reachable with mixed bundles | `tlc_runs/20260806-221718_fresh_probe_NeverPermitsMixedBundle.log` |

### The invariants are falsifiable (mutation matrix)

Green is worthless if deleting an enforcement check leaves it green. Deleting
each check in turn and re-running TLC gives **13 CAUGHT / 1 redundant / 0 blind**
(`tlc_runs/mutation_matrix_20260806-221804.md`, per-mutant logs in
`tlc_runs/mutants/`). The single escape, `leaf_epoch`, is redundancy and not
blindness: `AuthGateV3.tla:188` is implied by `AuthGateV3.tla:101` for every
input, and deleting **both** epoch checks together is caught by `EpochSafety` in
2s. See `MUTATION_NOTES.md` — and note that the ESCAPED count must always be
reported with that three-way breakdown, never as a bare number.

### Scoped invariants — disclosed, not hidden

`EpochSafety`, `ResourceBinding` and `ChainEpoch` were **narrowed** on
`tlc-remediation` to quantify over the decision witness rather than the whole
bundle (`AuthGateV3.tla:265-284`). The wide forms asserted bundle hygiene, not
authorisation soundness, and were never claimed by `SEMANTICS.md` or the Rust
engine. They are retained verbatim as `EpochSafetyWide` / `ResourceBindingWide` /
`ChainEpochWide` and their counterexamples are committed, so the narrowing is
checkable rather than asserted.

### FreedomKernel — a second spec, checked for the first time on 2026-08-06

`formal/freedom_kernel.tla` had never been model-checked by anything, because it
could not be. Two defects, both now fixed:

1. the filename did not match its module name (`freedom_kernel` vs
   `FreedomKernel`), which SANY rejects outright — the identical defect that had
   kept `authgate_v3.tla` unparseable, left unfixed on the sibling module;
2. `TypeInvariant` called `IsSeq`, which is not an operator in this module's
   `EXTENDS` and is defined nowhere in the repository.

The file is now `formal/FreedomKernel.tla`, `IsSeq(audit_log)` is replaced by the
faithful type `audit_log \in Seq([action : ActionIR, permitted : BOOLEAN])`, and
the module has its first `.cfg` (`MC_FreedomKernel.cfg`, harness
`MC_FreedomKernel.tla`).

| Property | Result | Evidence |
|---|---|---|
| `TypeInvariant` | holds at the harness bound | `tlc_runs/20260806-231747_freedomkernel_without_refuted_theorem.log` |
| `OwnerlessMachineBlocked` | holds at the harness bound | same |
| `SovereigntyAlwaysBlocks` | **VACUOUS — do not cite.** `MCActionIR` pins all seven sovereignty flags `FALSE`, so the invariant is checked only over inputs that cannot trigger it | same |
| `AttenuationHolds` | **REFUTED.** Three-state counterexample in 58s on its first ever run | `tlc_runs/20260806-230924_freedomkernel_first_ever_run.log` |

`THEOREM Spec => []AttenuationHolds` (`FreedomKernel.tla`) asserted that for
*every* pair of claims with different holders on the same resource where the
second carries `can_delegate`, the first's confidence is `<=` the second's — with
no delegation relation required between them. TLC found two unrelated claims at
confidence 60 and 30 immediately. The property is also self-contradictory when
two such claims both carry `can_delegate`, since it then demands the ordering in
both directions. The theorem is commented out with the counterexample recorded
inline rather than deleted or silently repaired: repairing it means choosing a
new definition of attenuation, which is an authoring decision.

This says nothing about the kernel. Attenuation as the kernel actually enforces
it is `Attenuation` in `AuthGateV3.tla`, which is green at bound 1 and is CAUGHT
by the mutation matrix.

Constants used in MC model:
```
MCActors      = {"a0", "a1", "a2", "a3"}
MCResources   = {"r1"}
MCProofHashes = {"h1", "h2", "h3", "h4", "h5"}
MCPublicKeys  = {"pk0", "pk1", "pk2", "pk3"}
MCRootKey     = "pk0"
MCMaxChainDepth = 2
MCMaxEpoch    = 2
```

## Kani Model Checking

**Status 2026-08-06: NOT RUN. Zero harnesses proved. The table this section
carried until today asserted 17 harnesses "✓ proved"; none of them were.**

This is recorded in full rather than deleted, because the distance between the
old table and the measured state is the most useful thing in this file for
anyone deciding how much of the rest to trust.

| Question | Measured answer |
|---|---|
| Is Kani installed? | No. `cargo install --locked kani-verifier` (0.67.0) does not build on Windows: `std::os::unix::fs::symlink` at `setup.rs:244` (E0433), plus E0599 on `Command::arg0` |
| Can it run under WSL? | No. WSL Ubuntu will not boot — four attempts up to 600s, each `Wsl/Service/CreateInstance/CreateVm/0x800705b4`. `LxssManager` is Stopped |
| How many harnesses exist? | **32** (30 in-repo). `kani::proof` appears 23 times, but the macro at `kani_proofs.rs:87` expands to 10 |
| How many have ever been model-checked? | **0** |
| Would they compile if Kani were present? | **No.** `RUSTFLAGS="--cfg kani" cargo check --lib` exits 101. Beyond the 21 expected `cannot find crate 'kani'` errors there are **11 real type errors** in `src/kani_proofs.rs` |

The 11 type errors are branch drift, not rot: `protocol/domain-separation` added
`trust_domain`, `trust_domains` and `delegation_depth` to the wire types and did
not update the harness helpers. Ordinary `cargo check` exits 0, because nothing
sets `--cfg kani` — the breakage is invisible to every build the project runs.
That is the mechanism by which a table of 17 "proved" rows could survive: no
command anyone ran was capable of contradicting it.

A further **10 harnesses sit in files no compilation unit includes.**
`src/tcb/kani_chain.rs` and `src/tcb/kani_confinement.rs` are not declared in
`src/tcb/mod.rs` — they were moved there from `formal/kani/` and the `mod` lines
were never added. `src/tcb/sequence.rs` is not the `sequence` module bound by
`lib.rs`. Two harnesses in `formal/kani/prop_revocation.rs` are in no cargo
target at all.

**Two names in the old table do not exist as symbols anywhere in the
repository**: `prop_attenuation_two_node` and `prop_epoch_check`. The nearest
real symbols, `proof_attenuation_two_node` and `proof_epoch_check`, are in the
orphan files above.

### Unwind bounds — required before any future Kani result is citable

`MAX_CHAIN_DEPTH = 16` (`src/tcb/dag.rs:23`, enforced at `:44`). Every recorded
bound is far below it: `proof_attenuation_two_node` `unwind(4)`,
`proof_epoch_check` `unwind(2)`, `proof_subject_resource_binding` `unwind(2)`,
`proof_canonical_gate_completeness` `unwind(2)`, `proof_rights_sufficiency`
`unwind(2)`, `prop_seq_step_count_matches_records` `unwind(5)`,
`prop_plan_permitted_means_no_forbidden_flags` `unwind(4)`. Had these run and
passed, they would say nothing about chains of length 3–16 — the range where
chain-walk defects live. Record the bound with every Kani result, exactly as for
TLC: a proof under `unwind(2)` is a statement about two-element inputs.

## Lean 4 Theorems

**Recounted 2026-08-06 against the source. Every prior count in this repository
was wrong, this section's included.** README said 16, this file said 7,
`INCOMPLETENESS.md` said 11. Measured: **39 theorem/lemma declarations, 34 of
which compile, 5 axioms, and zero `sorry` or `admit`.**

| File | Compiling, sorry-free | Count |
|---|---|---|
| `formal/FreedomKernel.lean` | `sovereignty_always_blocks`, `permitted_decidable`, `ownerless_machine_blocked`, `public_read_permitted` | 4 |
| `formal/lean4/FreedomKernel/Ed25519.lean` | `verify_agrees_with_rfc8032`, `rfc8032_accepted_has_an_honest_signer`, `accepted_signature_has_an_honest_signer`, `scheme_accepted_signature_has_an_honest_signer` | 4 |
| `formal/lean4/FreedomKernel/Scope.lean` | 14, incl. `scope_contains_reflexive`, `scope_contains_antisymmetric`, both traversal theorems, `prefix_implies_containment` | 14 |
| `formal/lean4/FreedomKernel/TCB.lean` | 8, incl. `forbidden_flags_always_block`, `verify_deterministic` | 8 |
| `formal/lean4/FreedomKernel/MultiAgent.lean` | `attenuation_cannot_escalate`, `delegation_depth_bounded` | 2 |
| `formal/lean4/FreedomKernel/Temporal.lean` | `taint_monotone`, `no_downward_write` | 2 |
| `formal/lean4/Proofs.lean` | **none — the file does not compile** | 0 of 5 |

**34 is the generous number and must not be quoted on its own.** Four of those
declarations are stated as `: True := trivial`
(`ownerless_machine_must_have_owner`, `machine_cannot_govern_human`,
`no_downward_write`), two are `:= h` — the hypothesis returned unchanged
(`attenuation_cannot_escalate`, `delegation_depth_bounded`) — and two are
`rfl`-trivial. Roughly **26 carry real content**, and most of those concern
small models rather than the shipping kernel. Report it that way.

`Proofs.lean` does not compile. `rights_sufficiency_correct` passes 8 arguments
to the 7-field `CanonicalAction`; `Core.lean` and `Invariants.lean` require
Mathlib, which is not a declared dependency at the pinned toolchain
(`lean-toolchain` pins 4.32.2, Mathlib master needs 4.33.0-rc2); and
`Invariants.lean`'s `ValidSignature`/`ValidRevocation` are ill-typed
(`List Char` supplied where `List Nat` is expected), so INV-SIGCHAIN and
INV-REVOCATION do not exist as statements at all.

### Axioms — 5, and the two this section used to name are empty

| Axiom | Location | What it assumes |
|---|---|---|
| `ed25519_verify_matches_rfc8032` | `Ed25519.lean:134` | `Verify = RFC8032Verify`. Dischargeable in principle by a verified implementation |
| `rfc8032_euf_cma` | `Ed25519.lean:179` | Irreducible cryptographic hardness. Its hypotheses `¬SmallOrder pk` and `¬Compromised pk` are undischarged in code |
| `infinite_horizon_undecidable` | `Incompleteness.lean:17` | A Rice's-theorem style limit |
| `sig_euf_cma` | `Proofs.lean:81` | **Concludes `True`.** Assumes nothing, grants nothing, supports no theorem |
| `forged_revocation_harmless` | `Proofs.lean:95` | **Concludes `True`.** Same |

Until today this section cited `sig_euf_cma` and `forged_revocation_harmless` as
"the cryptographic boundary". They are vacuous, they sit in a file that does not
compile, and their own inline comments say **DO NOT CITE**. The real crypto
boundary is `Ed25519.lean`, whose four theorems each assert their `#print axioms`
footprint inline. `scheme_accepted_signature_has_an_honest_signer` genuinely
`does not depend on any axioms` — it is stated over the `SignatureScheme`
interface, which moves trust to instance choice rather than removing it, and
`VerifiedImplementation` is deliberately uninhabited.

**The caveat that limits all of the above:** no other `.lean` file imports
`FreedomKernel.Ed25519`. The interface is a mechanism, not coverage — no kernel
theorem currently inherits either Ed25519 axiom, because no kernel theorem
connects to it.

**`forbidden_implies_blocked`, which this table listed first for months, is not a
declaration that exists anywhere in the repository.**

### Lean to Rust: no connection

There is no extraction, refinement, or correspondence tooling.
`Proofs.lean:82` — "admitted here pending code-to-spec correspondence".
`formal/CRYPTO_VERIFICATION_PLAN.md:192` — "the code-to-spec step is admitted.
Until it is discharged, the Lean development constrains a model of the kernel,
not the kernel." Lean is also not gated by CI: `formal-verification.yml` runs
TLC only.

## TCB Rust Test Coverage

| File | Tests | Code paths covered |
|---|---|---|
| `engine.rs` (inline) | 5 | Permit, Deny (tampered, expired, stale, wrong actor) |
| `dag.rs` (inline) | 8 | Root, delegation, wrong key, attenuation, AT-5.1, AT-3.1, two-level, resource propagation |
| `sequence.rs` (now `src/sequence.rs`, outside TCB) | 2 | Accumulation, limit detection |
| `tests.rs` | 73 | All 9 invariant paths × permit + deny + boundary |
| `call_gate.rs` (inline) | 22 | Same paths through public API + consistency + AT-7.5 |
| `hardening_tests.rs` | 31 | Resource redirection, malformed crypto, bundle manipulation, depth limit, rights/epoch edge cases, 6 proptest properties |
| **Total** | **213 measured** | The per-file rows above are stale: measured counts are engine.rs 11 (listed 5), dag.rs 7 (listed 8), tests.rs 109 (listed 73). Do not hand-edit; run `scripts/measure_verification.sh` |

## Adversarial Simulation

Run: `python attack_harness/attack_tree_coverage.py`

| Attack class | Scenarios | Result |
|---|---|---|
| AT-1 (IR tampering) | 31 | 0 violations |
| AT-2 (chain manipulation) | 42 | 0 violations |
| AT-3 (epoch/revocation) | 35 | 0 violations |
| AT-4 (composition) | 28 | 0 violations |
| AT-5 (identity binding) | 21 | 0 violations |
| AT-6 (crypto boundary) | 42 | 0 violations |
| AT-7 (integration boundary) | 32 | 0 violations |
| **Total** | **231** | **0 violations** |

## Newly Closed Gaps (this hardening pass)

| ID | Fix | What it closes |
|---|---|---|
| INV-RESOURCE-PROP | Resource propagation in `dag.rs` | Compromised delegator cannot redirect root-granted authority to a different resource. Previously, a delegator with a root-signed cap for R1 could issue a child cap for R2 and the chain would validate. Now rejected with "delegation chain resource mismatch". |
| TCB boundary | Moved `sequence.rs` out of `tcb/` | `SequenceContext` is a policy helper, not a security enforcer. Moving it clarifies the TCB boundary. (The "~255 LOC" figure that stood here until 2026-08-07 was wrong for these four files: measured, they are ~550 lines of non-test source. The current number is generated into `VERIFICATION_STATUS.md`.) |

## Delegation Lattice Theorems (Phase 1.2 — closed)

Proved in `SEMANTICS.md §5`:

| Theorem | Statement | Method |
|---|---|---|
| T1 Transitivity | Rights and confidence both propagate transitively through chains | Pen-and-paper proof; follows from ⊆ and ≤ transitivity |
| T2 Anti-monotonicity | Confidence never increases through any delegation chain | Inductive proof on chain length |
| T3 No Cycles | Delegation graph is a DAG; depth > 16 rejected at wire layer | Registry construction invariant + depth bound |
| T4 BDL | (Rights × [0,1]) forms a bounded distributive lattice under meet=(∩,min), join=(∪,max) | Distributivity of ∩/∪ over sets + min/max over ℝ |

## Scope Containment Theorems (Phase 1.3 formal — added 2026-05-29)

Located in `formal/lean4/FreedomKernel/Scope.lean`.
Mirrors SEMANTICS.md §5 formal properties.

| Theorem | Statement | Status |
|---|---|---|
| T-SC1 Reflexivity | `scopeContains(P, P) = True` for traversal-free P | Admitted (String.normalize induction pending) |
| T-SC2 Root-universal | `scopeContains("", C) = True` for traversal-free C | ✓ Proved |
| T-SC3 Traversal-parent | `hasTraversal(P) → scopeContains(P, C) = False` | ✓ Proved |
| T-SC3b Traversal-child | `hasTraversal(C) → scopeContains(P, C) = False` | ✓ Proved |
| T-SC4 Prefix-implies | `C.startsWith(normalize(P)++"/") → scopeContains(P,C)` | ✓ Proved |
| T-SC5 Antisymmetry | `scopeContains(P,Q) ∧ scopeContains(Q,P) → normalize(P)=normalize(Q)` | Admitted (String antisymmetry pending) |

Security-critical theorems (T-SC3, T-SC3b, T-SC4) are fully proved without sorry.
T-SC1 and T-SC5 require induction over String.normalize / String.startsWith interaction
and are admitted pending Lean 4 String library maturity; they are axiomatically sound
by inspection of the Python implementation.

## Threat Taxonomy (Phase 0, O3 — added 2026-05-29)

Located in `attack_harness/threat_taxonomy/`.
Adversarial ontology, attack class hierarchy, authority escalation tree, delegation abuse catalog, coercion primitives catalog.

| Module | Scenarios | Status |
|--------|-----------|--------|
| `ontology.py` | 21 scenarios across 3 catalogs (ESC-1..6, DEL-1..5, COER-1..10) | Defined |
| `authority_escalation.py` | ESC-1..6: ghost principal, rights amplification, confidence inflation, sovereignty flags, governs-humans, expired claim | All DENY (6/6) |
| `delegation_abuse.py` | DEL-1..5: orphaned delegation, chain amplification, no-delegate flag, self-delegation, scope expansion | All correct (6/6) |
| `coercion_primitives.py` | COER-1..10: 10 sovereignty flags mapped to coercion types | All DENY (10/10) |

Test files: `tests/test_authority_escalation.py`, `tests/test_delegation_abuse.py`, `tests/test_coercion_primitives.py`

**Delegation chain validation (new — 2026-05-29):**
`OwnershipRegistry._delegation_chain_valid()` now enforces at the Python compatibility layer:
- Self-delegation forbidden (T3: DAG invariant)
- Delegator must have a valid `can_delegate=True` claim whose scope contains child scope
- Child rights ⊆ parent rights (A6 attenuation)
- Child confidence ≤ parent confidence (T2 anti-monotonicity)

This closes the Python-layer gap for delegation chain integrity (previously only enforced at Rust TCB level).

## Open Gaps (explicit, not hidden)

| Gap | Description | Why it's acceptable |
|---|---|---|
| G1 | Semantic gap | Kernel doesn't parse intent — by design |
| G3 | Clock trust | Caller-supplied `now` — documented limitation |
| G5 | No replay protection | Kernel is stateless; replay protection belongs in the orchestration layer |
| G6 | Crypto assumptions | ed25519 break = NIST-level threat — out of scope |
| ~~TLC run~~ | **CLOSED 2026-08-06.** TLC runs and is green at bound 1; see the TLA+ section above. The bound remains a real limitation and is stated with every result | — |
| Refinement | No TLA+ → Rust refinement proof | Research-level gap; documented in INCOMPLETENESS.md |

## What Is NOT Formally Verified

- Python compatibility runtime (tested, not proved)
- Extension layer (IFC, manipulation scorer) — heuristic, no formal claims
- Adapter layer boundary semantics
- Distributed consistency (no spec exists yet)
- Implementation-level refinement from TLA+ to Rust
