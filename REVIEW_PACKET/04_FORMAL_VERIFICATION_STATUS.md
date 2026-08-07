# Formal verification status

**Generated 2026-07-29. Every cell reflects what was reproduced on the author's
Windows machine on that date, not what the artifacts are intended to show.**

The rule for this table: a cell is `PASS` only if the command in section 4 was run
and succeeded. Nothing is upgraded on the strength of the artifact existing, being
well written, or having passed in the past. A reviewer who finds one optimistic cell
here is entitled to distrust the entire packet, so the table is deliberately harsh.

## 1. Honest summary, read this first

**No formal artifact in this repository was reproduced on the author's machine on
2026-07-29.** The reason is environmental, not a known defect in the artifacts:

| Blocker | Detail | Consequence |
|---|---|---|
| MSVC linker absent | `cargo test` fails with ``linker `link.exe` not found``. rustc 1.96.0 and cargo 1.96.0 are installed; the Visual Studio C++ build tools are not | No Rust build, no test run, no Kani |
| Kani not installed | `kani` not on PATH | 0 of the harnesses below were re-proved |
| Lean toolchain not resident | `lake` began downloading Lean 4.32.2 on first invocation and did not finish | Lean theorems not rebuilt |
| TLC not run | Java availability unverified on this machine | TLA+ invariants not model-checked |

Any reviewer should therefore treat the columns below as **claims to be tested**, not
as results. If you reproduce any row, please open an issue and say so; that is the
single most useful contribution to this packet.

### Update 2026-08-02 — three rows above are superseded

The 2026-07-29 snapshot is preserved as written. Subsequent execution corrected
it, in both directions:

| Row | 2026-07-29 said | Established 2026-08-02 |
|---|---|---|
| Rust build | MSVC linker absent, no build | **`cargo build` compiles clean** (exit 0) on the gnu toolchain. Note the Kani harnesses are `#[cfg(kani)]` and are *not* compiled by this |
| Lean | toolchain not resident | Toolchain resident (elan 4.2.3, Lean 4.32.2). **5 of 6 Lean files fail to compile**, identically under 4.32.2 and 4.31.0 — so this is a real defect, not version drift |
| TLC | "Java availability unverified" | **Java 17.0.10 is installed and on PATH.** Java was never the blocker. The real blocker: the spec does not parse — `MC_AuthGateV3.tla:42` extends module `AuthGateV3`, but the file is named `authgate_v3.tla`. TLC had therefore never run against this spec, ever |
| Kani | not installed | Unchanged — still not installed, still 0 of the harnesses run |

The TLA+ row is the one that matters most for this packet's credibility: the
stated blocker was false, and the true blocker was a one-line filename mismatch
that any single attempt to run the documented command would have surfaced in
under a second. That is independent evidence that the command had never been
run. See `ASSUMPTIONS.md` and `formal/TLC_SETUP.md`.

## 2. Kani harnesses

`kani::proof` appears **23 times** across non-target Rust sources. Distinct harness
names found in `authgate-kernel/src/kani_proofs.rs`, `authgate-kernel/src/tcb/sequence.rs`
and `formal/kani/`:

| Harness | Property it is written to establish | Re-proved 2026-07-29 |
|---|---|---|
| `prop_permitted_implies_no_violations` | permit implies empty violation set | NOT RUN |
| `prop_blocked_implies_violations_non_empty` | deny implies at least one violation | NOT RUN |
| `prop_permitted_deterministic` | decision is a function of input, no hidden state | NOT RUN |
| `prop_read_denied_without_claim` | read requires an explicit claim | NOT RUN |
| `prop_write_denied_without_claim` | write requires an explicit claim | NOT RUN |
| `prop_delegation_denied_without_delegate_claim` | delegation requires the delegate right | NOT RUN |
| `prop_public_resource_read_permitted` | public read path is reachable, guards against vacuous denial | NOT RUN |
| `prop_ownerless_machine_blocked` | no owner implies no authority | NOT RUN |
| `prop_machine_governs_human_blocked` | machine principal cannot gain authority over a human principal | NOT RUN |
| `prop_seq_accumulated_monotone` | accumulated sequence rights never decrease | NOT RUN |
| `prop_seq_empty_never_exceeds` | empty sequence cannot exceed a limit | NOT RUN |
| `prop_seq_exceeds_limit_consistent` | limit check is consistent across orderings | NOT RUN |
| `prop_seq_idempotent_rights` | repeated identical rights are idempotent | NOT RUN |

**Unwind bounds and stubs are not recorded here yet.** Kani results are meaningless
to a reviewer without them: a proof under `--default-unwind 3` says nothing about
chains of length 4. Fill this in when the harnesses are re-run, one column per
harness, or a reviewer will assume the bound was chosen to make the proof pass.

## 3. TLA+

Specification: `formal/AuthGateV3.tla`, model `formal/MC_AuthGateV3.tla`.

### Update 2026-08-06 — this section is superseded, in the repo's favour

The table below is preserved as written on 2026-07-29, when it said NOT RUN
eleven times. It was still saying NOT RUN four days after TLC had in fact been
run, which is the same defect as over-claiming and is recorded here rather than
edited away.

**Established 2026-08-06 by an independent fresh run at HEAD** (`protocol/domain-separation`,
commit `2465562`, TLC2 2026.07.31.184830, jar sha256 `e22f8ffb…c735d5`, Java 17.0.10):

| Item | Result | Evidence |
|---|---|---|
| Bound 1 (`MC_AuthGateV3_b1.cfg`, `Len(audit_log) <= 1`) | **COMPLETED, no violation.** 2,263,930 states generated / 59,241 distinct / 0 left on queue, depth 6, 113s | `formal/tlc_runs/20260806-220818_fresh_verify_b1.log` |
| Invariants checked at that bound | **36**, all green, including `PermitSoundness` and `BigSafety` — not the ten listed below | `formal/MC_AuthGateV3_b1.cfg:22-63` |
| Non-vacuity | 4 of 4 reachability probes VIOLATE as designed, i.e. Permits are reachable at max epoch, on a second resource, and with mixed bundles | `formal/tlc_runs/20260806-2216*_fresh_probe_*.log` |
| Mutation matrix | **13 caught / 1 redundant / 0 blind** (was 4 caught / 9 escaped at audit) | `formal/tlc_runs/mutation_matrix_20260806-221804.md` |
| Bound 3 (the shipped `MC_AuthGateV3.cfg`) | **DOES NOT COMPLETE** (~10^9 states). No result may be cited at this bound | `formal/TLC_SETUP.md:130` |

The bound is not a formality. A completing TLC run is an exhaustive check of a
**finite** model — here `MCMaxChainDepth = 2`, `MCMaxEpoch = 2`,
`MCResources = {"r1"}`, `Len(audit_log) <= 1`, search depth 6. It is not a proof
for arbitrary N, and the word "verified" is not licensed by it. State the bound
in the same sentence as the result, every time.

**Three invariants were narrowed to get here, and a reviewer should know that
before finding it.** `EpochSafety`, `ResourceBinding` and `ChainEpoch` are now
scoped to the decision witness rather than the whole capability bundle
(`AuthGateV3.tla:265-284`). The wide forms additionally asserted that no *unused*
capability in a permitted bundle is stale or for another resource — bundle
hygiene, which was never an authorisation property of this kernel and is claimed
nowhere in `SEMANTICS.md` or the Rust engine. The wide forms are retained
verbatim as `EpochSafetyWide` / `ResourceBindingWide` / `ChainEpochWide` and
their counterexamples are committed, so the narrowing is checkable rather than
asserted. Attack it anyway if you disagree.

**The second spec, `FreedomKernel.tla`, was model-checked for the first time on
2026-08-06, and one of its four theorems is false.** It previously did not parse
(filename/module mismatch, then `Unknown operator: 'IsSeq'` at line 123) and had
no `.cfg`, so its `THEOREM` lines had never been checked by anything. Both
defects are fixed and it now has a harness. Result:
`THEOREM Spec => []AttenuationHolds` is **refuted** by a three-state
counterexample found in 58 seconds — it quantifies over pairs of claims with no
delegation relation between them and demands they be confidence-ordered, in both
directions at once. It is commented out with the counterexample recorded inline.
`TypeInvariant` and `OwnerlessMachineBlocked` hold at the harness bound;
`SovereigntyAlwaysBlocks` is **vacuous** under that harness because the flags
that would trigger it are pinned `FALSE`, and no green result for it should be
cited. Evidence: `formal/tlc_runs/20260806-2309*` and `*-231747_*`.

This is disclosed here rather than fixed quietly because a repository that
asserts a false theorem for months is exactly what this packet asks reviewers to
look for. None of it bears on the kernel: attenuation as the kernel enforces it
is `Attenuation` in `AuthGateV3.tla`, green at bound 1 and caught by the
mutation matrix.

### Preserved 2026-07-29 snapshot

The config declares ten invariants:

| Invariant | Model-checked 2026-07-29 |
|---|---|
| `TypeInvariant` | NOT RUN |
| `EpochSafety` | NOT RUN |
| `IdentityBinding` | NOT RUN |
| `Attenuation` | NOT RUN |
| `RevocationSafety` | NOT RUN |
| `ResourceBinding` | NOT RUN |
| `ChainEpoch` | NOT RUN |
| `ChainComplete` | NOT RUN |
| `BigSafety` | NOT RUN |
| `PermitSoundness` | NOT RUN |

`CHECK_DEADLOCK FALSE` is set deliberately, since the kernel state machine can always
take another step. Note for reviewers: the model runs under `MCConstraint`, so every
result is bounded by that constraint. The bound must be stated alongside any claim.

## 4. Lean 4

Files: `formal/lean4/Core.lean`, `formal/lean4/Invariants.lean`,
`formal/lean4/Proofs.lean`, `formal/FreedomKernel.lean`.

**`Proofs.lean` documents two admitted results in its own comments**, and these are
the most important lines in this section:

- line 5: cryptographic properties are "stated as axioms reducible to ed25519
  security, those are left as admitted"
- line 74: a step is "admitted here pending code-to-spec correspondence"

Both are defensible choices. Assuming Ed25519 unforgeability as an axiom is normal
practice. The second is not a cryptographic assumption but a **gap between the Lean
model and the Rust implementation**, and a reviewer will go straight for it. State it
as a limitation in every outreach message rather than waiting to be asked.

| Item | Status |
|---|---|
| Lean files build (`lake build`) | NOT RUN, toolchain still downloading |
| Cryptographic axioms | ADMITTED by design, reducible to Ed25519 security |
| Code-to-spec correspondence | ADMITTED, open gap |

## 5. Reproduction

Nothing in this table can be trusted until these run clean on a machine that is not
the author's. Exact toolchain versions must be pinned here once they do.

```bash
# Rust tests. Requires Visual Studio Build Tools with the C++ workload on Windows,
# or any working linker on Linux/macOS.
cd authgate-kernel && cargo test

# Kani. Not installed on the author's machine as of 2026-07-29.
cargo install --locked kani-verifier && cargo kani setup
cargo kani --harness prop_permitted_implies_no_violations

# Lean 4
cd formal/lean4 && lake build

# TLA+. Java 17 IS installed here; the earlier "Java unverified" note was wrong.
# The filename/module mismatch that made this unparseable was fixed on
# tlc-remediation (authgate_v3.tla -> AuthGateV3.tla). This now runs.
# Use the bound-1 cfg: the shipped Len(audit_log) <= 3 does not complete (~10^9 states).
# run_tlc.sh records the command line, jar hash, bound and verbatim output, and
# refuses to report a timeout as a result.
cd formal && ./run_tlc.sh MC_AuthGateV3_b1 my_repro

# Mutation matrix: delete each enforcement check in turn, confirm an invariant fires.
cd formal && ./mutation_matrix.sh MC_AuthGateV3_mut
```

## 6. What this table is for

The point of publishing a table of failures is that it is checkable. A reviewer can
run one command and move a cell, and every moved cell is worth more than any sentence
in the README. If you are reading this because you received an outreach email: the
claim being made to you is **not** "this kernel is verified". The claim is "here are
thirteen bounded properties, ten **declared** invariants and a Lean development, and
here is exactly how to attack them".

Corrected 2026-08-02: the phrase "ten model-checked invariants" above was wrong —
they are ten *declared* invariants, and none had been model-checked when this
packet was written. Worse, and more useful to a reviewer: mutation testing showed
that **deleting 9 of 13 enforcement checks in the model left all ten declared
invariants green.** Several of them could not distinguish a correct
implementation from a broken one, because they re-invoked the same
`Verify`/`ValidChain` definitions that produced the decision under test.

Re-corrected 2026-08-06, and this is the current state: that gap was the point of
the `tlc-remediation` work and it has been closed. The invariant suite was
rewritten — 36 invariants now, including thirteen independent witness/signature
invariants that do not re-invoke `Verify`, and eleven deny-completeness
invariants — and the matrix re-run at HEAD gives **13 caught, 1 redundant, 0
blind**. The one non-catch, `leaf_epoch`, is redundancy rather than blindness:
`AuthGateV3.tla:188` is implied by `AuthGateV3.tla:101` for every input, and
deleting **both** epoch checks together is caught by `EpochSafety` in two
seconds. That double-mutation was reproduced independently on 2026-08-06.

So the invitation stands, just aimed one level deeper. If you attack one thing in
this repository, attack the **bound** — every green result above is exhaustive
over a finite model with `MaxChainDepth = 2`, `MaxEpoch = 2`, one resource, and
an audit log of length 1, and nothing here proves anything about the Rust code
that actually runs. There is no refinement proof from the TLA+ model to the
implementation. That gap is real, it is not on a roadmap, and it is the honest
ceiling of this artifact. See `ASSUMPTIONS.md` for the full mutation matrix,
`formal/MUTATION_NOTES.md` for what a mutation matrix cannot measure, and
`attack_harness/ATTACK_MATRIX.md` for the re-adjudicated per-class verdicts.
