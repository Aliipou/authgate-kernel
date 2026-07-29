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

Specification: `formal/authgate_v3.tla`, model `formal/MC_AuthGateV3.tla`, config
`formal/MC_AuthGateV3.cfg`. The config declares ten invariants:

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

# TLA+, requires Java and tla2tools.jar
java -cp tla2tools.jar tlc2.TLC -config formal/MC_AuthGateV3.cfg formal/MC_AuthGateV3.tla
```

## 6. What this table is for

The point of publishing a table of failures is that it is checkable. A reviewer can
run one command and move a cell, and every moved cell is worth more than any sentence
in the README. If you are reading this because you received an outreach email: the
claim being made to you is **not** "this kernel is verified". The claim is "here are
thirteen bounded properties, ten model-checked invariants and a Lean development with
two admitted steps, and here is exactly how to attack them".
