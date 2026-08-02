# Mutation testing: what the matrix measures, and what it cannot

Companion to `tlc_runs/mutation_matrix_*.md`. The matrix is a generated table of
verdicts; this file is the interpretation, including the one result that is not
what it looks like.

## Where the numbers stand

| run | CAUGHT | ESCAPED | runtime error |
|---|---|---|---|
| audit (pre-remediation) | 4 | 9 | 0 |
| 2026-08-02 17:12 | 10 | 3 | 1 |
| 2026-08-02 19:08 | **13** | **1** | **0** |

The three escapes and the runtime error at 17:12 had three different causes, and
only two of them were fixable by fixing the model.

Both matrix tables are kept, but `tlc_runs/mutants/` holds per-mutant logs for
the **latest** run only — the harness rewrites them in place, so those logs
correspond to 19:08.

### `intermediate_signature` and `chain_epoch` — missing test data (fixed)

Both escaped because the model contained no input that could distinguish the
mutant from the original, not because any invariant was blind.

- Every capability with `sig_valid = FALSE` was a **root** cap (`BadSigCap`), so
  deleting the *intermediate* signature check changed no decision anywhere.
  Fixed by `BadSigDelegCap` (h13): a delegated cap, identity binding intact, in
  which only the signature is bad.
- Every stale capability was the **leaf** of its own request, so the leaf epoch
  gate rejected it before the chain walk was ever reached. The actual AT-3.1
  attack — a current leaf with a stale ancestor — was not in the model at all.
  Fixed by `StaleParentDelegCap` (h14), whose parent is `StaleCap`.

Both now report CAUGHT (`PermitSoundness`, `ChainEpoch`). A mutation escape of
this kind is a statement about the *test inputs*, and the fix belongs in the
model, not the invariants.

### `HasParent_completeness` — the mutation itself was ill-defined (fixed)

The original mutation replaced the `HasParent` conjunct with `TRUE`. That does
not weaken the spec, it **breaks** it: with the guard gone, `FindParent`'s
`CHOOSE` ranges over a bundle containing no matching parent, which is undefined,
and TLC throws instead of returning a verdict. A mutation has to remove the
*requirement* while leaving the spec well-defined, so it now treats a missing
parent as acceptable and leaves the rest of the delegated branch intact:

```tla
/\ IF ~HasParent(current, bundle) THEN TRUE
   ELSE LET parent == FindParent(current, bundle) IN ...
```

Verdict: CAUGHT (`ChainComplete`), on the `Orphan` action. Worth stating plainly
because a RUNTIME ERROR row is easy to read as "inconclusive, probably fine"
when it actually meant the check had never been tested at all.

### `leaf_epoch` — provably redundant, and it will never be caught

This one is **not** a defect in the invariant suite, and no test data can fix it.

`Witnesses` applies the leaf epoch gate at `AuthGateV3.tla:188`:

```tla
/\ c.epoch >= action.min_epoch                        \* I1 leaf epoch
/\ ValidChain(c, action.cap_bundle, action.min_epoch) \* I2 I3 I7 I8
```

`ValidChain` calls `WalkChain(c, 0, action.min_epoch)`, whose second line is
`ELSE IF current.epoch < mep THEN FALSE` (`AuthGateV3.tla:101`) — the *same*
test, on the *same* capability, against the *same* `min_epoch`, at depth 0.
Line 188 is therefore implied by line 189 for every input. Deleting it cannot
change any decision, so it is semantically inert and TLC is right to report
green.

Demonstrated rather than argued: deleting **both** epoch checks together is
caught immediately — `EpochSafety` fires on the `StaleEpoch` action (h3, epoch 0,
`min_epoch` 2). The suite sees stale leaves perfectly well. Line 188 alone is
simply unobservable.

**The implementation has the same redundancy, and the model is faithful to it.**
`engine.rs:68` denies on `cap.epoch < action.min_epoch`, then `engine.rs:74`
calls `validate_chain(cap, ..., action.min_epoch)`, which starts at
`let mut current = leaf` (`dag.rs:40`) and applies `current.epoch < min_epoch`
(`dag.rs:52`) to that same leaf. So this is a real property of the kernel, not a
modeling artifact — which is the outcome worth having, since the opposite
finding (model diverges from code) would have been much more serious.

**Do not delete `engine.rs:68` on the strength of this.** It is redundant for the
*decision* but not for the *diagnosis*: it produces
`"capability epoch predates minimum required epoch"`, whereas the chain walk
produces `"delegation chain node epoch predates minimum required epoch"`. Three
tests assert the former (`tests.rs:301`, `tests.rs:313`, `tests.rs:586`). The
TLA+ model does not model denial reasons, which is precisely why the mutant is
inert there and would not be inert in the Rust test suite.

## The methodological limit this exposes

A mutation matrix measures observability **at the granularity of the modeled
output**. This model's output is Permit/Deny plus the recorded witness, so a
check whose only unique contribution is a denial *reason* is invisible to it by
construction. "ESCAPED" therefore means one of three different things, and the
matrix alone cannot tell them apart:

1. the invariants are blind (a real gap — fix the invariants),
2. the inputs cannot reach the case (fix the model — the two fixed above),
3. the check is redundant at this granularity (fix nothing; record it).

Report the escape count with that breakdown, never as a bare number. The
honest reading of the current matrix is **13 caught, 1 redundant, 0 blind** —
not "1 escape remaining".

## Maintenance hazard in `mutation_matrix.sh`

The mutations are `sed` expressions keyed to **hardcoded line numbers** in
`AuthGateV3.tla` (101, 104, 110, 112–113, 116, 118, 182–191). Any edit that adds
or removes a line above those points silently retargets every mutation below it.
The script's `SED NO-OP` guard does not protect against this: it only fires when
the file is left *unchanged*, so a mutation landing on the wrong line is
reported as a perfectly ordinary verdict for a check it never touched.

Anyone editing `AuthGateV3.tla` must re-check every line number in the script, or
the matrix should be converted to pattern-anchored `sed` addresses.
