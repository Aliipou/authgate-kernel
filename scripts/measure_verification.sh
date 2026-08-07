#!/usr/bin/env bash
# Measure the verification state of this repository and emit VERIFICATION_STATUS.md.
#
# WHY THIS EXISTS
#
# On 2026-08-06 an audit found that essentially every hand-written count in this
# repository's documentation was wrong, in both directions:
#
#   - formal/COVERAGE.md said "PENDING TLC" on all eleven rows for four days
#     after TLC had run and passed, and named two invariants (I1 CanonicalBinding,
#     I3 ExpiryGate) that exist in no .tla file at all;
#   - it listed 17 Kani harnesses as "proved" when zero had ever been run, two of
#     the names were not symbols in the codebase, and the harness module had not
#     compiled since the domain-separation branch landed;
#   - it listed a Lean theorem, forbidden_implies_blocked, that does not exist,
#     and cited two "cryptographic axioms" that both conclude True and whose own
#     comments say DO NOT CITE;
#   - the Lean theorem count was given as 16 (README), 7 (COVERAGE) and 11
#     (INCOMPLETENESS); measured, it is 39 declared / 34 compiling;
#   - the Rust test count was given as 141; measured, 213;
#   - the TCB was described as "~255 LOC"; measured, 552 lines of non-test source.
#
# The common structure is the whole finding: every one of those was a claim that
# no command could contradict. Markdown is not executable. A THEOREM line with no
# .cfg is a comment. A #[kani::proof] behind #[cfg(kani)] that nothing compiles
# is a comment. Nothing in CI ran lean, lake, kani or tlc; nothing anywhere set
# --cfg kani; and COVERAGE.md was referenced by no script, test or workflow.
#
# Note the drift ran in BOTH directions. That matters. Uniformly optimistic drift
# would point at motivated reasoning, and there is none here. Bidirectional drift
# points at an absence of coupling between the measurements and the prose about
# them, which is a mechanical problem with a mechanical fix.
#
# So this script does not correct numbers. It generates them. CI regenerates and
# fails on any difference, which converts every count below from a claim into a
# build artifact.
#
# Usage:  ./scripts/measure_verification.sh          # write VERIFICATION_STATUS.md
#         ./scripts/measure_verification.sh --check  # fail if it would differ
#
# Deliberately static and fast: greps, line counts, and reads of committed TLC
# logs. It runs no test suite and no model checker, so it is cheap enough to gate
# every push. The dynamic counts belong to the jobs that actually run those tools.

set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1

OUT="VERIFICATION_STATUS.md"
MODE="${1:-write}"
TMP="$(mktemp)"

# ---------------------------------------------------------------- Rust / TCB --
TCB="authgate-kernel/src/tcb/engine.rs authgate-kernel/src/tcb/dag.rs authgate-kernel/src/tcb/call_gate.rs authgate-kernel/src/tcb/types.rs"

tcb_prod_loc() {
  local total=0 f n loc
  for f in $TCB; do
    n=$(grep -n 'cfg(test)' "$f" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$n" ]; then loc=$((n - 1)); else loc=$(wc -l < "$f"); fi
    total=$((total + loc))
  done
  echo "$total"
}

rust_tests=$(grep -rh '^\s*#\[test\]' authgate-kernel/src --include='*.rs' 2>/dev/null | wc -l)
tcb_loc=$(tcb_prod_loc)
tcb_total=$(cat $TCB 2>/dev/null | wc -l)
INTMUT='Mutex|RwLock|RefCell|UnsafeCell|AtomicU|AtomicI|AtomicBool|static mut|thread_local|lazy_static|once_cell|OnceLock'
tcb_intmut=$(grep -hE "$INTMUT" $TCB 2>/dev/null | wc -l)
crate_intmut=$(grep -rhE "$INTMUT" authgate-kernel/src --include='*.rs' 2>/dev/null | wc -l)

tcb_forbid=0
for f in $TCB authgate-kernel/src/tcb/mod.rs; do
  if grep -q 'forbid(unsafe_code)' "$f" 2>/dev/null; then tcb_forbid=$((tcb_forbid + 1)); fi
done
crate_forbid=$(grep -c 'forbid(unsafe_code)' authgate-kernel/src/lib.rs 2>/dev/null || true)
: "${crate_forbid:=0}"

# ---------------------------------------------------------------------- Kani --
# kani::proof ATTRIBUTES are not harnesses: the macro in kani_proofs.rs expands
# to ten. Counting attributes is how "23 harnesses" got into the review packet.
kani_attrs=$(grep -rh 'kani::proof' authgate-kernel/src formal/kani --include='*.rs' 2>/dev/null | wc -l)
kani_unwinds=$(grep -rh 'kani::unwind(' authgate-kernel/src formal/kani --include='*.rs' 2>/dev/null | wc -l)
kani_orphans=0
for m in kani_chain kani_confinement; do
  if [ -f "authgate-kernel/src/tcb/${m}.rs" ]; then
    if ! grep -q "mod ${m}" authgate-kernel/src/tcb/mod.rs 2>/dev/null; then
      kani_orphans=$((kani_orphans + 1))
    fi
  fi
done

# ---------------------------------------------------------------------- Lean --
lean_files=$(find formal -name '*.lean' 2>/dev/null | wc -l)
lean_thms=$(grep -rhE '^[[:space:]]*(theorem|lemma) ' formal --include='*.lean' 2>/dev/null | wc -l)
lean_axioms=$(grep -rhE '^[[:space:]]*axiom ' formal --include='*.lean' 2>/dev/null | wc -l)
# Comments in this repo discuss `sorry` constantly ("Was `sorry`. Now fully
# proved."), so a grep reports seven hits on a development that contains none.
# lean_sorry_check.py strips Lean comments first. Falsification-tested both ways.
if python scripts/lean_sorry_check.py formal > /dev/null 2>&1; then
  lean_sorry=0
else
  lean_sorry=$(python scripts/lean_sorry_check.py formal 2>/dev/null | grep -cE '^  .*\.lean:[0-9]+' || true)
  : "${lean_sorry:=unknown}"
fi
# Declarations whose entire content is `True := trivial` or `:= h` are not results.
lean_trivial=$(grep -rhE ':[[:space:]]*True[[:space:]]*:=[[:space:]]*trivial|^[[:space:]]*(theorem|lemma).*:=[[:space:]]*h[[:space:]]*$' formal --include='*.lean' 2>/dev/null | wc -l)

# ---------------------------------------------------------------------- TLA+ --
tla_invariants=$(sed -n '/^INVARIANTS/,/^CHECK_DEADLOCK/p' formal/MC_AuthGateV3_b1.cfg 2>/dev/null | grep -cE '^[[:space:]]+[A-Za-z][A-Za-z0-9_]*[[:space:]]*$' || true)
: "${tla_invariants:=0}"
tla_specs=$(ls formal/*.tla 2>/dev/null | wc -l)

latest_b1=$(ls -t formal/tlc_runs/*fresh_verify_b1.log 2>/dev/null | head -1)
if [ -n "$latest_b1" ] && grep -q "Model checking completed. No error has been found." "$latest_b1" 2>/dev/null; then
  tlc_status="GREEN"
  # Take the FINAL summary line, not a Progress line. TLC's progress output
  # contains comma-grouped figures like "10,663 distinct states found", and a
  # naive grep pulls "663" out of one of those -- which is how this file briefly
  # reported 663 distinct states for a run that found 59,241. The summary line is
  # the only one ending in "states left on queue."
  summary=$(grep -E '^[0-9]+ states generated, [0-9]+ distinct states found' "$latest_b1" | tail -1)
  tlc_states=$(echo "$summary" | awk '{print $1}')
  tlc_distinct=$(echo "$summary" | awk '{print $4}')
else
  tlc_status="NOT ESTABLISHED"
  tlc_states="-"
  tlc_distinct="-"
fi
: "${tlc_states:=-}" "${tlc_distinct:=-}"

latest_mut=$(ls -t formal/tlc_runs/mutation_matrix_*.md 2>/dev/null | head -1)
mut_caught=$(grep -E '^- CAUGHT:' "$latest_mut" 2>/dev/null | grep -oE '[0-9]+' | head -1)
mut_escaped=$(grep -E '^- ESCAPED:' "$latest_mut" 2>/dev/null | grep -oE '[0-9]+' | head -1)
: "${mut_caught:=0}" "${mut_escaped:=0}"

probes_ok=0
for p in NeverPermits NeverPermitsAtEpoch2 NeverPermitsOnR2 NeverPermitsMixedBundle; do
  l=$(ls -t formal/tlc_runs/*probe_${p}.log 2>/dev/null | head -1)
  if [ -n "$l" ] && grep -q "Invariant ${p} is violated" "$l" 2>/dev/null; then
    probes_ok=$((probes_ok + 1))
  fi
done

# --------------------------------------------------------------------- emit --
cat > "$TMP" <<HDR
# Verification status

<!--
  GENERATED FILE - DO NOT EDIT BY HAND.
  Regenerate with ./scripts/measure_verification.sh
  CI runs it with --check and fails the build if this file is out of date.

  This file exists because on 2026-08-06 every hand-written count in this
  repository was found to be wrong, in both directions. See the header of
  scripts/measure_verification.sh for the full list and the diagnosis.
-->

Generated by \`scripts/measure_verification.sh\` from the working tree.
Every number below is measured. None is asserted.

## Trusted computing base

| Measurement | Value |
|---|---|
| TCB production LOC (4 files, excluding inline tests) | ${tcb_loc} |
| TCB total LOC including inline tests | ${tcb_total} |
| Interior-mutability hits inside the TCB | ${tcb_intmut} |
| Interior-mutability hits across the whole crate | ${crate_intmut} |
| TCB files carrying \`forbid(unsafe_code)\` (of 5, incl. mod.rs) | ${tcb_forbid} |
| Crate-wide \`forbid(unsafe_code)\` in lib.rs | ${crate_forbid} |

\`${tcb_intmut}\` interior-mutability hits inside the TCB is the number that
supports the "pure and stateless" claim. If it is ever non-zero, that claim -
which appears in COVERAGE.md, in the TLA+ refinement argument, and in
correspondence with an external reviewer - must be corrected before anything else
in this file is read.

Crate-wide \`forbid(unsafe_code)\` is \`${crate_forbid}\` and cannot be 1:
\`src/ffi.rs\` uses \`unsafe\` for the C ABI by design. Per-file coverage is what
protects the TCB, which is why the per-file count above is tracked separately.

## Rust tests

| Measurement | Value |
|---|---|
| \`#[test]\` attributes in authgate-kernel/src | ${rust_tests} |

This counts attributes in source, which is deliberately NOT the number \`cargo
test\` reports (213 on 2026-08-06). The difference is tests behind inactive
feature gates - \`src/sandbox.rs\` alone holds 11 that never run under default
features. Quote the \`cargo test\` figure for "tests passing" and this one only
for "tests written", and never substitute one for the other silently: the
figure of 141 that stood in the docs was neither.

## Kani

| Measurement | Value |
|---|---|
| \`kani::proof\` attributes | ${kani_attrs} |
| \`kani::unwind(n)\` bounds recorded | ${kani_unwinds} |
| Harness modules present but not declared in tcb/mod.rs | ${kani_orphans} |

Attribute count is not harness count: the macro in \`kani_proofs.rs\` expands to
ten harnesses from a single attribute. Counting attributes is how "23 harnesses"
entered the review packet.

## Lean 4

| Measurement | Value |
|---|---|
| \`.lean\` files | ${lean_files} |
| \`theorem\`/\`lemma\` declarations | ${lean_thms} |
| \`axiom\` declarations | ${lean_axioms} |
| \`sorry\`/\`admit\` occurrences | ${lean_sorry} |
| Declarations that are \`: True := trivial\` or \`:= h\` | ${lean_trivial} |

The last row is why a bare theorem count overstates the development. Subtract it
before quoting a number, and say which number you are quoting.

## TLA+ / TLC

| Measurement | Value |
|---|---|
| \`.tla\` files under formal/ | ${tla_specs} |
| Invariants checked at bound 1 | ${tla_invariants} |
| Latest bound-1 run | ${tlc_status} |
| States generated / distinct | ${tlc_states} / ${tlc_distinct} |
| Non-vacuity probes violating as designed (of 4) | ${probes_ok} |
| Mutation matrix: caught / escaped | ${mut_caught} / ${mut_escaped} |

A green TLC run means nothing on its own. It is meaningful only together with the
\`${probes_ok}/4\` probes proving Permits are reachable at all, and the
\`${mut_caught}\` enforcement checks proving the invariants are falsifiable. Cite
all three numbers or none of them.

Every TLC result above is at **bound 1** (\`Len(audit_log) <= 1\`,
\`MaxChainDepth = 2\`, \`MaxEpoch = 2\`, one resource). It is an exhaustive check of
a finite model, not a proof for arbitrary N. The shipped bound 3 does not
complete. State the bound in the same sentence as the result, every time.

## What no measurement in this file can tell you

- **No Kani harness has ever been model-checked.** Kani does not install on this
  platform. The counts above are of source constructs, not of proofs.
- **There is no refinement proof from the TLA+ model to the Rust implementation.**
  Every TLC result describes the model. Nothing mechanically connects it to the
  code that runs.
- **The Lean development does not connect to the Rust implementation either.**
  \`Proofs.lean\` records the code-to-spec step as admitted.
HDR

if [ "$MODE" = "--check" ]; then
  if [ ! -f "$OUT" ]; then
    echo "MISSING: $OUT - run ./scripts/measure_verification.sh"
    rm -f "$TMP"
    exit 1
  fi
  if diff -u "$OUT" "$TMP"; then
    echo "VERIFICATION_STATUS.md is up to date."
    rm -f "$TMP"
    exit 0
  else
    echo ""
    echo "VERIFICATION_STATUS.md is STALE - the measured state has changed."
    echo "Run ./scripts/measure_verification.sh and commit the result."
    rm -f "$TMP"
    exit 1
  fi
fi

mv "$TMP" "$OUT"
echo "wrote $OUT"
