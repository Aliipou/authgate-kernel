#!/usr/bin/env bash
# Mutation matrix for authgate-kernel TLA+ spec (branch tlc-remediation).
#
# For each enforcement check in AuthGateV3.tla: DELETE that check (neutralise it
# to TRUE), run the model checker, and record whether any invariant catches it.
#
#   CAUGHT   = TLC reports an invariant violation with a counterexample.
#              The suite can see this check. This is the desired outcome.
#   ESCAPED  = TLC completes green with the check deleted. The suite is BLIND
#              to this check and its passing carries no information.
#
# The audit found 9 of 13 checks ESCAPED the original ten invariants. This
# script re-measures against the new invariant suite.
#
# SAFETY: the spec is restored from git after every mutation, and the script
# refuses to run if the working tree is dirty. A mutant must never be committed
# as the real spec.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

SPEC="AuthGateV3.tla"
CFG="${1:-MC_AuthGateV3_b1}"
RESULTS="tlc_runs/mutation_matrix_$(date +%Y%m%d-%H%M%S).md"

if [ -n "$(git -C .. status --porcelain -- formal/$SPEC)" ]; then
  echo "REFUSING TO RUN: formal/$SPEC has uncommitted changes."
  echo "Commit or stash first -- this script rewrites and restores it from git."
  exit 1
fi

restore() { git -C .. checkout -- "formal/$SPEC"; }
trap restore EXIT INT TERM

# name | previously-caught? | sed expression neutralising the check
run_mutant() {
  local name="$1" prev="$2" sedexpr="$3"
  restore
  sed -i "$sedexpr" "$SPEC"
  if ! git -C .. diff --quiet -- "formal/$SPEC"; then
    :
  else
    echo "| \`$name\` | $prev | **SED NO-OP - MUTATION NOT APPLIED** | investigate |" >> "$RESULTS"
    echo "  $name: SED NO-OP"
    return
  fi

  local out rc verdict violated
  out="$(timeout --signal=INT 900 java -XX:+UseParallelGC -jar tla2tools.jar \
          -workers auto -config "${CFG}.cfg" "MC_AuthGateV3.tla" 2>&1 \
          | grep -v '^Parsing file\|^Semantic processing\|^Linting')"
  rc=$?
  rm -f MC_AuthGateV3_TTrace_*.tla MC_AuthGateV3_TTrace_*.bin

  if echo "$out" | grep -q "^Error: Invariant .* is violated"; then
    violated="$(echo "$out" | grep -o 'Invariant [A-Za-z0-9_]* is violated' \
                | sed 's/Invariant //;s/ is violated//' | sort -u | tr '\n' ' ')"
    verdict="**CAUGHT**"
  elif echo "$out" | grep -q "Model checking completed. No error has been found."; then
    violated="(none - suite is blind to this check)"
    verdict="**ESCAPED**"
  elif echo "$out" | grep -q "Error: Evaluating invariant\|was interrupted\|TLC threw"; then
    violated="$(echo "$out" | grep -m2 'Error' | tr '\n' ' ')"
    verdict="RUNTIME ERROR"
  else
    violated="(unclear - see raw log)"
    verdict="INCONCLUSIVE / rc=$rc"
  fi

  echo "| \`$name\` | $prev | $verdict | $violated |" >> "$RESULTS"
  echo "  $name -> $verdict ($violated)"

  mkdir -p tlc_runs/mutants
  { echo "MUTANT: $name"; echo "sed: $sedexpr"; echo "cfg: ${CFG}.cfg";
    echo "verdict: $verdict"; echo "violated: $violated"; echo;
    echo "$out"; } > "tlc_runs/mutants/${name}.log"
  restore
}

{
  echo "# Post-fix mutation matrix"
  echo
  echo "- date: $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "- branch: $(git -C .. rev-parse --abbrev-ref HEAD)"
  echo "- commit: $(git -C .. rev-parse HEAD)"
  echo "- cfg: ${CFG}.cfg"
  echo "- bound: $(grep -E '^CONSTRAINT' ${CFG}.cfg | head -1)"
  echo "- tlc: $(java -jar tla2tools.jar -version 2>&1 | head -1)"
  echo "- jar sha256: $(certutil -hashfile tla2tools.jar SHA256 2>/dev/null | sed -n 2p | tr -d ' \r')"
  echo
  echo "CAUGHT = deleting the check produces an invariant violation."
  echo "ESCAPED = the suite still passes green and is blind to that check."
  echo
  echo "| enforcement check | caught BEFORE (audit) | verdict NOW | invariant(s) that fired |"
  echo "|---|---|---|---|"
} > "$RESULTS"

echo "Running mutation matrix against ${CFG}.cfg ..."

# ── the nine the audit found NOT CAUGHT ─────────────────────────────────────
run_mutant "A1_binding_valid_gate" "NO" \
  '182s|.*|  IF FALSE THEN {}   \\* MUTANT: A1 canonical gate deleted|'
run_mutant "root_signature" "NO" \
  '104s|.*|                   /\\ TRUE  \\* MUTANT: root sig check deleted|'
run_mutant "intermediate_signature" "NO" \
  '112s|.*|                   /\\ TRUE  \\* MUTANT: intermediate sig deleted|'
run_mutant "attenuation_A6" "NO" \
  '118s|.*|                      /\\ TRUE  \\* MUTANT: attenuation deleted|'
run_mutant "expiry" "NO" \
  '187s|.*|          /\\ TRUE   \\* MUTANT: expiry check deleted|'
run_mutant "leaf_epoch" "NO" \
  '188s|.*|          /\\ TRUE   \\* MUTANT: leaf epoch gate deleted|'
run_mutant "chain_epoch" "NO" \
  '101s|.*|        ELSE IF FALSE THEN FALSE  \\* MUTANT: chain epoch deleted|'
# I8 (parent-in-bundle). NOTE: the obvious mutation -- replacing line 113 with
# "/\ TRUE" -- is ILL-DEFINED rather than merely unsafe. With the guard gone,
# FindParent's CHOOSE ranges over a bundle that contains no matching parent, so
# TLC throws an exception instead of returning a verdict; that is what the
# 17:12 matrix recorded as RUNTIME ERROR. A mutation must remove the
# REQUIREMENT while keeping the spec well-defined, so this one treats a missing
# parent as acceptable and leaves the rest of the delegated branch intact.
run_mutant "HasParent_completeness" "NO" \
  '113s|.*|                   /\\ IF ~HasParent(current, bundle) THEN TRUE  \\* MUTANT: I8 deleted|; 114s|.*|                      ELSE LET parent == FindParent(current, bundle) IN|'
run_mutant "resource_binding" "NO" \
  '186s|.*|          /\\ TRUE   \\* MUTANT: resource binding deleted|'

# ── the four the audit found already CAUGHT (regression check) ──────────────
run_mutant "identity_binding" "yes" \
  '116s|.*|                      /\\ TRUE  \\* MUTANT: identity binding deleted|'
run_mutant "rights_coverage" "yes" \
  '190s|.*|          /\\ TRUE  \\* MUTANT: rights coverage deleted|'
run_mutant "revocation" "yes" \
  '191s|.*|          /\\ TRUE}  \\* MUTANT: revocation check deleted|'
run_mutant "actor_match" "yes" \
  '184s|.*|    LET actor_caps == {c \\in action.cap_bundle : TRUE}  \\* MUTANT: actor match deleted|'

# ── the check added on this branch ──────────────────────────────────────────
run_mutant "root_key_authority_AT2" "n/a (did not exist)" \
  '110s|.*|                   /\\ TRUE  \\* MUTANT: RootKey authority deleted|'

restore

# HARD SAFETY ASSERTION. A mutant must never survive into the working tree, let
# alone into a commit. If the script was killed mid-run the trap should have
# restored the spec; verify it independently rather than trusting it.
if grep -q "MUTANT" "$SPEC"; then
  echo "!!! FATAL: mutant text still present in $SPEC after restore. !!!"
  echo "!!! Run: git checkout -- formal/$SPEC   before doing anything else. !!!"
  exit 2
fi
if ! git -C .. diff --quiet -- "formal/$SPEC"; then
  echo "!!! FATAL: $SPEC differs from HEAD after restore. !!!"
  exit 2
fi
echo "spec verified clean against HEAD (no mutant survived)"

{
  echo
  echo "## Totals"
  echo
  echo "- CAUGHT:  $(grep -c '| \*\*CAUGHT\*\* |' "$RESULTS")"
  echo "- ESCAPED: $(grep -c '| \*\*ESCAPED\*\* |' "$RESULTS")"
  echo "- other:   $(grep -cE '\| (RUNTIME ERROR|INCONCLUSIVE)' "$RESULTS")"
} >> "$RESULTS"

echo
echo "=== $RESULTS ==="
cat "$RESULTS"
