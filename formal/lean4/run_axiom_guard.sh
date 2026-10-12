#!/usr/bin/env bash
# Single entry point for the Lean axiom guard. This is the ONLY place the
# module lists and allowlists live; CI calls this script, and so should you.
#
# Do NOT run `lake env lean check_axioms.lean` directly: without `--run` Lean
# merely elaborates the file, prints nothing and exits 0, which looks like a
# clean result but checks nothing.
#
# Usage:  formal/lean4/run_axiom_guard.sh {authgate|freedomkernel|all}
# Run `lake build` in the relevant package first.
#
# Allowlists are empty: the development declares no axioms beyond Lean's own
# (propext, Classical.choice, Quot.sound). Adding an entry must be a reviewed
# change here AND an entry in the preprint's list of unproved assumptions.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"

authgate() {
  (cd "$root" && lake env lean --run check_axioms.lean "" \
    Authgate.Core Authgate.Invariants Authgate.Proofs)
}

freedomkernel() {
  (cd "$root/FreedomKernel" && lake env lean --run ../check_axioms.lean "" \
    FreedomKernel Scope TCB Temporal MultiAgent Incompleteness)
}

case "${1:-}" in
  authgate) authgate ;;
  freedomkernel) freedomkernel ;;
  all) authgate && freedomkernel ;;
  *) echo "usage: $0 {authgate|freedomkernel|all}" >&2; exit 2 ;;
esac
