#!/usr/bin/env bash
# TLC run harness for authgate-kernel (branch tlc-remediation).
#
# Usage: ./run_tlc.sh <cfg-basename> <label> [timeout-seconds] [module.tla]
#
# The module defaults to MC_AuthGateV3.tla. Pass MC_FreedomKernel.tla to run the
# FreedomKernel harness, which got its first cfg on 2026-08-06.
#
# Writes a dated, self-describing log to tlc_runs/ containing:
#   exact command line, jar version + SHA-256, the bound, wall-clock,
#   states generated/distinct, and the VERBATIM final TLC output block.
#
# A run that hits the timeout is recorded as TIMED OUT / CUT OFF and is NOT a
# verification result. Do not report one as if it completed.

set -u

CFG="${1:?usage: run_tlc.sh <cfg-basename> <label> [timeout-seconds]}"
LABEL="${2:?missing label}"
TIMEOUT="${3:-1800}"
MODULE="${4:-MC_AuthGateV3.tla}"

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="tlc_runs/${STAMP}_${LABEL}.log"
mkdir -p tlc_runs

JAR_SHA="$(certutil -hashfile tla2tools.jar SHA256 2>/dev/null | sed -n 2p | tr -d ' \r')"
JAR_SIZE="$(stat -c %s tla2tools.jar 2>/dev/null || echo unknown)"
TLC_VER="$(java -jar tla2tools.jar -version 2>&1 | head -1)"
BOUND="$(grep -E '^CONSTRAINT' "${CFG}.cfg" | head -1)"
CMD="java -XX:+UseParallelGC -jar tla2tools.jar -workers auto -config ${CFG}.cfg ${MODULE}"

{
  echo "=============================================================="
  echo "TLC RUN LOG"
  echo "=============================================================="
  echo "label            : ${LABEL}"
  echo "date (local)     : $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "repo branch      : $(git -C "$HERE/.." rev-parse --abbrev-ref HEAD 2>/dev/null)"
  echo "repo commit      : $(git -C "$HERE/.." rev-parse HEAD 2>/dev/null)"
  echo "git dirty        : $(if [ -n "$(git -C "$HERE/.." status --porcelain 2>/dev/null)" ]; then echo YES; else echo no; fi)"
  echo "host             : $(uname -s) $(uname -m)"
  echo "java             : $(java -version 2>&1 | head -1)"
  echo "tlc version      : ${TLC_VER}"
  echo "jar sha256       : ${JAR_SHA}"
  echo "jar size (bytes) : ${JAR_SIZE}"
  echo "module           : ${MODULE}"
  echo "config file      : ${CFG}.cfg"
  echo "bound / constraint: ${BOUND}"
  echo "timeout (s)      : ${TIMEOUT}"
  echo "command line     : ${CMD}"
  echo "=============================================================="
  echo
  echo "----- VERBATIM TLC OUTPUT (parser noise filtered) -----"
} > "$OUT"

START=$(date +%s)
timeout --signal=INT "${TIMEOUT}" $CMD 2>&1 \
  | grep -v "^Parsing file\|^Semantic processing\|^Linting" >> "$OUT"
RC=${PIPESTATUS[0]}
END=$(date +%s)
ELAPSED=$((END - START))

{
  echo "----- END VERBATIM TLC OUTPUT -----"
  echo
  echo "wall clock (s)   : ${ELAPSED}"
  echo "process exit code: ${RC}"
  if [ "$RC" -eq 124 ] || [ "$RC" -eq 130 ]; then
    echo "STATUS           : *** TIMED OUT / CUT OFF AFTER ${TIMEOUT}s ***"
    echo "                   This is NOT a verification result. The state space"
    echo "                   was not exhausted. Do not report it as one."
  elif grep -q "Model checking completed. No error has been found." "$OUT"; then
    echo "STATUS           : COMPLETED - state space exhausted, no violation"
  elif grep -q "^Error: Invariant .* is violated" "$OUT"; then
    echo "STATUS           : COMPLETED - INVARIANT VIOLATED (counterexample above)"
    echo "violated         : $(grep -o 'Invariant [A-Za-z0-9_]* is violated' "$OUT" | head -1)"
  else
    echo "STATUS           : OTHER / see output above"
  fi
} >> "$OUT"

rm -f MC_AuthGateV3_TTrace_*.tla MC_FreedomKernel_TTrace_*.tla
echo "wrote $OUT (exit $RC, ${ELAPSED}s)"
grep -E "^STATUS|^violated|^wall clock" "$OUT"
