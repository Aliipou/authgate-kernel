# TLC Model Checker Setup — authgate-kernel Phase 1.1

This document provides step-by-step setup to run the TLA+ model checker (TLC)
against `formal/authgate_v3.tla` and `formal/MC_AuthGateV3.tla`.

TLC will verify 9 invariants + PermitSoundness exhaustively on the finite
model (3 actors, 3 resources, 3 epochs). Estimated runtime: <5 minutes on
a 4-core machine.

---

## Prerequisites

### Java (required by TLC)

TLC is distributed as `tla2tools.jar` — a self-contained Java application.

```bash
# Ubuntu / Debian
sudo apt-get install default-jdk
java -version   # must be 11+

# macOS (Homebrew)
brew install openjdk@17
java -version

# Windows — download from https://adoptium.net/ (Temurin 17 LTS)
# Then add to PATH: C:\Program Files\Eclipse Adoptium\jdk-17...\bin
java -version
```

### Download tla2tools.jar

```bash
# From GitHub releases (latest stable)
curl -L -o formal/tla2tools.jar \
  "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"

# Verify download
java -jar formal/tla2tools.jar -help 2>&1 | head -3
```

---

## Run TLC

### Standard model check

```bash
cd formal/

# Check MC_AuthGateV3 (finite model — all 9 invariants + PermitSoundness)
java -jar tla2tools.jar -tool MC_AuthGateV3 2>&1 | tee tlc_run.log
```

Expected output (success):
```
Model checking completed. No error has been found.
  Estimates of the state space explored:
  Number of states found: <N>
  Number of distinct states found: <M>
```

### What TLC checks

The `MC_AuthGateV3.cfg` file specifies:

```
SPECIFICATION Spec
INVARIANT
  SovereigntyAlwaysBlocks
  OwnerlessMachineBlocked
  AttenuationHolds
  MachineWithinOwnerScope
  NoDominionWithoutOwnership
  NoForbiddenFlagPermitted
  HighConfidenceRequiresExplicitClaim
  EpochSafetyHolds
  RevocationHonored
THEOREM PermitSoundness
CONSTRAINT MCConstraint
```

`MCConstraint` bounds the state space to ≤3 log entries to make TLC tractable.

### Parallel TLC (faster on multi-core)

```bash
# Use 4 workers
java -jar tla2tools.jar -workers 4 -tool MC_AuthGateV3
```

### With Apalache (symbolic model checker — optional)

Apalache can check some properties symbolically without state enumeration:

```bash
# Install Apalache
curl -L https://github.com/apalache-mc/apalache/releases/download/v0.42.0/apalache.zip -o /tmp/apalache.zip
unzip /tmp/apalache.zip -d /tmp/

# Check one invariant
/tmp/apalache/bin/apalache-mc check \
  --inv=SovereigntyAlwaysBlocks \
  --length=5 \
  formal/authgate_v3.tla
```

---

## CI integration (GitHub Actions)

Add to `.github/workflows/spec-core.yml`:

```yaml
name: TLA+ Model Check
on:
  push:
    branches: [spec-core]
    paths: ['formal/**']

jobs:
  tlc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'
      - name: Download tla2tools
        run: |
          curl -L -o formal/tla2tools.jar \
            "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
      - name: Run TLC
        run: |
          cd formal
          java -workers 4 -jar tla2tools.jar -tool MC_AuthGateV3
        timeout-minutes: 10
```

---

## Interpreting results

### Invariant violation

If TLC finds a violation, it prints a counterexample trace:

```
Error: Invariant SovereigntyAlwaysBlocks is violated.
...
State 1:
  registry = [claims |-> { ... }, owners |-> ... ]
  action = [actor |-> "bot", flags |-> {sovereignty} ...]
  decision = Permit   ← this is the violation
```

What to do:
1. Read the trace — find which transition led to the violation
2. Check if the spec is wrong (does the invariant statement match the intent?)
3. Or check if the implementation is wrong (does `FreedomVerifier.verify()` miss a case?)
4. Open a spec-core PR with the violation counterexample documented

### Liveness / deadlock

TLC also checks for deadlocks (no enabled transitions). A deadlock in the
spec means the state machine is stuck — usually a missing transition.

---

## Current status

**TLC has not yet been run** — this is MASTER_PLAN success criterion #1 (pending Java setup).

The spec (`authgate_v3.tla`) and model (`MC_AuthGateV3.tla`, `MC_AuthGateV3.cfg`)
are complete and ready. The only requirement is Java installation and tla2tools.jar download.

Estimated time to run: <5 minutes on a laptop once Java is available.

---

## After running TLC

1. If all invariants pass: mark criterion #1 ✓ in `TODO.md`
2. Commit `tlc_run.log` to `spec-core` branch
3. Update `formal/COVERAGE.md`: change PENDING TLC → ✓ VERIFIED (date)
4. Update `README.md` badge: TLA+ → VERIFIED
