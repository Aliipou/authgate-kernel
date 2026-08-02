# TLC Model Checker Setup — authgate-kernel Phase 1.1

This document provides step-by-step setup to run the TLA+ model checker (TLC)
against `formal/authgate_v3.tla` and `formal/MC_AuthGateV3.tla`.

> **Read this first.** Two claims that stood in this document for months were
> false, and are corrected below:
>
> 1. The blocker was never Java. Java 17 is installed and on PATH; TLC was
>    never run because **the committed spec does not parse** (see
>    "Current status").
> 2. The runtime estimate below was never measured. At the bound the model
>    actually ships (`Len(audit_log) <= 3`) the state space is on the order
>    of 10⁹ and does **not** complete.

The cfg declares 10 invariants (`TypeInvariant`, `EpochSafety`,
`IdentityBinding`, `Attenuation`, `RevocationSafety`, `ResourceBinding`,
`ChainEpoch`, `ChainComplete`, `BigSafety`, `PermitSoundness`) over a finite
model of **4 actors, 1 resource, 5 proof hashes, 4 public keys,
MaxChainDepth = 2, MaxEpoch = 2** (`MC_AuthGateV3.tla:46-52`).

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

The `MC_AuthGateV3.cfg` file specifies, verbatim:

```
SPECIFICATION MCSpec

CONSTANTS
  Actors      <- MCActors
  Resources   <- MCResources
  ProofHashes <- MCProofHashes
  PublicKeys  <- MCPublicKeys
  RootKey     <- MCRootKey
  MaxChainDepth <- MCMaxChainDepth
  MaxEpoch    <- MCMaxEpoch
  Hash        <- MCHash

CONSTRAINT MCConstraint

INVARIANTS
  TypeInvariant
  EpochSafety
  IdentityBinding
  Attenuation
  RevocationSafety
  ResourceBinding
  ChainEpoch
  ChainComplete
  BigSafety
  PermitSoundness

CHECK_DEADLOCK FALSE
```

> **Correction.** Every previous revision of this document quoted a config that
> does not exist, naming nine invariants. **Not one of the nine appears in
> `MC_AuthGateV3.cfg`** — the file this document claimed to be quoting.
> Specifically:
>
> - `SovereigntyAlwaysBlocks`, `OwnerlessMachineBlocked`, `AttenuationHolds`,
>   `MachineWithinOwnerScope` are real definitions, but they live in
>   `formal/freedom_kernel.tla` — a **different module, with no `.cfg` at all**
>   (see the ORPHAN notice in that file). Quoting them here attributed the
>   orphan module's invariants to the runnable model.
> - `NoDominionWithoutOwnership`, `NoForbiddenFlagPermitted`,
>   `HighConfidenceRequiresExplicitClaim`, `EpochSafetyHolds`,
>   `RevocationHonored` appear in **no `.tla` or `.cfg` file in this
>   repository** at all.
>
> The quote also wrote `SPECIFICATION Spec` (the real cfg uses `MCSpec`) and
> `THEOREM PermitSoundness`, which is not a TLC config keyword. The block above
> is copied verbatim from the real `MC_AuthGateV3.cfg`.

`MCConstraint == Len(audit_log) <= 3` (`MC_AuthGateV3.tla:277`) is the shipped
bound. It is **not tractable**: 26.5M states generated / 2.3M distinct after
10 minutes on 4 workers with the queue still growing. Use a smaller bound to
get a completing run, and state the bound whenever you cite the result.

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

# Check one invariant (use a name that actually exists in the spec)
/tmp/apalache/bin/apalache-mc check \
  --inv=PermitSoundness \
  --length=5 \
  formal/authgate_v3.tla
```

Apalache has **not** been run against this spec. Nothing below the line
"Apalache can check some properties symbolically" has ever been executed here.

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

**Java was never the blocker.** Java 17.0.10 is installed and on PATH. The
previous text here ("pending Java setup") was false.

**The committed spec does not parse.** Running the exact command this document
gives:

```
Cannot find source file for module AuthGateV3 imported in module MC_AuthGateV3.
*** Errors: 1
```

`MC_AuthGateV3.tla:42` says `EXTENDS AuthGateV3`. TLA+ requires the filename to
match the module name. The module declared on line 1 of `formal/authgate_v3.tla`
is `AuthGateV3`; the **file** is `authgate_v3.tla`. These differ by more than
case, so this fails on every platform. Anyone who had ever run the documented
command once, anywhere, would have hit this in under a second — which is
independent proof that TLC had never been run here.

The fix is a one-line rename (`authgate_v3.tla` → `AuthGateV3.tla`); it is
being made on the `tlc-remediation` branch, not here, because this branch is
scoped to correcting claims rather than changing the model.

The previous claim that the spec and model are "complete and ready" was
therefore also false, and is withdrawn.

---

## After running TLC

1. Commit the run log (with its exact bound and command line) to
   `formal/tlc_runs/`.
2. Update `formal/COVERAGE.md` and the status tables — but record
   **"checked at bound X"**, never "VERIFIED". A completing TLC run at these
   bounds is an exhaustive check of a finite model, not a proof for arbitrary
   N. State the bound in the same sentence as the result, every time.
3. A green run does **not** license a "verified" badge in `README.md`. A green
   run whose invariants cannot detect a deleted enforcement check (see
   `ASSUMPTIONS.md`, mutation matrix) licenses nothing at all — fix the
   invariants first, then re-run.
4. Statuses may only stay the same or go DOWN as a result of review. They go
   up only against a new run or proof committed as evidence.
