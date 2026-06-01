# OPTIMIZATION.md — What was optimized (and what still needs the Rust build env)

Date: 2026-06-01. Companion to `RED-TEAM-FINDINGS.md`, `SOLUTION.md`, `SPEC-v2-invariants.md`.

## Done in this pass (verified, no regression — 1155 tests still green)

### Security hardening (additive — closes demonstrated runnable exploits)
- **`src/authgate/kernel/hardened.py` — `HardenedVerifier`.** Anchors every security-decisive input in *trusted* state instead of the attacker-supplied `Action`. Closes (with a runnable PoC suite proving each): C3 (actor spoofing), C4 (attacker `min_epoch` / epoch revocation), C5 (self-declared sovereignty flags → advisory only; enforcement is structural), H4 (anonymous / name-based identity), H5 (client-declared `is_public`), H6 (stale snapshot vs live revocation), H1 (naive replay), M7 (dust-confidence). 17/17 adversarial checks pass; see `redteam/test_redteam_regression.py`.
- The hardened path is **additive** — the original `FreedomVerifier` is untouched, so the existing suite cannot regress (verified: `1155 passed`).

### Repo hygiene (real bloat removed)
- **Untracked 317 committed build/cache artifacts**: `.hypothesis/` (146 files), `freedom-kernel/target/debug/...` (compiled binaries — should never be in VCS), `.pytest_cache/`, `.coverage`. `git rm --cached` only — working files untouched.
- **`.gitignore`** extended to cover `.hypothesis/`, `target/`, `freedom-kernel/target/`, `**/target/` so they don't re-enter.
- **Secret hygiene (urgent):** a GitHub Personal Access Token was stored in plaintext in the `origin` remote URL (`.git/config`). Remote re-pointed to a token-less URL. **The exposed token must be rotated** at github.com/settings/tokens — it leaked into tooling logs and must be considered burned.

## High-value optimizations that require the Rust toolchain (cannot verify here)

The Rust crate does not link on this machine (no MSVC C++ build tools), so these are specified, not executed:

1. **C1 — Repoint the FFI/PyO3 to the real TCB (biggest architectural win).** `lib.rs:46`/`ffi.rs` currently route the public ABI to the legacy `src/engine.rs` (v1 registry engine, no signatures), making the audited ed25519 `tcb::` core unreachable dead code. Delete `src/engine.rs`; have `verify_json`/`authgate_kernel_verify` parse a `CanonicalAction`, take a root key fixed at construction, and call `tcb::call_gate`/`tcb::engine`. This single change converts the project from "authorization middleware with a bypassed core" to "the core actually runs."
2. **C4 (Rust) — trusted epoch.** Add `current_epoch: u64` as a `verify()` parameter (like `now`); compare `cap.epoch < current_epoch`; ignore `action.min_epoch`. Make the verifier consult a trusted revocation set, not the attacker's bundle.
3. **H2 — `proof_hash` must commit to the full proof.** `to_canonical_bytes()` excludes the `issuer` discriminant that `signing_message()` includes → Root/Delegated collision affecting parent lookup and revocation matching. Hash `signing_message() ‖ signature`.
4. **H3 — domain separation.** Prefix `CapabilityProof` and `RevocationProof` signing messages with distinct constant tags (they share one root key).
5. **H7 — fix `crypto.rs::verify_signature`.** It re-signs with the private key and discards `verify_strict`. Verify with `verifying_key.verify_strict(...)`.
6. **M1/M2/M3 — DoS surface.** Cap `capability_proofs`/`revocation_proofs` length before any crypto; fix the `MAX_CHAIN_DEPTH` off-by-one (accepts 17); resolve the `panic="abort"` vs `catch_unwind` contradiction.
7. **M8 — dead `tcb/sequence.rs`.** Not declared in `tcb/mod.rs`; the Kani `prop_seq_*` harnesses live in a file that isn't compiled. Declare the canonical one; fix the TCB LOC accounting.
8. **C2 — point the attack simulation at the shipped verifier**, not the in-harness mock (`attack_harness/simulation/engine.py:80-149`).

## Performance / code-quality opportunities (Python, low risk)

- `registry._delegation_chain_valid` scans `self._claims` O(n) per claim; index delegator claims by holder for O(1) lookup (already indexed for direct claims — extend to the delegation path).
- `HardenedVerifier.verify` deep-freezes the registry per call (correct for revocation freshness, but a deep copy). For hot paths, add a registry version/epoch counter and snapshot only on change.
- De-theologize identifiers per `SPEC-v2-invariants.md` Part 4 (`DivineJustice`→`ConstrainedObjective`, `MahdaviCompass`→`InvariantCompass`) and move motivation to a `THEORY-APPENDIX`.

## Priority order

`C1 → C4 → C3/H4/H5 (auth boundary) → C5 → H2/H3/H7 (crypto) → C2/H8 (test the real thing) → M-series (DoS) → perf`.
The Python `HardenedVerifier` already demonstrates the trusted-input model that items C3/C4/C5/H4/H5/H6 require — port the same discipline into the Rust TCB.
