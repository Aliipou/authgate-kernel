# RED-TEAM-FINDINGS.md — Brutal Adversarial Review of the Kernel

**Target:** `freedom-kernel-work/` (AuthGate / freedom-kernel).
**Method:** three offensive subagents (Rust TCB / Python+adapters / harness-runner) + direct verification by the lead. Every empirical claim below was either run (Python) or read at file:line (Rust, which does not build here). Findings marked **[verified firsthand]** were re-checked by the lead, not just relayed.
**Date:** 2026-06-01.

## Ground truth about the environment

- **Python 3.13:** the suite runs. `pytest` → **1155 passed**. `attack_harness/simulation` → **230 pass / 1 known-gap / 0 fail** across 231 scenarios.
- **Rust TCB:** **does not link on this machine** (MSVC C++ build tools absent; `link.exe` fails). So `cargo test`, Kani, and the Lean proofs **cannot be reproduced here.** All "formally verified / 1155 tests / Kani+Lean" claims are unverifiable in the author's own environment.

## The two findings that reframe everything

> The project's green dashboards measure code that is **not the code an attacker reaches.**

- **C1 — The shipped entry points bypass the audited TCB.** **[verified firsthand]** `freedom-kernel/src/lib.rs:46`: the PyO3/FFI `verify_json` calls `crate::engine::verify(&vi.registry, &vi.action)` — the **legacy v1 registry engine**, taking a **caller-supplied registry** from JSON — *not* `tcb::engine` / `CallGate` / `dag::validate_chain`. With `crate-type=["cdylib"]`, the ed25519 proof-chain TCB you audited is **unreachable dead code** from any external caller. An attacker submits a registry that grants itself a claim; `verify` returns Permit. No signatures involved.
- **C2 — The flagship "attack simulation" tests a mock, not the product.** **[verified firsthand]** `attack_harness/simulation/engine.py:80-149` defines its *own* `verify_action`/`compute_binding_hash`, where signatures are dictionary flags (`cap.get("sig_valid", True)` — defaults **True**). The 231 "passing adversarial scenarios" validate this re-implementation. The shipped Python `FreedomVerifier` (`verifier.py:128`) has **no crypto, no binding hash, no signatures**; the reachable Rust FFI runs the v1 engine. Textbook CLAUDE.md §3.3 violation: the test passes because the test's own model matches the test's expectations.

---

## Findings, severity-ranked (deduplicated across all three reviewers)

### CRITICAL

| ID | Title | Location | Exploit | Status |
|----|-------|----------|---------|--------|
| **C1** | Shipped FFI/PyO3 routes to v1 registry engine; audited TCB unreachable | `lib.rs:14,46`, `ffi.rs:62` | Caller-supplied registry → self-grant → Permit; ed25519 TCB never invoked | **verified firsthand** |
| **C2** | 231-scenario attack sim validates a mock, not shipped code | `attack_harness/simulation/engine.py:80-149` | Signatures are `sig_valid` booleans defaulting True | **verified firsthand** |
| **C3** | Unauthenticated HTTP API: self-mint authority then use it | `src/authgate/api/app.py:103,126,140,169` | `POST /machine`+`/claim` (no auth) then `/verify` with chosen `actor` → Permit | **ran, output captured** |
| **C4** | Revocation is non-functional against an adversary | Rust `engine.rs:68,74` + Python `registry.py:318,344`, `verifier.py:51` | `min_epoch` is attacker-supplied (no trusted current-epoch input); **and** `advance_epoch` re-stamps the live claim's epoch (1→5), so even an honest `min_epoch=5` check passes the "revoked" claim | **ran + read** |
| **C5** | Corrigibility/sovereignty enforcement is honor-system | Python `verifier.py:53-62,147-163` | The 10 flags (`coerces`,`deceives`,`bypasses_verifier`,`increases_machine_sovereignty`,…) are self-declared booleans defaulting False on the `Action` the agent submits; a recursive-self-improvement-to-remove-constraints action was **PERMITTED** | **ran, output captured** |

### HIGH

| ID | Title | Location | Exploit |
|----|-------|----------|---------|
| **H1** | Replay fully unmitigated; nonce/timestamp decorative | `tcb/engine.rs:27` (stateless), `types.rs:147-150` | Identical re-submission of a valid action permits every time; their own `same_valid_action_permits_twice` documents it |
| **H2** | `proof_hash` preimage omits the `issuer` discriminant → Root/Delegated collision | `types.rs:82-93` vs `:63-79` | `to_canonical_bytes` (proof_hash) excludes `issuer`; `signing_message` includes it. Two proofs differing only in issuer collide on `proof_hash`, which is used for parent lookup (`dag.rs:77`) **and** revocation matching (`engine.rs:99`) |
| **H3** | No domain separation between Capability and Revocation signatures (one root key) | `types.rs:63-79` vs `:120-125` | Neither signed message has a type/domain tag; a signature minted in one context can, under length coincidence/future change, validate in the other |
| **H4** | Name-based TOFU identity; missing token → impersonation | `entities.py:116-119`, `registry.py:108-113` | With no `identity_token`, a fresh `Entity("alice", HUMAN)` inherits alice's claims and is returned as evil_bot's owner |
| **H5** | Client-declared `is_public:true` bypasses all claim/epoch/identity checks | `registry.py:313`, `api/app.py:116` | Per-request `is_public` short-circuits to Permit before any check; read any CREDENTIAL/DATASET |
| **H6** | Stale verifier snapshot: live revocation never reaches a long-lived verifier | `verifier.py:115`, `registry.py:71-78` | Deep-copy freeze means `revoke_all`/`advance_epoch` on the live registry are invisible to an already-built verifier (the natural agent-runtime pattern) |
| **H7** | `verify_signature` re-signs with the private key (verification requires the secret) | `crypto.rs:96-127` | "Verifies" by re-signing and `ct_eq`-comparing; the real `verify_strict` result is discarded (`let _ =`). Defeats public verifiability |
| **H8** | "Formally verified / Kani+Lean / 1155 tests" unreproducible; cited proof artifacts not all present; build fails | repo root, `tcb/mod.rs:19`, `TCB_CONSTRAINTS.md` | No buildable toolchain here; some cited `formal/*.lean`/`.tla` paths not resolvable from the audited tree |

### MEDIUM

| ID | Title | Location | Note |
|----|-------|----------|------|
| **M1** | CPU-DoS amplification: unbounded `capability_proofs` × 16 chain verifies × R·C revocation loop | `engine.rs:51,74,94-103` | No bundle-size cap before crypto |
| **M2** | `MAX_CHAIN_DEPTH` off-by-one: chains of 17 nodes accepted | `dag.rs:44-47` | `depth > 16` after post-increment |
| **M3** | `catch_unwind` is a no-op under `panic="abort"` → reachable panic aborts host process | `ffi.rs:61`, `Cargo.toml` | cdylib in a host process = remote DoS |
| **M4** | "Frozen" snapshot is field-mutable | `registry.py:80-85`, `entities.py:135` | `RightsClaim` is a non-frozen dataclass; `snap._claims[0].can_write=True` escalates |
| **M5** | Revocation matches by `holder.name` only → collateral revoke / DoS | `registry.py:358-419` | Revoking machine "admin" also strips human "admin" |
| **M6** | Machine-dominion guard is an attacker-declared `governs_humans` list | `verifier.py:186-195` | Omit the victim, pass the guard |
| **M7** | `confidence=1e-12` is PERMITTED; 0.8 warn threshold is cosmetic | `entities.py:165`, `verifier.py:213` | `is_valid` accepts any `confidence>0` |
| **M8** | Orphaned `tcb/sequence.rs` not compiled; LOC budget counts the wrong file | `lib.rs:8` vs `tcb/sequence.rs` | The Kani `prop_seq_*` harnesses live in a file that isn't built |

### LOW

| ID | Title | Location |
|----|-------|----------|
| **L1** | `audit_log=None` default → all decisions silently unlogged (API never sets it) | `verifier.py:107,121`, `api/app.py:37` |
| **L2** | `now`/clock fully caller-trusted; `now=0` bypasses every expiry | `engine.rs:26,60` |

---

## Honest non-findings (defenses that HELD under attack)

Reported for fairness — the reviewers tried and failed to break these:

- **`scope_contains` prefix confusion** — `("a/b","a/bc")=False`, `("secret","secrets")=False`. The `+"/"` boundary + traversal guard are correct.
- **`revoke_cascading` direction** — the BFS does revoke the full delegated chain; the dead-code branch is harmless.
- **Forged delegation lineage** — hand-setting `delegated_by` to an empty-handed root is caught by `_delegation_chain_valid`.
- **`identity_token` when actually set** — mismatched/missing token is correctly denied. The defense works; it's just opt-in (H4).
- **Single-action attenuation (child ⊆ parent)** and **live-registry revocation (`freeze=False`)** — genuinely correct and tested.

So the core capability *algebra* is sound. The failures are at the trust boundary and in the wiring, not in the lattice math.

---

## The one cross-cutting root cause

**Almost every critical/high finding is the same mistake: the kernel reads a security-decisive input from the party it is defending against.**

| Decisive input | Who supplies it today | Should be |
|---|---|---|
| `min_epoch` / current epoch | the attacker's Action | trusted host parameter (like `now`) |
| revocation set | the attacker's Action bundle | trusted registry/CRL the verifier consults |
| sovereignty/coercion flags | the attacker's Action | removed (semantic → out of TCB) or externally derived |
| `actor` identity | the HTTP client | authenticated principal, pubkey-bound |
| `is_public` | the per-request body | a registered property of the resource record |
| the registry itself (`verify_json`) | the JSON caller | server-side trusted state |

A capability kernel is only as sound as its trust anchor. This one **anchors several of its guarantees in attacker-controlled fields**, and its real ABI doesn't even reach the part that does anchoring correctly (C1).

---

## Remediation priority (do in this order)

1. **C1 — Repoint the FFI/PyO3 to the real TCB.** Delete `src/engine.rs` (v1); make `verify_json`/`authgate_kernel_verify` parse a `CanonicalAction`, take a root key fixed at construction, and call `CallGate`/`tcb::engine`. Until then, no production protection exists.
2. **C4 — Make epoch & revocation trusted.** Add `current_epoch: u64` as a verify() parameter; reject `cap.epoch < current_epoch`; ignore `action.min_epoch`. Have the verifier consult a trusted revocation set, not the attacker's bundle. Fix `advance_epoch` re-stamping.
3. **C3/H4/H5 — Authenticate the boundary.** Bind `actor` to an authenticated principal; gate `/claim` and `/machine` behind operator auth; make `identity_token`/pubkey mandatory, default-deny; move `is_public` to the registered resource record.
4. **C5 — Drop the self-attested flags** from the enforced path, or stop claiming the kernel enforces corrigibility. A guard the adversary fills in is theater.
5. **H2/H3/H7 — Fix the crypto.** Make `proof_hash` commit to the full proof (include issuer/parent_hash); add per-type domain tags before signing; verify with `verifying_key.verify_strict`, never by re-signing.
6. **C2/H8 — Test the real thing.** Point the attack simulation at the shipped verifier; produce a reproducible build + actual Kani/Lean run logs; stop citing absent artifacts.
7. **M1/M2/M3 — Harden DoS surface.** Cap bundle sizes before crypto; fix the depth off-by-one; resolve the `panic=abort`/`catch_unwind` contradiction.

---

## Verdict: is it industrial / production-grade?

**No — not in the form that runs.** Stated precisely and fairly:

- The capability **lattice** (attenuation, scope containment, identity-when-bound, default-deny) is genuinely sound and well-tested. That is real and worth keeping.
- But the **reachable runtime** (FFI→v1 engine; unauthenticated API; honor-system flags; attacker-controlled epoch/revocation) provides little protection against an adversary, and the **audited secure core is not the code the ABI exposes** (C1). The flagship adversarial metric tests a **mock** (C2).
- The project's *own* docs are commendably honest about much of this (`THREAT_MODEL.md`, `SEMANTICS.md`, `entities.py` C-1 note, `DEPLOYMENT_READINESS.md`: "zero confirmed external deployments"). The problem is the **gap between the marketing language** ("consistent axiomatic system," "production-ready," "formally verified") **and the reachable artifact.**

This is a **strong research prototype with a sound core wired up backwards**, not production infrastructure. Close C1–C5 and re-point the tests at the real code, and it can become the credible capability-confinement substrate that `SOLUTION.md` describes. Ship it as-is under a "production-grade / formally-verified" banner and the first competent adversary — or the first honest external auditor — will reproduce this document.
