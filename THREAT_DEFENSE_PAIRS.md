# Threat ↔ Defense Pairs (Antithesis Model)

For every named attack the project documents, there must be an exactly-named
structural defense. The pairing is what makes the security claim falsifiable:
if you can break the defense for a given attack, the attack class is open.

Format: `AT-X.Y ↔ DEF-X.Y` — each defense is enforced by code, not by policy.

---

## AT-1 ↔ DEF-1: Canonicalization / IR Mismatch

| Attack | Defense | Enforcement site |
|--------|---------|------------------|
| AT-1.1 actor_id field tampered after sealing | DEF-1.1 binding_hash recompute rejects mismatch | `engine.rs:35` (Layer 1) |
| AT-1.2 resource_hash field tampered | DEF-1.2 same — binding_hash includes resource_hash | `engine.rs:35` |
| AT-1.3 required_rights field tampered | DEF-1.3 same — binding_hash includes required_rights | `engine.rs:35` |
| AT-1.4 nonce tampered | DEF-1.4 same — binding_hash includes nonce | `engine.rs:35` |
| AT-1.5 timestamp tampered | DEF-1.5 same — binding_hash includes timestamp | `engine.rs:35` |
| AT-1.6 min_epoch lowered | DEF-1.6 same — binding_hash includes min_epoch | `engine.rs:35` |
| AT-1.7 cap_bytes injected/swapped | DEF-1.7 same — binding_hash includes cap_bytes | `engine.rs:35` |
| AT-1.8 rev_bytes injected | DEF-1.8 same — binding_hash includes rev_bytes | `engine.rs:35` |

**Falsifiability:** if a mutation to any binding-hash-covered field produces Permit, DEF-1 is broken.
**Tests:** `attack_harness/simulation/engine.py` AT-1.* (40 scenarios)

---

## AT-2 ↔ DEF-2: Proof Chain Manipulation

| Attack | Defense | Enforcement site |
|--------|---------|------------------|
| AT-2.1 empty capability bundle | DEF-2.1 reject if no caps for actor | `engine.rs:39` |
| AT-2.2 cross-actor cap reuse | DEF-2.2 subject_id filter — only caps where subject==actor | `engine.rs:51` |
| AT-2.3 cross-resource cap reuse | DEF-2.3 resource_hash match check | `engine.rs:55` |
| AT-2.4 child rights exceed parent | DEF-2.4 attenuation check `(rights & !parent_rights) != 0` | `dag.rs:101` |
| AT-2.5 invalid signature | DEF-2.5 ed25519 verify on every chain node | `dag.rs:62, 72` |
| AT-2.6 expired capability | DEF-2.6 `cap.expiry < now` check | `engine.rs:60` |
| AT-2.7 chain depth exhaustion | DEF-2.7 `MAX_CHAIN_DEPTH = 16` enforced | `dag.rs:23` |
| AT-2.8 insufficient rights | DEF-2.8 `(cap.rights & req) != req` check | `engine.rs:79` |

**Falsifiability:** if any chain producing one of these conditions yields Permit, DEF-2 is broken.

---

## AT-3 ↔ DEF-3: Epoch / Revocation

| Attack | Defense | Enforcement site |
|--------|---------|------------------|
| AT-3.1 stale parent epoch (chain) | DEF-3.1 every chain node checked, not just leaf | `dag.rs:52` |
| AT-3.2 stale leaf epoch | DEF-3.2 `cap.epoch < min_epoch` check | `engine.rs:68` |
| AT-3.3 forged revocation injection | DEF-3.3 only root-signed revocations honored | `engine.rs:108` |
| AT-3.4 revocation suppression | DEF-3.4 N/A — epoch advance is primary, not list-based | (architectural) |
| AT-3.5 nonce replay | DEF-3.5 nonce in binding_hash — different nonce = different action | `types.rs` (compute_hash) |
| AT-3.6 expiry past now | DEF-3.6 same as AT-2.6 | `engine.rs:60` |

---

## AT-4 ↔ DEF-4: Composition / Sequence

| Attack | Defense | Enforcement site |
|--------|---------|------------------|
| AT-4.1 stepwise privilege accumulation | DEF-4.1 SequenceContext tracks accumulated rights | `sequence.rs:56` |
| AT-4.2 read-execute-write exfiltration | DEF-4.2 caller compares accumulated vs session limit | `sequence.rs:74` |
| AT-4.3 multi-actor rights merge | DEF-4.3 policy-layer concern — sequence tracks, policy filters | (architectural) |
| AT-4.4 high-water mark regression | DEF-4.4 bitwise OR is monotonic — Kani proof prop_seq_accumulated_monotone | `sequence.rs:57` |
| AT-4.5 session boundary confusion | DEF-4.5 one SequenceContext per session, caller owns lifecycle | (architectural) |

---

## AT-5 ↔ DEF-5: Identity Binding

| Attack | Defense | Enforcement site |
|--------|---------|------------------|
| AT-5.1 delegation impersonation (forged issuer) | DEF-5.1 SHA-256(issuer_pubkey) must equal parent.subject_id | `dag.rs:95` |
| AT-5.2 all-zeros actor confusion | DEF-5.2 actor_id is opaque 32 bytes — no special-casing | `types.rs` |
| AT-5.3 Python name-based impersonation | DEF-5.3 identity_token in Entity + registry token tracking (C-1) | `registry.py:_enroll_identity` |
| AT-5.4 multi-identity collision (HUMAN x / MACHINE x) | DEF-5.4 compound key (name, kind, resource) | `registry.py:_claim_key` |

---

## AT-6 ↔ DEF-6: Crypto Boundary

| Attack | Defense | Enforcement site |
|--------|---------|------------------|
| AT-6.1 signature forgery (without key) | DEF-6.1 ed25519 EUF-CMA assumption (admitted axiom in Lean) | `formal/lean4/` sig_euf_cma |
| AT-6.2 cross-context proof reuse | DEF-6.2 resource_hash in proof and action must match | `engine.rs:55` |
| AT-6.3 timing-side-channel on hash compare | DEF-6.3 constant-time comparison in verify_binding() | `types.rs` |
| AT-6.4 weak nonce predictability | DEF-6.4 N/A — caller-supplied; deployment responsibility | (DEPLOY) |
| AT-6.5 nonce reuse across actions | DEF-6.5 binding_hash uniqueness derives from nonce | `types.rs:compute_hash` |

---

## AT-7 ↔ DEF-7: Integration / Adapter Boundary

| Attack | Defense | Enforcement site |
|--------|---------|------------------|
| AT-7.1 adapter mutates action between caller and gate | DEF-7.1 binding_hash detects (covers entire action) | `engine.rs:35` |
| AT-7.2 adapter replays a signed action | DEF-7.2 nonce uniqueness + timestamp + caller-side replay cache (DEPLOY) | (DEPLOY) |
| AT-7.3 post-verify mutation | DEF-7.3 same — binding_hash recompute would change | `engine.rs:35` |
| AT-7.4 adapter logs sensitive proof material | DEF-7.4 N/A — adapter is untrusted, do not log proofs in adapter | (architectural) |
| AT-7.5 shadow execution (skip verify entirely) | DEF-7.5 Rust: `engine::verify` is `pub(crate)`. Python: GatedTool name-mangled. OS: WASM/seccomp closes residual | `call_gate.rs` + `call_gate.py` |

---

## Antithesis discipline

For any new attack class added to the attack taxonomy:

1. **Name the structural defense first.** If you cannot name it, the attack is unblocked.
2. **Cite the enforcement site** — exact file:line where the defense is implemented.
3. **Write a falsifiability statement** — "if X happens, DEF-Y is broken."
4. **Add a test** in `attack_harness/simulation/engine.py` that runs the attack and asserts denial.

If a defense relies on `(DEPLOY)` — it is a deployment-time concern, not a code-level
guarantee. Such defenses must be listed in `DEPLOYMENT_READINESS.md`.

If a defense relies on `(architectural)` — it is the caller's responsibility but the
project documents the boundary. Such defenses must be explicit in `NON_GOALS.md`
or this file.

---

## What is NOT defended

Per `NON_GOALS.md` and `formal/INCOMPLETENESS.md`:

| Threat class | Why not defended |
|--------------|------------------|
| Semantic intent verification | Out of scope — kernel does not interpret natural language |
| Side-channel attacks (timing, cache, power) | Out of scope — caller's environmental responsibility |
| Malicious trust root | Out of scope until Phase 4 distributed systems |
| Compiler/toolchain compromise | Out of scope — reproducible builds are a deployment concern |
| Hardware attacks (Rowhammer, Spectre) | Out of scope — defense at hardware/OS level |

These are not "defenses we forgot." They are "defenses out of scope by design."
The threat model boundary is explicit, not hidden.

---

*Updated: 2026-05-30. Re-pair when any AT-* is added or any defense changes.*
