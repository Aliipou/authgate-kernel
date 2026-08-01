-- formal/lean4/FreedomKernel/Ed25519.lean
--
-- EXPLICIT AXIOM for the unverified Ed25519 signature checker.
--
-- Status: this file is an ASSUMPTION, not a proof. It exists so that every
-- downstream claim that leans on signature checking says so out loud, with a
-- statement precise enough that a cryptographer can disagree with it.
--
-- It replaces `formal/lean4/Proofs.lean:66`
--     axiom sig_euf_cma (key : PrincipalId) (sig msg : List Nat)
--         (h : IsValidSig key sig msg) : True
-- whose conclusion is `True`. That axiom is VACUOUS: `True` is provable without
-- it, so it assumes nothing, grants nothing, and cannot support any theorem.
-- Nothing in this file is inherited from it.
--
-- ── What is being axiomatized ──────────────────────────────────────────────
-- The concrete artifact assumed correct is:
--   ed25519-dalek v2.2.0 (authgate-kernel/Cargo.lock:564-566),
--   `<VerifyingKey as Verifier>::verify`  -- NOT `verify_strict`
-- as invoked at exactly three live call sites:
--   authgate-kernel/src/tcb/dag.rs:62      (root capability signature)
--   authgate-kernel/src/tcb/dag.rs:71      (intermediate delegation signature)
--   authgate-kernel/src/tcb/engine.rs:110  (revocation signature)
-- Feature set: default + rand_core. `batch` OFF, `legacy_compatibility` OFF.
-- Neither ed25519-dalek nor curve25519-dalek carries a machine-checked proof of
-- correctness or of constant-time execution. There is no HACL*/Fiat/EverCrypt
-- code anywhere in the dependency graph.
--
-- ── Scope ──────────────────────────────────────────────────────────────────
-- This axiom constrains `authgate-kernel/src/tcb/dag.rs` and
-- `authgate-kernel/src/tcb/engine.rs`. It says nothing about any other layer.
-- The Python capability path performs NO signature verification at all
-- (src/authgate/kernel/verifier.py contains no crypto call); the Go client
-- never checks the `Signature` field it carries; the CLI has no crypto
-- dependency. Do not cite this axiom outside the Rust TCB.

namespace FreedomKernel.Ed25519

-- ── Abstract syntax ────────────────────────────────────────────────────────
-- Deliberately abstract: modelling the group law would imply a claim to have
-- checked the group law, which we have not.

/-- A 32-byte compressed Edwards point, as it appears on the wire. -/
opaque PubKey : Type

/-- A 64-byte signature (R ‖ S), as it appears on the wire. -/
opaque Sig : Type

/-- The exact byte string passed to `verify`. In this system it is always the
    output of `CapabilityProof::signing_message()` (authgate-kernel/src/tcb/
    types.rs:63-79) or `RevocationProof::signing_message()` (types.rs:120-125). -/
abbrev Msg := List UInt8

/-- The behaviour of the deployed checker: `verify(pk, msg, sig).is_ok()`.
    Uninterpreted — this is the thing we are declining to prove. -/
opaque Verify : PubKey → Msg → Sig → Bool

/-- `Signed pk m` : the holder of the private key matching `pk` has, at some
    point in this system's history, run the signing algorithm on exactly `m`.
    This is the honest-signer query set of the EUF-CMA game. -/
opaque Signed : PubKey → Msg → Prop

/-- `pk` is a low-order point (order dividing 8). ed25519-dalek's non-strict
    `verify` ACCEPTS these; `verify_strict` rejects them
    (ed25519-dalek-2.2.0/src/verifying.rs:357-381). The TCB calls the former,
    performs no `is_weak()` check, and never validates the root key it is
    handed (authgate-kernel/src/tcb/call_gate.rs:32). -/
opaque SmallOrder : PubKey → Prop

/-- The private key matching `pk` has leaked. Out of scope by design
    (THREAT_MODEL.md, DEATH_SCENARIOS.md §4). -/
opaque Compromised : PubKey → Prop

-- ── THE AXIOM ──────────────────────────────────────────────────────────────

/--
**A-ED25519 (EUF-CMA for the deployed checker).**

If the deployed Ed25519 checker accepts `(pk, m, s)`, and `pk` is a well-formed
non-low-order key whose private half has not leaked, then the holder of that
private key actually signed exactly the byte string `m`.

The conclusion is `Signed pk m` — a real proposition, not `True`. Removing this
axiom must break any proof that depends on it; if it does not, the proof never
depended on signatures.

The two hypotheses are not decoration. They are exactly the two guarantees the
code does NOT establish for itself:
  * `¬ SmallOrder pk` — unenforced. The TCB calls non-strict `verify`, never
    calls `is_weak()`, and `CallGate::new` accepts any `VerifyingKey`. A weak
    key admits signatures valid under many messages. Discharging this hypothesis
    is the caller's job, and no code does it.
  * `¬ Compromised pk` — the standard, declared-out-of-scope key-custody
    assumption.
-/
axiom ed25519_euf_cma
    (pk : PubKey) (m : Msg) (s : Sig)
    (hweak : ¬ SmallOrder pk)
    (hkey  : ¬ Compromised pk)
    (hver  : Verify pk m s = true)
    : Signed pk m

-- ── Non-vacuity check ──────────────────────────────────────────────────────
-- The defect in the axiom this file replaces was that it could be deleted with
-- no effect. Guard against repeating that: this lemma is provable ONLY via
-- `ed25519_euf_cma`, so `#print axioms` must list it. If a future edit makes
-- this lemma provable without the axiom, the axiom has gone vacuous again.

theorem accepted_signature_has_an_honest_signer
    (pk : PubKey) (m : Msg) (s : Sig)
    (hweak : ¬ SmallOrder pk) (hkey : ¬ Compromised pk)
    (hver : Verify pk m s = true)
    : Signed pk m :=
  ed25519_euf_cma pk m s hweak hkey hver

-- Expected output: 'FreedomKernel.Ed25519.accepted_signature_has_an_honest_signer'
--   depends on axioms: [FreedomKernel.Ed25519.ed25519_euf_cma]
#print axioms accepted_signature_has_an_honest_signer

-- ── WHAT THIS AXIOM DOES *NOT* GIVE YOU ───────────────────────────────────
-- Stated as prose, not as axioms, because asserting them would be false. Every
-- item below is a gap verified in the code on 2026-08-01, not a hypothetical.
--
-- 1. NOT signature uniqueness, and NOT key uniqueness. `Signed pk m` binds one
--    signer to one message. It does not say `s` is the only signature on `m`,
--    nor that `pk` is a legitimate key. S-malleability specifically IS excluded
--    (`legacy_compatibility` is off, so `check_scalar` enforces S < ℓ —
--    ed25519-dalek-2.2.0/src/signature.rs:89-96), but low-order-point
--    non-uniqueness is NOT, which is why `hweak` is a hypothesis.
--
-- 2. NOT proof of possession by the requester. `CanonicalAction` carries no
--    signature; `binding_hash` is an unkeyed SHA-256 (tcb/types.rs:163-186).
--    A valid chain proves an ISSUER signed a grant. It never proves the party
--    presenting the bundle controls `actor_id`'s private key. Capability
--    bundles are BEARER credentials: whoever copies one can replay it, bounded
--    only by `expiry`/`min_epoch` against a caller-supplied clock
--    (tcb/call_gate.rs:13-15: "Clock integrity is the caller's responsibility").
--
-- 3. NOT integrity of `proof_hash`. `signing_message()` (types.rs:63-79) omits
--    `proof_hash`, and the TCB never recomputes it — yet `proof_hash` is what
--    resolves chain parents (dag.rs:76) and matches revocations (engine.rs:99).
--    An adversary assembling the action can set it freely and recompute the
--    unkeyed `binding_hash`. So a signature says nothing about `proof_hash`.
--
-- 4. NOT revocation. Revocation is fail-open: an invalid revocation signature
--    hits `continue` with no log, no error, no metric (engine.rs:93-96), so a
--    revocation lost to corruption or key rotation degrades to Permit.
--    Combined with (3), a valid signature gives NO assurance the capability has
--    not been revoked. Epoch advancement, not this axiom, is the real mechanism.
--
-- 5. NOT domain separation. The SAME root key signs three grammars with no
--    context string, version byte, or type tag:
--      capability grants   121 B (Root) / 153 B (Delegated)  types.rs:63-79
--      revocations          40 B                             types.rs:120-125
--      rotation certificates 84 B      src/authgate/key_rotation.py:71-79
--    The `0x00`/`0x01` byte at types.rs:71,73 separates Root from Delegated
--    WITHIN the capability grammar; it separates nothing between grammars.
--    Cross-protocol confusion is currently blocked only by the three lengths
--    happening to be pairwise distinct. That is an accident of the present
--    field layout — not a designed property, not tested, and not preserved by
--    any future field addition or variable-length field.
--
-- 6. NOT a statement about `authgate-kernel/src/crypto.rs:97-127`. That
--    function is named `verify_signature` but performs no public-key
--    verification: it re-signs with the PRIVATE key and byte-compares
--    (crypto.rs:123-124), and discards the one real asymmetric call via
--    `let _ = ... verify_strict(...)` (crypto.rs:125). It is currently
--    unreachable (private `mod crypto`, `#[allow(dead_code)]`, zero callers),
--    so it is not a live vulnerability — but any future caller expecting to
--    verify a third party's signature would get a function that cannot.
--
-- 7. NOT constant-time execution. Side channels are out of scope by design
--    (NON_GOALS.md). ed25519-dalek's timing properties are unproved.

end FreedomKernel.Ed25519
