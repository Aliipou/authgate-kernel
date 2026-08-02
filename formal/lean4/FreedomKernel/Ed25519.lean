-- formal/lean4/FreedomKernel/Ed25519.lean
--
-- EXPLICIT AXIOMS for the unverified Ed25519 signature checker, SPLIT into the
-- part a verified implementation can discharge and the part nothing can.
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
-- ── 2026-08-02: WHY THE AXIOM IS NOW SPLIT ────────────────────────────────
-- Review advice from Adam Chlipala (MIT CSAIL, Fiat Cryptography), 2026-07-31:
--   "That's a start, though it would also be nice to connect the proofs
--    formally."
-- The previous single axiom `ed25519_euf_cma` conflated two claims that have
-- completely different epistemic status:
--
--   (a) IMPLEMENTATION CORRECTNESS — `Verify` computes exactly the RFC 8032
--       verification predicate. This IS dischargeable, by a verified
--       implementation (HACL*/libcrux, or Fiat-Crypto's field arithmetic).
--   (b) EUF-CMA HARDNESS — that predicate cannot be satisfied by an adversary
--       without the private key. This is a COMPUTATIONAL HARDNESS assumption,
--       established by reduction to discrete log in the random-oracle model.
--       NO implementation proof discharges it, ever.
--
-- Conflating them invites the false claim "the signature checker is verified"
-- once a verified library is linked. The defensible claim after such a swap is:
--   "The checker is verified to compute the RFC 8032 predicate. That the
--    predicate is unforgeable remains a standard cryptographic assumption."
-- The split below makes that distinction machine-checkable rather than
-- rhetorical: see `#print axioms` on each headline theorem.
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
-- correctness or of constant-time execution AS BUILT.
--
-- CORRECTED 2026-08-02: this comment previously read "There is no
-- HACL*/Fiat/EverCrypt code anywhere in the dependency graph." That is false.
-- `fiat-crypto 0.2.9` is pinned at Cargo.lock:634, and curve25519-dalek 4.1.3
-- depends on it unconditionally (Cargo.lock:477-489). Fiat-Crypto's verified
-- field arithmetic is therefore COMPILED BUT NOT SELECTED: the arithmetic
-- backend is chosen at build time and, with no `curve25519_dalek_backend` cfg
-- set, defaults to simd/serial rather than `fiat`. The verified code ships in
-- the dependency tree and is never called.
--
-- Selecting it is one build flag:
--   RUSTFLAGS='--cfg curve25519_dalek_backend="fiat"' cargo build
-- That would cover field arithmetic only — NOT point decompression, NOT
-- small-order handling (see `SmallOrder` below), NOT scalar range checks, and
-- NOT unforgeability. It shrinks this axiom's surface; it does not discharge
-- it. See formal/CRYPTO_VERIFICATION_PLAN.md §3.
--
-- ── Scope ──────────────────────────────────────────────────────────────────
-- These axioms constrain `authgate-kernel/src/tcb/dag.rs` and
-- `authgate-kernel/src/tcb/engine.rs`. They say nothing about any other layer.
-- The Python capability path performs NO signature verification at all
-- (src/authgate/kernel/verifier.py contains no crypto call); the Go client
-- never checks the `Signature` field it carries; the CLI has no crypto
-- dependency. Do not cite these axioms outside the Rust TCB.

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

/-- The behaviour of the DEPLOYED checker: `verify(pk, msg, sig).is_ok()`.
    Uninterpreted — this is the concrete artifact currently linked. -/
opaque Verify : PubKey → Msg → Sig → Bool

/-- The RFC 8032 §5.1.7 verification predicate, as a mathematical object,
    independent of any implementation. This is the specification that a
    verified implementation is verified AGAINST. -/
opaque RFC8032Verify : PubKey → Msg → Sig → Bool

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

-- ── AXIOM (a): IMPLEMENTATION CORRECTNESS — DISCHARGEABLE ──────────────────

/--
**A-ED25519-IMPL (implementation correctness).**

The deployed checker computes exactly the RFC 8032 verification predicate.

This axiom is **dischargeable**. It is precisely what a verified Ed25519
implementation buys you, and it is what the HACL*/libcrux or Fiat-Crypto route
would supply. It carries NO cryptographic hypotheses because it is not a
cryptographic claim — it is a claim about code agreeing with a specification.

To discharge it, inhabit `VerifiedImplementation` below and build the scheme
with `ed25519Verified` instead of `ed25519Assumed`. Doing so removes THIS
axiom from the footprint of every downstream theorem, mechanically, with no
edit to any theorem statement. That is the formal connection.
-/
axiom ed25519_verify_matches_rfc8032
    (pk : PubKey) (m : Msg) (s : Sig)
    : Verify pk m s = RFC8032Verify pk m s

-- ── AXIOM (b): EUF-CMA HARDNESS — IRREDUCIBLE ──────────────────────────────

/--
**A-ED25519-EUFCMA (existential unforgeability under chosen-message attack).**

If the RFC 8032 predicate accepts `(pk, m, s)`, and `pk` is a non-low-order key
whose private half has not leaked, then the holder of that private key actually
signed exactly the byte string `m`.

**This axiom is IRREDUCIBLE.** It is a computational hardness assumption about
the mathematics of Ed25519, established in the literature by reduction to the
discrete logarithm problem in the random-oracle model. No implementation proof
— not HACL*, not Fiat-Crypto, not EverCrypt — discharges it. Any status table
that marks this "verified" after a library swap is wrong.

The conclusion is `Signed pk m` — a real proposition, not `True`. Removing this
axiom must break any proof that depends on it; if it does not, the proof never
depended on signatures.

**THE SPLIT THIS DOCSTRING USED TO DEMAND HAS BEEN CARRIED OUT.** An earlier
version of this passage read "THIS AXIOM CONFLATES TWO SEPARABLE CLAIMS AND
SHOULD BE SPLIT", written when a single fused `ed25519_euf_cma` asserted both
(a) implementation correctness — that `Verify` computes the RFC 8032 predicate —
and (b) cryptographic hardness. That recommendation was acted on: (a) is now
`ed25519_verify_matches_rfc8032` (:134) and (b) is *this* axiom. The warning it
carried still stands and is stated where it belongs, directly above: only (a) is
dischargeable by a verified implementation, so a status table that marks this
axiom "verified" after a library swap is wrong.
See formal/CRYPTO_VERIFICATION_PLAN.md §6.

The two hypotheses are not decoration. They are exactly the two guarantees the
code does NOT establish for itself, and they attach HERE, to hardness, rather
than to implementation correctness — a correct implementation of RFC 8032 is
still forgeable against a low-order or leaked key:
  * `¬ SmallOrder pk` — unenforced. The TCB calls non-strict `verify`, never
    calls `is_weak()`, and `CallGate::new` accepts any `VerifyingKey`. A weak
    key admits signatures valid under many messages. Discharging this hypothesis
    is the caller's job, and no code does it.
  * `¬ Compromised pk` — the standard, declared-out-of-scope key-custody
    assumption.
-/
axiom rfc8032_euf_cma
    (pk : PubKey) (m : Msg) (s : Sig)
    (hweak : ¬ SmallOrder pk)
    (hkey  : ¬ Compromised pk)
    (hver  : RFC8032Verify pk m s = true)
    : Signed pk m

-- ── Non-vacuity checks, one per axiom ──────────────────────────────────────
-- The defect in the axiom this file replaced was that it could be deleted with
-- no effect. Guard against repeating that: each lemma below is provable ONLY
-- via its axiom, so `#print axioms` must list exactly that axiom. If a future
-- edit makes either lemma provable without its axiom, that axiom has gone
-- vacuous and the corresponding claim must be withdrawn.

/-- Non-vacuity witness for AXIOM (a). -/
theorem verify_agrees_with_rfc8032 (pk : PubKey) (m : Msg) (s : Sig) :
    Verify pk m s = true ↔ RFC8032Verify pk m s = true := by
  rw [ed25519_verify_matches_rfc8032]

-- Expected: depends on axioms: [ed25519_verify_matches_rfc8032]
#print axioms verify_agrees_with_rfc8032

/-- Non-vacuity witness for AXIOM (b). -/
theorem rfc8032_accepted_has_an_honest_signer
    (pk : PubKey) (m : Msg) (s : Sig)
    (hweak : ¬ SmallOrder pk) (hkey : ¬ Compromised pk)
    (hver : RFC8032Verify pk m s = true)
    : Signed pk m :=
  rfc8032_euf_cma pk m s hweak hkey hver

-- Expected: depends on axioms: [rfc8032_euf_cma]
#print axioms rfc8032_accepted_has_an_honest_signer

/-- The original headline claim, now visibly resting on BOTH axioms. -/
theorem accepted_signature_has_an_honest_signer
    (pk : PubKey) (m : Msg) (s : Sig)
    (hweak : ¬ SmallOrder pk) (hkey : ¬ Compromised pk)
    (hver : Verify pk m s = true)
    : Signed pk m :=
  rfc8032_euf_cma pk m s hweak hkey ((ed25519_verify_matches_rfc8032 pk m s).symm.trans hver)

-- Expected: depends on axioms:
--   [ed25519_verify_matches_rfc8032, rfc8032_euf_cma]
#print axioms accepted_signature_has_an_honest_signer

-- ── The SignatureScheme interface ──────────────────────────────────────────
-- Per CRYPTO_VERIFICATION_PLAN.md §5.1: parameterise, don't axiomatise.
--
-- The point of this structure is that the kernel is proved against an
-- INTERFACE, not against a particular axiom. Swapping in a verified
-- implementation then becomes an INSTANTIATION that Lean checks, rather than
-- an edit a human asserts. `#print axioms` on a theorem stated over `S` shows
-- no crypto axioms at all; the axioms appear only when a specific instance is
-- supplied. That is the difference between a connected proof and two
-- disconnected artifacts.

/-- The contract the kernel needs from *any* signature checker. -/
structure SignatureScheme where
  PubKey      : Type
  Sig         : Type
  Verify      : PubKey → Msg → Sig → Bool
  Signed      : PubKey → Msg → Prop
  SmallOrder  : PubKey → Prop
  Compromised : PubKey → Prop
  /-- The obligation an implementation must discharge. -/
  euf_cma : ∀ (pk : PubKey) (m : Msg) (s : Sig),
      ¬ SmallOrder pk → ¬ Compromised pk →
      Verify pk m s = true → Signed pk m

/-- The kernel-level theorem, stated over an arbitrary scheme.

    Note the `#print axioms` result: **no axioms at all**. The cryptographic
    obligation has become a hypothesis carried by `S`, so this theorem is
    unconditionally true of every scheme that satisfies the interface. All
    trust has been pushed to the choice of instance, where it is visible. -/
theorem scheme_accepted_signature_has_an_honest_signer
    (S : SignatureScheme)
    (pk : S.PubKey) (m : Msg) (s : S.Sig)
    (hweak : ¬ S.SmallOrder pk) (hkey : ¬ S.Compromised pk)
    (hver : S.Verify pk m s = true)
    : S.Signed pk m :=
  S.euf_cma pk m s hweak hkey hver

-- Expected: does not depend on any axioms
#print axioms scheme_accepted_signature_has_an_honest_signer

-- ── Instance 1: what is actually deployed today ────────────────────────────

/-- The scheme as currently linked: ed25519-dalek's non-strict `verify`, with
    BOTH axioms assumed. This is the only instance available today. -/
def ed25519Assumed : SignatureScheme where
  PubKey      := PubKey
  Sig         := Sig
  Verify      := Verify
  Signed      := Signed
  SmallOrder  := SmallOrder
  Compromised := Compromised
  euf_cma     := accepted_signature_has_an_honest_signer

-- Expected: depends on axioms:
--   [ed25519_verify_matches_rfc8032, rfc8032_euf_cma]
#print axioms ed25519Assumed

-- ── Instance 2: the obligation a verified implementation must discharge ────

/--
**The proof obligation a verified Ed25519 implementation must supply.**

This is the *type* referred to in CRYPTO_VERIFICATION_PLAN.md §5.1. It is
deliberately NOT inhabited here: no verified implementation is linked, so
manufacturing an inhabitant would be a lie. Its value is that it is a
checkable statement of exactly what the HACL*/libcrux (or Fiat-backend) work
has to deliver — an intention turned into a type.
-/
abbrev VerifiedImplementation : Prop :=
  ∀ (pk : PubKey) (m : Msg) (s : Sig), Verify pk m s = RFC8032Verify pk m s

/--
The scheme built from a VERIFIED implementation.

This is a *function* of the obligation, not a fake inhabitant: it cannot be
used until someone supplies `hcorrect`. Note what its axiom footprint proves:

    #print axioms ed25519Verified  -->  [rfc8032_euf_cma]

`ed25519_verify_matches_rfc8032` is GONE — discharged by the hypothesis rather
than assumed — while `rfc8032_euf_cma` remains, exactly as
CRYPTO_VERIFICATION_PLAN.md §6 predicts. That is the machine-checked statement
of what a verified crypto library buys and what it does not, and it is the
deliverable the review advice asked for.
-/
def ed25519Verified (hcorrect : VerifiedImplementation) : SignatureScheme where
  PubKey      := PubKey
  Sig         := Sig
  Verify      := Verify
  Signed      := Signed
  SmallOrder  := SmallOrder
  Compromised := Compromised
  euf_cma     := fun pk m s hweak hkey hver =>
    rfc8032_euf_cma pk m s hweak hkey ((hcorrect pk m s).symm.trans hver)

-- Expected: depends on axioms: [rfc8032_euf_cma]  -- axiom (a) discharged
#print axioms ed25519Verified

-- ── WHAT THESE AXIOMS DO *NOT* GIVE YOU ───────────────────────────────────
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
--    not been revoked. Epoch advancement, not these axioms, is the real
--    mechanism.
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
--    (NON_GOALS.md). ed25519-dalek's timing properties are unproved. NOTE:
--    this is the one gap Route B (libcrux/HACL*) would additionally close,
--    since HACL* carries a machine-checked secret-independence property.
--    Route A (Fiat backend) does NOT close it.
--
-- 8. NOT any connection to a downstream kernel theorem. As of 2026-08-02 NO
--    other file in this Lean development imports this one, so no other theorem
--    in the library currently depends on either axiom. The interface above is
--    the mechanism by which such theorems WOULD inherit the assumption; it is
--    not evidence that any do. Stated explicitly so the interface is not
--    mistaken for coverage it does not yet have.

end FreedomKernel.Ed25519
