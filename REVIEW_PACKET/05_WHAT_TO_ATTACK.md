# What we ask reviewers to attack

**Added 2026-08-02.** This document exists because a reviewer's time is the
scarcest input this project has, and pointing it at the weakest joints is worth
more than pointing it at the strongest ones.

Everything below is a place where we believe the project is weakest. None of it
was extracted by an external reviewer — it came out of an internal adversarial
audit that downgraded our own claims. We are publishing the downgrades because a
documented self-audit is a stronger signal than a green checkmark, and because
every item here is checkable against the repository in minutes.

---

## 0. Start here: the one-command falsification

If you only do one thing, do this one. It is the fastest route to an informed
low opinion of our formal layer, and we would rather you reach it deliberately
than stumble into it.

```bash
cd formal/
java -jar tla2tools.jar -tool MC_AuthGateV3
```

As committed, this fails immediately:

```
Cannot find source file for module AuthGateV3 imported in module MC_AuthGateV3.
```

`MC_AuthGateV3.tla:42` extends module `AuthGateV3`; the file is named
`authgate_v3.tla`. TLA+ requires filename to match module name. This is a
one-line rename — but it is *proof* that TLC had never been run here, because
anyone who ran the documented command once, anywhere, would have hit it in under
a second. Documents in this repo previously blamed a missing Java runtime. That
was false; Java 17 is installed.

**What we ask:** confirm the reasoning, and tell us whether you think a project
in this state should have been describing invariants as "verified" anywhere.
We think not, and have retracted those claims, but the calibration question is
genuinely useful to us.

---

## 1. Axiom-translation fidelity — the core open problem

The project asserts axioms A1–A7 ("Theory of Liberty") and claims the kernel's
authorization semantics are grounded in them. That grounding requires three
independent links per axiom:

1. Does the formal translation preserve the axiom's **meaning**?
2. Is the translated property actually **proven in the model**?
3. Is the **code a (contextual) refinement** of the model?

Any broken link and the axioms are philosophical decoration. We currently cannot
show all three for any axiom — no axiom scores fully discharged. See
`ASSUMPTIONS.md` for the per-axiom table.

**What we ask:** attack link (1) specifically. It is the one no amount of
tooling fixes, and the one where we are most likely to be fooling ourselves. If
an axiom's plain-language statement and its TLA+/Lean translation have come
apart, we would rather learn it from you than from a referee.

---

## 2. The invariants cannot detect their own enforcement being deleted

This is the finding we consider most serious.

Method: delete one enforcement check from the model, re-run TLC against the
**unmodified** ten-invariant config, see whether anything fires.

Result: **9 of 13 enforcement checks can be deleted with every declared
invariant still green.** Not caught: the `binding_valid` canonical gate, root
signature, intermediate signature, attenuation, expiry, leaf epoch, chain
epoch, `HasParent` chain completeness, resource binding. Caught: identity
binding, rights coverage, revocation, actor match.

Two root causes, needing different fixes:

- **Self-reference.** `PermitSoundness` and `ChainEpoch` re-invoke the very
  `Verify`/`ValidChain` definitions that computed the decision. Weaken the
  enforcement and the invariant weakens in lockstep, so nothing can fire. The
  same shape makes `RevocationSafety` near-tautological and `CompositionMono`
  tautological-by-construction.
- **Missing adversarial data.** All six model capabilities carry
  `rights |-> {"READ"}`, so no capability *can* escalate relative to its parent
  — attenuation is unfalsifiable at this model. The `EscalationCap` promised in
  the header comment at `MC_AuthGateV3.tla:31` **is never defined; only the
  comment exists.** Likewise `MCResources == {"r1"}` makes cross-resource reuse
  inexpressible rather than merely unchecked.

**What we ask:** tell us whether mutation survival is the right bar for a spec
of this kind, and whether our proposed fixes (independent invariants that do not
re-invoke `Verify`; deny-completeness properties, one per adversarial action)
are the right shape. We are also interested in whether you think a
mutation-testing gate belongs in CI for specs generally — we have not seen it
done and may be missing why.

---

## 3. Vacuity, and what a green run at these bounds is worth

All eight safety invariants are implications guarded on `decision = "Permit"`.
Seven of the nine model actions always Deny, so the invariants say nothing at
all about them. Only two hand-written happy-path bundles reach Permit.

Meanwhile the shipped bound is not checkable: at `Len(audit_log) <= 3`, TLC
generated 26.5M states / 2.3M distinct in 10 minutes with the queue still
growing, against a reachable state count on the order of 10⁹. The only
completing run we have ever produced used `Len(audit_log) <= 1` — an audit log
of at most one entry, so **no multi-decision interaction is reachable at all**:
no revoke-then-use, no epoch-advance-then-replay.

Our own framing, which we ask you to sharpen or reject: *a green TLC run at
these bounds is closer to an exhaustively-checked unit-test suite than to a
proof for arbitrary N.*

**What we ask:** is that framing right, and is there a bound at which you would
consider the result to carry real weight? We would rather state a small proven
claim than a large cracked one.

---

## 4. Unverified Ed25519, and key reuse

`sig_valid` is an opaque Boolean in the model, and `RootKey` never appears in
any executable expression — so at present *any* `issuer_pubkey` validates a root
capability as long as `sig_valid` is TRUE. The distinguished root key is
declared and then never used.

Underneath that, Ed25519 correctness is an explicit trust assumption. We have
added it as a named Lean axiom, `ed25519_verify_correct_axiom`, rather than
letting it hide inside a proof — a commitment made to Adam Chlipala, pending a
verified implementation from the HACL*/Fiat lineage.

**What we ask:** two things.
(a) Is the axiom's *statement* faithful — encoding, malleability,
batch-vs-single verification? An axiom that quietly assumes a stronger property
than Ed25519 provides is worse than no axiom.
(b) **Key reuse.** The same key material appears in the delegation chain and in
the audit log. We have not analysed the interaction and consider it a live
weakness.

---

## 5. Kani's bounded-checking limits

19 harnesses are written. **None has ever been run** — Kani is not installed on
the author's machine, and the harnesses are `#[cfg(kani)]`, so ordinary builds
skip them silently. The README claimed "all proved". That was false and has been
retracted.

Separately, and independent of the harnesses ever running: **no unwind bound is
recorded anywhere in this repository.** A proof under `--default-unwind 3` says
nothing about chains of length 4, and a reviewer is entitled to assume a bound
was chosen to make the proof pass unless told otherwise.

**What we ask:** per Bryan Parno's framing — what *should* a bounded model
checking result be allowed to claim for a security kernel, and what bound would
make the delegation-chain harnesses meaningful given `MaxChainDepth = 16` in the
Rust implementation?

---

## 6. Where the Lean development actually stands

**5 of 6 Lean files do not compile.** The errors are identical under toolchains
4.32.2 and 4.31.0, so this is a real defect rather than version drift. A theorem
in a file that does not build is not discharged, whatever the file says.

**What we ask:** if you use `#print axioms` as a discipline, tell us whether you
would accept it as our evidentiary standard. Our intent is that every headline
theorem's claim be backed by its `#print axioms` output rather than by our
description of it, so that `sorryAx` cannot hide.

---

## 7. What we are *not* asking

We are not asking whether the components are novel. They are largely not, and we
say so: Capsicum, E-lang, CHERI, Macaroons and proof-carrying authorization are
all prior art, catalogued in `PRIOR_ART.md`. The claim under test is that the
*synthesis* is useful — a runtime capability model for AI agents, plus a
formal-verification attempt, plus the two-level primitive/crypto
secure-compilation problem.

If your conclusion is "this is a well-engineered restatement of known results",
that is a useful answer and we will describe it that way.

---

## Ground rules we hold ourselves to

From the repository's own governance:

- Every "proven"/"checked" claim must cite a specific theorem or property by
  file path and name.
- "Partial" and "unfalsifiable at the current model" are different statuses and
  are never merged.
- Statuses may only stay the same or go **down** as a result of review. They go
  up only against a new run or proof committed as evidence.
- When in doubt, round down.
- Claims must match the nearest completed milestone, never the destination.
  "Reviewable" ≠ "verified".

If you find a cell in `ASSUMPTIONS.md` or
`04_FORMAL_VERIFICATION_STATUS.md` that is more optimistic than its evidence,
that is a bug report we want, and it takes precedence over everything above.
