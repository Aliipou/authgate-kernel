# Why `God -> Human` stays a documented gap, not a TODO

COVERAGE_MATRIX.md row 20 reports the ontological root of the ownership
hierarchy — `Person(h) -> OwnedByGod(h)` — as a **Documented gap**, the only
row of the twenty not marked Enforced, Implemented, or Partial. This file
exists to make explicit *why* that is the correct status permanently, not a
placeholder for future work, and how it differs in kind from a row like
Consent Logic (row 8), which genuinely was closeable and now is (see
[`../docs/CONSENT_SEMANTICS.md`](../docs/CONSENT_SEMANTICS.md)).

## Two different kinds of gap

Row 8 (Consent Logic) was a gap in *coverage*: the theory names a checkable
predicate (was this human actually informed, voluntary, competent, undeceived
when they consented?), and no code computed it. That predicate is, in
principle, the kind of thing a judge — human or machine — can be asked to
assess, wrong sometimes, but assess. Adding `semantic_consent_veto` closed
that gap the honest way: not by having the TCB pretend to compute an
unverifiable semantic property, but by composing an untrusted, veto-only,
fail-closed judge on top of it, exactly the way `compass.py` and
`synthesis.py` already sit outside the gate for the same reason.

Row 20 (`God -> Human`) is a gap in *kind*, not coverage. `Person(h) ->
OwnedByGod(h)` is not a predicate any judge — human, machine, or formal
system — can be asked to assess and return a verdict for, because there is no
procedure, and there is no such procedure *even in principle*, that takes
this claim as input and returns `informed_voluntary_competent` or
`inconsistent` the way a consent judge can. It is not unimplemented. It is
not implementable, by any system that also wants to be finite and
non-contradictory — which the theory itself insists on
(`../PHILOSOPHY/README.md`: "a formal system must be *finite and
non-contradictory* rather than pretend to encode what it cannot").

## The precedent already in this codebase

`formal/lean4/FreedomKernel/Incompleteness.lean` already states the same shape
of boundary for the axioms A1–A7 generally, and it is the model for this file:

> "The kernel enforces A1–A7. Whether A1–A7 are the correct axioms is a
> philosophical question outside the scope of formal verification. The kernel
> is sound *relative to* A1–A7; it cannot verify A1–A7 themselves."

Every formal system has this shape. Peano arithmetic does not prove its own
axioms; ZFC does not prove the axiom of choice is true, only what follows
if it is assumed; Lean's own kernel does not verify that its type theory
is itself the right foundation. A system that tries to derive its own
starting axioms from inside itself either becomes circular or fails to
terminate — Gödel's second incompleteness theorem is the general version of
exactly this: a sufficiently expressive consistent formal system cannot prove
its own consistency from within.

`Person(h) -> OwnedByGod(h)` is this kernel's axiom, one level further up
than A1–A7: it is the claim that grounds *why* the human is the trust root
that A1–A7 then protect. Trying to encode it as a checkable TCB invariant
would not make the system more rigorous — it would make a category error,
treating an ontological claim as if it were a computational one, and would
either (a) silently assume what it claims to prove, or (b) require an oracle
for a question no oracle answers. Leaving it declared and unenforced is not
a failure of nerve. It is the same discipline TCB_DISCIPLINE.md's Rule 2
already applies one level down: keep the trusted core free of concepts it
cannot honestly verify, and say plainly where it stops.

## What "cohesive and comprehensive" means here, then

A moral order for AI that claims to formally ground *every* level — including
its own first premise — is not more comprehensive than one that stops and
names its boundary. It is less honest, in exactly the way a "100% test
coverage" claim that mocks the one thing it can't actually test is less
honest than 99% coverage with the gap stated. Comprehensiveness, for a system
that also has to stay non-contradictory, means:

1. Every claim that *can* be mechanically checked, *is* — Kani, Lean4, TLA+,
   the 300 Rust tests, the property tests on every evaluator composed on top.
2. Every claim that can be judged but not mechanically verified — consent's
   four semantic predicates, purpose-vs-payload consistency, and so on — gets
   an untrusted, veto-only, fail-closed judge, composed outside the TCB,
   never mistaken for proof.
3. Every claim that is neither — the ontological root itself — is named,
   dated, and left exactly as undefended as it actually is, with the
   reasoning for why that's the right place to stop written down here rather
   than left as a bare "not modeled" with no argument behind it.

Row 20 stays a documented gap under this file, permanently, by the same
discipline that makes the rest of the matrix trustworthy: nothing here is
asserted that the system does not actually back up.
