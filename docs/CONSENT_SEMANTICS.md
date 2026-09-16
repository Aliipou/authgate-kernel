# Semantic consent veto

## Problem

`kernel/consent.py`'s `ConsentCapability` enforces what a boolean check can
honestly verify: the grantor is human, the grant has a finite expiry, the
operation is in the declared set, and the context (if bound) matches. The
theory's actual predicate is wider:

```
valid_consent(H, A) :- informed, voluntary, specific, revocable,
                       competent, not coerced, not deceived
```

`specific`, `revocable` (mandatory expiry), and `human-grantor` are structural
and are enforced. `informed`, `voluntary`, `competent`, and `not deceived`
require judging what a human actually understood and agreed to — not
something a boolean can check without pretending to understand language.
PHILOSOPHY/COVERAGE_MATRIX.md row 8 has always reported this honestly as
**Partial**, not faked as **Enforced**.

## Placement

Same discipline as `compass.py` (guidance), `synthesis.py` (the guidance
function), and `resolver.py` (conflict resolution): outside `kernel/`,
composed on top, never granting authority. TCB_DISCIPLINE Rule 2 forbids
"informed", "voluntary", "competent" and "deceived" from the trusted core by
name — correctly, since a kernel cannot mechanically verify what a human
understood. `semantic_consent_veto` does not try. It is an optional,
untrusted judge a caller may compose after `ConsentVerifier.check()` passes,
and it can only add a refusal, never remove one.

## Guarantee

For any judge output whatsoever — a real verdict, garbage, an exception, a
`str` subclass built to impersonate a verdict — `semantic_consent_veto`
either permits (only on the one honest path, a parsed
`informed_voluntary_competent` judgment) or denies. It never raises and never
grants consent that `ConsentCapability`'s own structural checks did not
already allow. `tests/test_consent_semantics.py::test_semantic_consent_veto_never_grants`
checks this as a Hypothesis property over arbitrary judge output.

## Defenses specific to a free-text judge

Identical set to `decision_os_min.semantic.semantic_veto`, reused line for
line (see that project's `docs/SEMANTIC_VETO.md` for the fuller rationale):

| Risk | Defense |
|---|---|
| Judge mutates the capability or reaches kernel objects | Judge receives a canonical JSON string, not the object. |
| Deceptive content hidden past a truncation point | A view longer than `max_view_chars` is denied without calling the judge. |
| Attacker-controlled `repr` shown to the judge | Non-JSON view content (objects, NaN) is denied without calling the judge. |
| Judge output impersonating a permit | Only the three canonical judgments are accepted, compared by base `str` value. |
| Judge errors used to switch the check off | Exceptions, `SystemExit`, `KeyboardInterrupt`, and malformed output are denied regardless of `on_uncertain`. |
| Judge text forging or disguising a log record | Reasons are flattened to one line, control/bidi/zero-width characters removed, length capped at 280 characters. |
| Judge reasoning about *who* is asking instead of *what* | `grantor` (the human's identity) is excluded from the default view fields. |

Every denial reason starts with `consent-veto[<judge name>]`.

## What it cannot do, stated plainly

- It does not verify a human was actually informed — it means an untrusted
  judge did not find a problem. That is weaker than the mechanically-checked
  parts of this project and must never be presented as equivalent.
- It has no timeout of its own. Unlike decision-os-min, this codebase has no
  single host applying `evaluator_timeout_s` uniformly to every composed
  check; a caller wiring this into a real-time or async pipeline is
  responsible for bounding how long they wait on `judge.judge(view)`.
- It is single-request scope: it judges one consent grant's stated request
  against itself. It does not detect a pattern of individually-plausible
  requests that add up to deception across a session — the same limitation
  `decision_os_min.semantic_veto` documents for actions.
- Nothing here is covered by this project's Kani harnesses, Lean4 theorems,
  or TLA+ model. A permit from this module is not part of that evidence and
  must not be reported alongside it.
- `DisclosureMatchJudge` (the deterministic reference judge shipped here) can
  only catch a disclosed-vs-actual purpose mismatch when a caller supplies
  both strings. It says `uncertain` otherwise — it does not invent an opinion
  about text it wasn't given. A model-backed judge is a drop-in replacement,
  same shape as `examples/semantic_llm_judge.py` in decision-os-min.

## What this changes in PHILOSOPHY/

Row 8 of `PHILOSOPHY/COVERAGE_MATRIX.md` moves from *Partial, gap stated,
nothing built* to *Partial, gap stated, and here is the composable check that
closes it when a caller opts in* — the status word stays **Partial** on
purpose. Consent semantics are not "Enforced" by this module and never will
be by any module: enforcement implies mechanical guarantee, and a language
judge is not one. See `PHILOSOPHY/COVERAGE_MATRIX.md` for the updated row and
`PHILOSOPHY/GOD_HUMAN_BOUNDARY.md` for why row 20 (`God -> Human`) is a
different kind of gap — one that should stay open rather than be "closed" the
way this one was.
