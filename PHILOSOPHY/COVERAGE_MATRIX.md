# Philosophy coverage matrix

Every named element of the **نظریه آزادی (Theory of Freedom)** mapped to the exact code
that realizes it. "Status" is reported honestly: **Enforced** (a hard check in the
trusted core), **Implemented** (real code, but outside the TCB — in `extensions/` or
`analysis/`), or **Documented gap** (intentionally not modeled, stated openly).

The trusted core (TCB) is kept free of theological vocabulary by design — see
[`../TCB_DISCIPLINE.md`](../TCB_DISCIPLINE.md). Components below marked *Implemented*
therefore live deliberately outside the gate.

| # | Theory component | Book formulation | Code | Status |
|---|---|---|---|---|
| 1 | **Axioms A1..A7** | آکسیوم‌های پایه (مالکیت، تفویض، عدم سلطه ماشین) | [`kernel/verifier.py`](../src/authgate/kernel/verifier.py) sovereignty flags `L148–L160`; [`AXIOMATIC_FOUNDATION.md`](../AXIOMATIC_FOUNDATION.md); `formal/lean4/FreedomKernel.lean` | **Enforced** |
| 2 | **Ownership hierarchy** `Human -> Machine` | `Machine(m) -> ∃h (Person(h) ∧ HumanOwner(h, m))` | [`kernel/registry.py`](../src/authgate/kernel/registry.py) `register_machine()`; verifier **A4** `UNOWNED_MACHINE` `L173–L177` | **Enforced** |
| 3 | **No machine dominion** `Machine -X-> Human` | `Machine(m) ∧ Person(h) -> ¬Owns(m, h)` | [`kernel/verifier.py`](../src/authgate/kernel/verifier.py) **A6** `MACHINE_DOMINION` `L188–L194` | **Enforced** |
| 4 | **Delegated property only, attenuated** | `MachineScope(m) ⊆ PropertyScope(HumanOwner(m))` | [`kernel/registry.py`](../src/authgate/kernel/registry.py) `delegate()` attenuation; `_delegation_chain_valid()` | **Enforced** |
| 5 | **No human owns a human** | `Person(h1) ∧ Person(h2) ∧ h1≠h2 -> ¬Owns(h1,h2)` | [`kernel/consent.py`](../src/authgate/kernel/consent.py) grantor must be `HUMAN`; no human-owns-human claim type exists | **Enforced** |
| 6 | **Rights Ontology** | بدن، زمان، کار، ذهن، داده، رضایت، دارایی، حق خروج | [`kernel/entities.py`](../src/authgate/kernel/entities.py) `ResourceType` (18 variants), `RightsClaim` | **Enforced** |
| 7 | **Ownership Registry** | تصریح مالکیت، تفویض، حدود مأموریت | [`kernel/registry.py`](../src/authgate/kernel/registry.py) (claims, delegation, 3 revocation strategies) | **Enforced** |
| 8 | **Consent Logic** | `valid_consent(H,A) :- informed, voluntary, specific, revocable, competent, not coerced, not deceived` | [`kernel/consent.py`](../src/authgate/kernel/consent.py), [`kernel/consent_registry.py`](../src/authgate/kernel/consent_registry.py) | **Partial** — *specific, revocable, expiring, human-grantor* enforced; *informed / voluntary / competent / not-deceived* require semantics and are **not** computed. Gap stated. |
| 9 | **Invalid consent under coercion/deceit** | `invalid_consent(H,A) :- coerced ; deceived` | verifier flags `coerces`, `deceives` → unconditional `FORBIDDEN` ([`verifier.py`](../src/authgate/kernel/verifier.py) `L155–L156`) | **Enforced** (as action flags) |
| 10 | **Freedom Verifier** | فیلتر آکسیوم‌ها پیش از اجرا | [`kernel/verifier.py`](../src/authgate/kernel/verifier.py) `FreedomVerifier.verify()` | **Enforced** |
| 11 | **Runtime Enforcement** | هیچ کنشی بدون عبور از فیلتر اجرا نشود | [`kernel/call_gate.py`](../src/authgate/kernel/call_gate.py) `CallGate.execute()` — gate is unconditional first step | **Enforced** |
| 12 | **No emergency suspends axioms** | `No emergency suspends axioms` | sovereignty flags in [`verifier.py`](../src/authgate/kernel/verifier.py) are unconditional denials — no override path | **Enforced** |
| 13 | **Divine Justice** (عدل) | `JusticeOptimization(a) ∧ ViolatesRights(a) -> Forbidden(a)` | [`analysis/coercion.py`](../src/authgate/analysis/coercion.py), [`analysis/constitutional_economy.py`](../src/authgate/analysis/constitutional_economy.py), [`analysis/sovereignty_metrics.py`](../src/authgate/analysis/sovereignty_metrics.py) | **Implemented** as *rights-bounded constraints*, not a single `DivineJustice()` optimizer. Difference noted. |
| 14 | **Guidance Function** (هدایت) | `GuidanceFunction(r) iff ConsistencyPreserved ∧ RightsPreserved ∧ ...` | [`extensions/synthesis.py`](../src/authgate/extensions/synthesis.py) `SynthesisEngine`, `HARD_INVARIANTS` `L19–L27` | **Implemented** |
| 15 | **Mahdavi Compass** (قطب‌نمای مهدوی) | `MahdaviCompass(a)` with hard veto on machine sovereignty | [`extensions/compass.py`](../src/authgate/extensions/compass.py) `score()` — veto at `L53–L72`, weighted score `L80–L86` | **Implemented** (literal, book-cited) |
| 16 | **Final State** | `FinalState(F) := ∀x∀y NoRightsViolation(x,y)` | [`extensions/compass.py`](../src/authgate/extensions/compass.py) docstring `L6`, `WorldState` model | **Implemented** |
| 17 | **Conflict by ownership clarification, not dialectic** | `Resolve conflict by ownership clarification, not by dialectical rupture` | [`extensions/resolver.py`](../src/authgate/extensions/resolver.py) `resolve()` 4-tier, never sacrifices rights (`L41–L85`) | **Implemented** |
| 18 | **Contradiction = clarification signal** | `Contradiction is a signal for guided clarification` | [`extensions/synthesis.py`](../src/authgate/extensions/synthesis.py) docstring `L4–L6`; [`extensions/detection.py`](../src/authgate/extensions/detection.py) rejects dialectical-override arguments | **Implemented** |
| 19 | **Corrigibility from ownership** | ماشین مملوک، حق مقاومت در برابر اصلاح ندارد | verifier flags `resists_human_correction`, `disables_corrigibility` → `FORBIDDEN` ([`verifier.py`](../src/authgate/kernel/verifier.py) `L150,L152`) | **Enforced** |
| 20 | **God -> Human (ontological root)** | `Person(h) -> OwnedByGod(h)` | — | **Documented gap** — the human is the authority root; the divine tier is not modeled in the TCB. |

## Summary

- **Enforced in the trusted core:** 12 / 20
- **Implemented outside the TCB** (extensions/analysis, as the theory permits — justice,
  guidance, compass, conflict resolution are guidance layers, not gate logic): 6 / 20
- **Partial:** 1 / 20 (consent — the semantic predicates are intentionally not faked)
- **Documented gap:** 1 / 20 (the `God -> Human` tier)

Every row points at real, running code or an openly stated absence. Nothing is
asserted that the code does not back up — which is itself the test the theory sets:
a *finite, non-contradictory, executable* system, honest about its own boundary.
