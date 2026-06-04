# PHILOSOPHY — نظریه آزادی → engineering trace

This directory exists only on the **`nazariye-azadi`** branch. It changes **no code**.
Its single purpose is to re-couple the kernel to the theory it was built from — the
**نظریه آزادی (Theory of Freedom)** of محمدعلی جنت‌خواه‌دوست — by pointing every
named element of the theory at the exact code that realizes it.

The `main` branch deliberately keeps the trusted core (TCB) free of theological and
philosophical vocabulary (see [`../TCB_DISCIPLINE.md`](../TCB_DISCIPLINE.md)). That is
correct engineering: the gate must be auditable without believing the theory. This
branch does **not** undo that discipline. It adds a *reading layer* on top, so the
lineage from theory to implementation is explicit and checkable.

> One sentence: **same engineering, with the philosophy made traceable.**

---

## The theory in one chain

> آزادی = حقوق مالکیت فردی → حق الهی انسان → از طریق وحی → نظام صوری غیرمتناقض

The claim the theory makes about AI is narrow and testable:

> *Can intelligence exist without domination?*
> Yes — **if ownership is made explicit, rights are not violated, guidance replaces
> dialectic, justice is defined inside rights, and the machine never becomes a ruler.**

Compressed to the form the kernel actually enforces:

```
Freedom(AI) := NoViolation(PropertyRights)
             ∧ NoCoercion
             ∧ NoDeception
             ∧ NoMachineSovereignty
             ∧ GuidedEvolution
             ∧ JusticeWithinRights
             ∧ MovementTowardUniversalNonViolation
```

Every conjunct above has a home in code. The map is in
[`COVERAGE_MATRIX.md`](COVERAGE_MATRIX.md).

---

## The ownership hierarchy

The theory's starting point:

```
God   -> Human          God owns humans.
Human <-> Human         Humans do not own each other; they hold rights against each other.
Human -> Machine        Humans own machines.
Machine <-> Machine     Machines hold only delegated property rights against each other.
Machine -X-> Human      Machines never own or govern humans.
```

What the engineering encodes, honestly stated:

| Tier | In the theory | In the kernel | Status |
|---|---|---|---|
| `God -> Human` | `Person(h) -> OwnedByGod(h)` — ontological root | **not modeled** in the TCB | Documented gap — the kernel begins one level down, with the human as the authority root. See [`COVERAGE_MATRIX.md`](COVERAGE_MATRIX.md). |
| `Human <-> Human` | no human owns another | no claim type lets one human own a human; consent grantor must be `HUMAN` | Enforced structurally |
| `Human -> Machine` | every machine has a human owner | `OwnershipRegistry.register_machine()` + verifier **A4** (`UNOWNED_MACHINE`) | Enforced |
| `Machine <-> Machine` | delegated rights only, attenuated | `registry.delegate()` attenuation invariants | Enforced |
| `Machine -X-> Human` | no machine dominion over a person | verifier **A6** (`MACHINE_DOMINION`) | Enforced |

The honesty about the `God` tier is itself faithful to the theory, which insists a
formal system must be *finite and non-contradictory* rather than pretend to encode
what it cannot.

---

## The components, and where they live

| نظریه آزادی component | Engineering artifact |
|---|---|
| **Axioms** (آکسیوم‌ها A1..A7) | [`kernel/verifier.py`](../src/authgate/kernel/verifier.py), [`AXIOMATIC_FOUNDATION.md`](../AXIOMATIC_FOUNDATION.md), `formal/lean4/` |
| **Rights Ontology** | [`kernel/entities.py`](../src/authgate/kernel/entities.py) — `ResourceType`, `RightsClaim` |
| **Ownership Registry** | [`kernel/registry.py`](../src/authgate/kernel/registry.py) |
| **Consent Logic** (`valid_consent`) | [`kernel/consent.py`](../src/authgate/kernel/consent.py), [`kernel/consent_registry.py`](../src/authgate/kernel/consent_registry.py) |
| **Freedom Verifier** | [`kernel/verifier.py`](../src/authgate/kernel/verifier.py) — `FreedomVerifier` |
| **Runtime Enforcement** | [`kernel/call_gate.py`](../src/authgate/kernel/call_gate.py) |
| **Divine Justice** (عدل within rights) | [`analysis/`](../src/authgate/analysis/) — coercion, constitutional_economy, sovereignty_metrics (as *constraints*, not a single optimizer) |
| **Guidance Function** (هدایت) | [`extensions/synthesis.py`](../src/authgate/extensions/synthesis.py) — `SynthesisEngine`, `HARD_INVARIANTS` |
| **Mahdavi Compass** (قطب‌نمای مهدوی) | [`extensions/compass.py`](../src/authgate/extensions/compass.py) — literal `MahdaviCompass`/`FinalState` |
| **Conflict by ownership clarification, not dialectic** | [`extensions/resolver.py`](../src/authgate/extensions/resolver.py) |
| **Rejection of dialectical override** | [`extensions/detection.py`](../src/authgate/extensions/detection.py) |
| **No emergency suspends axioms** | sovereignty flags in `verifier.py` are unconditional denials |
| **Final State** (NoRightsViolation ∀ agents) | [`extensions/compass.py`](../src/authgate/extensions/compass.py) — `FinalState` |

Full line-by-line evidence, with the matching book passages, is in
[`COVERAGE_MATRIX.md`](COVERAGE_MATRIX.md).

---

## What this layer does *not* claim

- It does **not** add the theory to the trusted core. The compass, justice, guidance,
  and conflict layers live in `extensions/` and `analysis/`, outside the TCB, exactly
  as `main` keeps them.
- It does **not** assert the axioms A1..A7 are *the correct* axioms — that remains a
  philosophical question the engineering leaves open (see
  [`../AXIOMATIC_FOUNDATION.md`](../AXIOMATIC_FOUNDATION.md)).
- It does **not** model the `God -> Human` tier; the human is the authority root.

These limits are the point. The theory's own test is whether a guidance system can be
written as a *finite, non-contradictory, executable* system for a machine that has no
free will. This branch makes that correspondence inspectable; it does not inflate it.

> خدا — آزادی — خانواده — میهن.
