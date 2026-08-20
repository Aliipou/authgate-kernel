# Freedom Theory — final positioning

**Decision date:** 2026-08-20  
**Decision:** Theory of Freedom is retained as an **optional upstream normative
layer**, not as the primary industrial or security-capability claim.

---

## The question

Should the stack be reordered as:

```text
Theory of Freedom
  → rights ontology
  → legitimacy / FDK
  → delegation / capability
  → AuthGate execution
  → tools / MCP
```

…or should freedom-theory remain an independent philosophical contribution while
AuthGate is pitched as systems/security engineering?

## Evidence that decided it

1. **Kill-tests on AuthGate authorization** (`STATUS.md`, `WHY_NOT_OPA.md`) —
   authorization is absorbed by Cedar / OPA / Zanzibar. The surviving industrial
   thesis is purpose/flow governance and **non-amplifying composition**, not a
   new moral theory.
2. **Ownership discriminant experiment** (`REVIEW_REQUEST_2026-08-10.md` §3–4) —
   the claim that deriving legitimacy from an ownership/consent ontology is a
   unique contribution was **falsified** after pre-registration and blind audit.
3. **Pattern across the program** — ideas collapsed toward philosophy and survived
   toward runtime enforcement, distributed systems, and capability management.

## The arrangement (locked)

| Layer | Role | Public claim |
|---|---|---|
| Theory of Freedom (`freedom-theory-work`, `PHILOSOPHY/`) | Optional normative *interpretation* of why veto-only legitimacy exists | Academic / lineage only; never a product differentiator |
| FDK legitimacy | Veto-only evaluator (DENY/DEFER); co-equal under lattice meet | Constraint input, not grant authority |
| AuthGate / decision-os-min | Authority, attenuation, PEP, audit | **Primary claim** — executable AE-1…AE-10 under non-amplification |
| MCP | Standardization surface for tool mediation | Adoption path (not a new RFC) |

Invariant that does **not** depend on the theory being true:

> `compose(a, k₁…kₙ) ⊑ a` — No Amplification. Constraint inputs (including any
> legitimacy evaluator derived from any ontology) are veto-only.

## What this forbids in outreach

- Pitching AuthGate as “the Theory of Freedom made executable” as the *main* hook.
- Claiming philosophical correctness of A1–A7 as a security result.
- Letting normative vocabulary outrun the ASSUMPTIONS table.

## What this still allows

- Keeping `PHILOSOPHY/` on the `nazariye-azadi` branch as lineage documentation.
- Using FDK as one veto-only evaluator among others (safety, privacy, budget).
- Academic papers on the theory as a **separate** track from the conformance /
  MCP engineering track.

**Revisit when:** an external reviewer produces evidence that the ontology
discriminant holds on a new, pre-registered corpus — or when a standards body
requires a normative annex. Until then, this decision stands.
