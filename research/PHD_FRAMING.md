# Research framing — Authority Attenuation for Autonomous Agents

**Branch:** `research` only. Do NOT merge to `main`, `integration`, `tcb-core`, `spec-core`, or `adversarial-lab`.

> Per architectural feedback (2026-05-30): academic framing must stay on a dedicated branch
> so the engineering branches remain pure infrastructure. This document exists for PhD
> applications, workshop papers, and arXiv preprints — not for marketing the project.

---

## Research question

> How should delegation chains of typed capabilities be represented, verified, and
> revoked in autonomous agent ecosystems such that:
> 1. attenuation is structurally enforceable (child ⊆ parent),
> 2. revocation is O(1) under bounded staleness,
> 3. and the verifier is formally minimal (small TCB, mechanically verified)?

## Why this question matters

Agent systems increasingly hold delegated authority over real resources
(filesystems, APIs, credentials). Existing access-control models (RBAC, ABAC,
OAuth scopes) were not designed for chains of delegation between non-human
principals. Capability systems (Capsicum, seL4, CHERI) were designed for
processes, not for agents whose authority chains span runtime boundaries.

## Contribution claims (candidate)

1. **A typed canonical action format** with binding-hash commitment that
   detects all single-field mutations between adapter and verifier.

2. **Epoch-based primary revocation** that invalidates a cohort of capability
   proofs in O(1) without distributing revocation lists — and the formal proof
   that this is safe under stated assumptions about clock integrity.

3. **A delegation DAG validation algorithm** that enforces attenuation chain-wide
   (not only at the leaf), closing AT-3.1 and AT-5.1 attack classes that
   capability prototypes commonly miss.

4. **A minimal Trusted Computing Base** (≤ 1500 LOC across 5 files) with
   Kani bounded model checking + Lean4 theorems for core invariants, paired
   with explicit `INCOMPLETENESS.md` enumeration of what is NOT proved.

5. **An attack taxonomy** (AT-1..AT-7 + WA-1..WA-18) with 231 simulated
   scenarios and 1155 tests, demonstrating the chosen invariants are
   necessary and sufficient against the named threats.

## Paper outline (workshop-grade)

1. Introduction & motivation
2. Threat model (single-org Phase 1; distributed Phase 4 out of scope)
3. Canonical action format & binding hash
4. Delegation DAG & attenuation invariants
5. Epoch-based revocation
6. Formal verification scope (Kani harnesses, Lean theorems, admitted axioms)
7. Implementation: Rust TCB + Python reference layer
8. Evaluation: latency, throughput, attack coverage
9. Limitations (cf. `formal/INCOMPLETENESS.md`)
10. Related work: seL4, Capsicum, CHERI, OPA, SPIFFE
11. Discussion: extending to multi-issuer trust (Phase 4)

## Venues to consider

- USENIX Security workshops
- IEEE S&P workshops
- ACM CCS workshops
- PLAS workshop
- arXiv preprint as a first step

## Honest current state

| Dimension | Status for PhD application |
|-----------|---------------------------|
| Engineering rigor | strong — above average for independent project |
| Formal artifacts | strong — Kani + Lean4 + TLA+ spec |
| Threat coverage | strong — explicit & enumerated |
| Empirical eval | reasonable — benchmarks + attack simulation |
| External validation | weak — no external audit yet |
| Novel claim | candidate — needs sharpening |
| Reproducibility | strong — full source + tests public |

## What to do BEFORE PhD application

In order of impact per hour of work:

1. **Write an arXiv preprint** of the paper outline above
2. **One external adversarial review** (security engineer outside the project)
3. **One real deployment** (any single company / project using AuthGate before tool execution)
4. **Workshop paper submission** to any venue above

A preprint + external review is worth more than 500 additional tests for PhD review.

## What to NOT do

- Don't add more features. The current scope is already paper-sized.
- Don't expand to AGI or civilization framing. Reviewers will reject as out-of-scope.
- Don't promise distributed/federated systems. Phase 1 alone is the paper.

---

*This file lives on the `research` branch only. The engineering branches must
read as pure infrastructure, not as an academic project.*
