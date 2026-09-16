# Industry Readiness — Maturity Tiers

AuthGate uses **four cumulative tiers**. Each tier adds obligations; higher tiers inherit lower ones.
Do not claim a tier without meeting every gate on that row.

| Tier | Git branch | Audience | Gate |
|------|------------|----------|------|
| **T1 Assurance-bounded** | `tier/assurance-bounded` | Researchers, formal-methods reviewers | Minimal formal core; every `sorry`/axiom/non-goal named |
| **T2 Engineering-complete** | `tier/engineering-complete` | Kernel engineers, CI owners | T1 + zero open [Engineering gaps](README.md#engineering-gaps) + formal/seccomp/sandbox CI green |
| **T3 Deployable reference** | `tier/deployable-reference` | Platform teams, early adopters | T2 + Docker/compose, K8s sidecar, probes, Prometheus, runbooks |
| **T4 Production infra-ready** | `tier/production-infra-ready` | Security-conscious production | T3 + KMS guide, DR, migration tooling, advisory process, 100% code-addressable [deployment checklist](DEPLOYMENT_READINESS.md) |

---

## T1 — Assurance-bounded

**Claim:** A minimal, **consistent** formal system that **contains all it asserts** — proved, admitted, or excluded.

| Requirement | Artifact |
|-------------|----------|
| Axioms A1–A7 stated | [AXIOMATIC_FOUNDATION.md](AXIOMATIC_FOUNDATION.md) |
| Proved vs admitted split | [formal/INCOMPLETENESS.md](formal/INCOMPLETENESS.md) |
| Bounded TLC | [formal/tlc_run.log](formal/tlc_run.log), CI `formal.yml` |
| Kani TCB harnesses | [formal/COVERAGE.md](formal/COVERAGE.md) |
| Lean partial (2 sorry, 2 crypto axioms) | `formal/lean4/FreedomKernel/Scope.lean`, `Proofs.lean` |

**Not claimed:** Full refinement TLA+→Rust, semantic intent, infinite-horizon safety.

---

## T2 — Engineering-complete

**Claim:** All engineering gaps from the original audit are closed or explicitly scoped.

| Requirement | Artifact |
|-------------|----------|
| Engineering gaps table empty | [README.md#engineering-gaps](README.md#engineering-gaps) |
| WASM sandbox CI | `.github/workflows/sandbox.yml` |
| Seccomp adversarial CI | `.github/workflows/seccomp.yml` |
| TLC + Lean CI | `.github/workflows/formal.yml` |
| CLI smoke | `.github/workflows/ci.yml` (`cli-smoke` job) |

**Merge target:** `main` after PR review. T2 is the minimum bar for calling the repo “engineering-complete.”

---

## T3 — Deployable reference

**Claim:** A real platform team can run the verifier as a sidecar without the author on call.

| Requirement | Artifact |
|-------------|----------|
| HTTP verifier + `/readyz` + `/metrics` | [INFRA.md](INFRA.md), `src/authgate/api/app.py` |
| Docker + compose | `Dockerfile`, `docker-compose.yml` |
| K8s sidecar + probes | [examples/kubernetes/](examples/kubernetes/) |
| Incident response | [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) |
| Threat model + non-goals | [THREAT_MODEL.md](THREAT_MODEL.md), [NON_GOALS.md](NON_GOALS.md) |

**Honest limit:** `/verify` is open on the pod network — lock down with NetworkPolicy + mesh mTLS.

---

## T4 — Production infra-ready

**Claim:** 100% of **code-addressable** deployment checklist items are satisfied; human-dependent items have **process-ready** templates.

| Code-addressable (must be YES) | Artifact |
|-------------------------------|----------|
| Key management integration | [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) |
| Disaster recovery | [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) |
| Schema migration tooling | [MIGRATION.md](MIGRATION.md), `authgate-cli migrate` |
| CVE / advisory process | [SECURITY.md](SECURITY.md) |
| External review package | [EXTERNAL_REVIEW_PACKAGE.md](EXTERNAL_REVIEW_PACKAGE.md) |

| Human-dependent (process-ready, not “done”) | How to close |
|---------------------------------------------|--------------|
| D8 External adversarial review | Commission review using EXTERNAL_REVIEW_PACKAGE |
| F1 Real production deployment | First adopter / shadow mode ([FIRST_ADOPTER.md](FIRST_ADOPTER.md)) |
| F4 Postmortem from real incident | Requires F1 first |

**Scoring:** [DEPLOYMENT_READINESS.md](DEPLOYMENT_READINESS.md) — target **100% code-addressable**, **process-ready** for field evidence.

---

## Branch promotion flow

```text
spec-core / tcb-core / adversarial-lab  (three truths — see BRANCHES.md)
        ↓ merge when CBCT satisfied
tier/engineering-complete  →  main
        ↓ + ops artifacts
tier/deployable-reference
        ↓ + KMS / DR / migration
tier/production-infra-ready
```

**Rule:** Never skip a tier in public claims. “Production infra-ready” requires T4 branch + green CI on that branch.

---

## What elites expect (translation)

| Your tier | Industry reads as |
|-----------|-------------------|
| T1 | Publishable formal artifact |
| T2 | Merge-ready engineering |
| T3 | Reference implementation / shadow deployment OK |
| T4 | Production candidate — pending external review + field evidence |

T4 is the maximum **the repository alone** can guarantee. Field evidence (F1, F4) is organizational, not a code gap.
