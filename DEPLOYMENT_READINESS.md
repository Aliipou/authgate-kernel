# Deployment Readiness — Can a real company deploy this tomorrow?

> "Can a real company put this in front of its agents tomorrow?"
> If YES → infrastructure. If NO → still research.
> — Architect review, 2026-05-30

This file is the honest answer.

## Scoring rule

- `[YES]`  — done, tested, documented
- `[YES*]` — done with deployment-time caveat
- `[NO]`   — gap that blocks production
- `[N/A]`  — not applicable to this project type

A real company adopts this only when 80%+ of the items below are `[YES]`
or `[YES*]` with caveats they accept. Below 80%: still research-grade.

---

## A. Core enforcement

| # | Item | Status | Note |
|---|------|--------|------|
| A1 | Tool execution gated by capability proof | YES | CallGate.execute() — Python and Rust paths |
| A2 | Permit/Deny is deterministic | YES | Same input → same output (Rust TCB pure; Python documented impure C-4) |
| A3 | Denied tool body never runs | YES | 25 red-team tests verify (test_adversarial_redteam.py) |
| A4 | Cryptographic identity binding | YES* | Rust TCB: SHA-256(pubkey). Python: identity_token opt-in (C-1 documented) |
| A5 | Capability chain validation | YES | dag.rs validates attenuation, signatures, epochs |
| A6 | Revocation works in O(1) | YES | epoch advance — both Rust and Python |
| A7 | Audit log tamper-evident | YES | SHA-256 hash chain |
| A8 | Audit chain verifiable post-incident | YES | AuditLog.verify_chain() |
| A9 | OS-level isolation (subprocess/syscall) | YES* | Linux only: seccomp executor + WASM sandbox. Windows: open (C-2) |
| A10 | Concurrent verify is thread-safe | YES | test_thread_safety.py + test_army.py concurrent tests |

**A subtotal: 10/10 (3 with caveats)**

---

## B. Observability

| # | Item | Status | Note |
|---|------|--------|------|
| B1 | Every decision is logged by default | YES | FreedomVerifier warns when audit_log=None (S-1) |
| B2 | Audit log persistence to disk | YES | AuditLog(path=...) writes JSONL |
| B3 | Audit log bounded growth | YES | AuditLog(max_entries=N) rotation |
| B4 | Forensic replay of past decision | YES | AuditLog.replay(index) |
| B5 | Chain integrity check tool | YES | authgate-cli audit verify |
| B6 | Health check endpoint | YES | authgate.health_check() |
| B7 | Performance metrics exported | NO | No Prometheus/StatsD integration yet |
| B8 | Structured logs (JSON) | YES | All audit entries are JSON |

**B subtotal: 7/8 (88%)**

---

## C. Operations

| # | Item | Status | Note |
|---|------|--------|------|
| C1 | Container image available | YES | Dockerfile in repo |
| C2 | docker-compose for local dev | YES | docker-compose.yml |
| C3 | Kubernetes manifests | YES | examples/kubernetes/ |
| C4 | Health & readiness probes | YES* | health_check() exists; manifests need wire-up |
| C5 | Key rotation procedure documented | YES | key_rotation.py + DEPLOYMENT.md |
| C6 | Key storage guidance (HSM/Vault) | NO | Trust root supply is "caller's responsibility" |
| C7 | Incident response playbook | YES | INCIDENT_RESPONSE.md |
| C8 | Migration guide between versions | NO | No v1→v2 migration plan written |
| C9 | Capacity planning numbers | YES | benchmarks/comprehensive_bench.py |
| C10 | Disaster recovery plan | NO | No procedure for audit log loss / key compromise |

**C subtotal: 6/10 (60%)**

---

## D. Security validation

| # | Item | Status | Note |
|---|------|--------|------|
| D1 | Threat model documented | YES | THREAT_MODEL.md |
| D2 | Non-goals documented | YES | NON_GOALS.md |
| D3 | Known gaps enumerated | YES | FINDINGS.md, formal/INCOMPLETENESS.md |
| D4 | Adversarial test suite (>100 attacks) | YES | 231 simulation scenarios + 25 red team |
| D5 | Property-based testing | YES | Hypothesis tests + differential fuzzer |
| D6 | Bounded model checking | YES | Kani: 19 v1 + 5 v2-sequence harnesses |
| D7 | Theorem proofs (Lean) | YES | 16 theorems in formal/lean4/ |
| D8 | External adversarial review | NO | Self-tested only — biggest gap |
| D9 | Bug bounty program | NO | Not yet announced |
| D10 | CVE / security advisory process | NO | SECURITY.md exists but no historical CVEs |

**D subtotal: 7/10 (70%)**

---

## E. Developer experience

| # | Item | Status | Note |
|---|------|--------|------|
| E1 | Install in one command | YES | pip install -e ".[dev]" |
| E2 | Quickstart runs without internet | YES | examples/callgate_demo.py |
| E3 | CLI tool | YES | authgate-cli verify / audit / validate |
| E4 | JSON Schema for wire format | YES | spec/*.schema.json |
| E5 | Framework adapters (≥3 frameworks) | YES | 8 adapters: LangChain, OpenAI, Anthropic, AutoGen, CrewAI, LangGraph, DSPy, MCP |
| E6 | Adapter integration tests | YES | test_adapters_callgate_integration.py |
| E7 | Type hints (mypy clean) | YES | mypy in CI |
| E8 | API stability guarantee | YES* | schema_version = 1.0.0; breaking changes need MAJOR bump |
| E9 | Migration tool between versions | NO | Same as C8 |
| E10 | Multi-language SDKs | NO | Only Python + Rust. Go, TypeScript, Java pending |

**E subtotal: 8/10 (80%)**

---

## F. Real deployment evidence

| # | Item | Status | Note |
|---|------|--------|------|
| F1 | At least one external production user | NO | Zero confirmed external deployments |
| F2 | Performance numbers from real load | NO | Only synthetic benchmarks |
| F3 | Public reference customer | NO | None |
| F4 | Postmortem from a real incident | NO | No incidents because no real users |
| F5 | Community contributions (≥5 external PRs) | NO | Project is single-maintainer |

**F subtotal: 0/5 (0%)**

---

## TOTAL SCORE

| Section | Score |
|---------|-------|
| A. Core enforcement | 10/10 |
| B. Observability | 7/8 |
| C. Operations | 6/10 |
| D. Security validation | 7/10 |
| E. Developer experience | 8/10 |
| F. Real deployment evidence | 0/5 |
| **TOTAL** | **38/53 (72%)** |

---

## Honest assessment

A real company **can technically** deploy this tomorrow, on Linux, with:
- explicit `identity_token` for every Entity (C-1 mitigation)
- explicit `audit_log=AuditLog(path=..., max_entries=...)` configuration
- seccomp executor or WASM sandbox (C-2 mitigation)
- their own key management / HSM integration (no built-in solution for C6)

But they SHOULDN'T do that without:
- **External adversarial review** (D8) — the single most important missing item
- **At least one reference deployment** to derive operational lessons (F1)

A reasonable deployment plan today:
1. Use it for internal/non-critical tools first
2. Run alongside existing auth as a shadow validator for 1-2 months
3. Promote to primary gate once F1+F4 evidence accumulates

## What gets us to "yes, deploy"

The minimum work to take this from 72% to 90% — at which point a security-conscious
company can reasonably deploy:

1. **External adversarial review** (D8) — single biggest credibility move
2. **Key management integration guide** (C6) — Vault/AWS KMS/Azure Key Vault recipes
3. **Disaster recovery procedure** (C10) — what to do if root key compromised
4. **Migration tool** (C8/E9) — v1→v2 proof reissuance
5. **One real deployment** (F1) — even internal use at one company

Items 1, 3, 5 cannot be done by code alone. They need humans.

---

*Updated: 2026-05-30. Re-score after any items change.*
