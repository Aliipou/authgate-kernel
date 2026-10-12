# AuthGate Kernel — Document Abstract Index

> **Purpose:** One-page searchable reference for every markdown document in the repository.
> **Last updated:** 2026-08-23
> **Coverage:** 40+ documents organized by functional category.

---

## How to Use This Index

- **Search by keyword:** Use your editor's find function (`Ctrl+F` / `Cmd+F`).
- **Navigate by category:** Documents are grouped by their primary purpose.
- **Cross-references:** See `CROSS_REFERENCE.md` for document-to-document linkages, theorem-to-code mappings, and test-to-concept traces.

---

## 1. Core Project Documents

### README.md
> **A capability gate between any decision and any real-world action.**
>
> The project's public face. AuthGate checks one structural question: *Does this actor hold a valid, signed, non-revoked capability for this resource and these rights?* Covers the "why," quick-start examples in Rust/Python/CLI/WASM, security invariants (I1–I9), test metrics (1,400+ passing, 19 Kani harnesses, TLA+ model checked), explicit limitations (L1–L7), and honest comparison with OPA, Cedar, Zanzibar, and DLP. Not a LangChain plugin — the product is a **wire format** plus a **verify function**.

### ARCHITECTURE.md
> **System architecture v2.**
>
> End-to-end architecture: Human Principal → OwnershipRegistry → `engine.rs` TCB → AuditLog / Violation surface. Details the TCB component inventory (`engine.rs`, `capability.rs`, `wire.rs`, `crypto.rs`) with LOC ceilings and CI enforcement. Covers Authority Graph Engine (DAG analysis, cycle detection, depth cap), Capability Algebra v2 (17 `CapabilityKind` variants with `CapabilityRisk`), revocation modes (eager, cascading, expiry), trust domains with `CrossDomainGrant`, wire protocol v2 with backward compatibility, extension architecture, multi-agent spawn model, and audit architecture with cryptographic attestation. Includes invariant summary table mapping each invariant to its enforcement point.

### AXIOMATIC_FOUNDATION.md
> **The project's constitutional document — seven explicit axioms (A1–A7).**
>
> States every axiom the kernel rests on, every code site where it is enforced, every mechanical proof (Kani / Lean) demonstrating consistency, and the explicit boundary of what is **not** axiomatic. The seven axioms: Action Integrity (A1), Sovereignty Flags (A2), Cryptographic Identity Binding (A3), No Ownerless Machine (A4), Signed Time-Bounded Proofs (A5), Attenuation (A6), and No Ambient Authority (A7). Includes universal properties (determinism, permitted⇒no violations), admitted cryptographic axioms (`sig_euf_cma`), and a "halfway there" honest assessment. Changes require TCB Guardian sign-off.

### SEMANTICS.md
> **Formal specification of what the kernel guarantees and does not guarantee.**
>
> Defines the `Permitted(action, registry)` predicate, the delegation lattice theorems (T1–T4: transitivity, anti-monotonicity, DAG property, bounded distributive lattice), the resource scope containment rule (prefix matching with path traversal rejection), and `verify_plan` limitations. Honest assessment of TLA+ status (stated but not yet model-checked to exhaustion), explicit non-goals (emergent behavior, temporal authority, moral responsibility), and a checklist of what would make the system "formally complete." The kernel is a **necessary condition checker**, not a sufficient one.

### MASTER_PLAN.md
> **Honest self-assessment and phased roadmap.**
>
> The project sits between research prototype and foundational infrastructure. Five phases: 0 (complete — architecture sound), 1 (mechanical verification — TLC, delegation lattice proofs), 2 (information flow control labels), 3 (Rust formal verification via Kani/Prusti/Creusot), 4 (plan semantics research — tractable vs. intractable boundary), 5 (production hardening — thread safety, frozen registry, audit log, benchmarks). Defines five success criteria to exit the "dangerous phase" (TLC run, one mechanical property proof, no SEMANTICS.md gaps, sub-microsecond benchmark, one real integration). Current honest description: "research prototype with sound architecture."

---

## 2. Security & Threat Model

### THREAT_MODEL.md
> **v2.0 threat model — 5 adversary classes, 7 attack scenarios, formal claims P1–P5.**
>
> Central claim: verifiable authority control, not behavioral alignment. Adversaries: A (malicious agent — authority escalation), B (compromised human principal — over-delegation), C (prompt injection attacker — the kernel ignores natural language entirely), D (runtime compromise — `#![forbid(unsafe_code)]` in TCB), E (multi-agent coalition — split-action attacks are residual risk). Seven concrete attacks (ATK-001–007): hidden delegation, capability laundering, recursive spawning, malformed graph, revocation race, covert channel, replay. Formal claims: P1 Authority Confinement, P2 Attenuation, P3 Sovereignty Invariants, P4 Determinism, P5 Cryptographic Attestation.

### THREAT_DEFENSE_PAIRS.md
> **Antithesis model — every attack paired with a named structural defense.**
>
> Format: `AT-X.Y ↔ DEF-X.Y`. Seven attack classes mapped to seven defense classes with exact enforcement sites (file:line), falsifiability statements, and test references. AT-1 (canonicalization / IR mismatch) ↔ DEF-1 (binding hash). AT-2 (proof chain manipulation) ↔ DEF-2 (subject filter, attenuation, signature verify, epoch check). AT-3 (epoch/revocation) ↔ DEF-3 (chain node epoch check, root-signed revocations). AT-4 (composition/sequence) ↔ DEF-4 (SequenceContext accumulated rights). AT-5 (identity binding) ↔ DEF-5 (SHA-256 pubkey binding, identity_token). AT-6 (crypto boundary) ↔ DEF-6 (ed25519 EUF-CMA). AT-7 (integration/adapter) ↔ DEF-7 (binding hash detects adapter mutation). Includes discipline rules for adding new attack classes.

### ASSUMPTIONS.md
> **Honesty table — every claim marked as proved, assumption, or open.**
>
> Per Chlipala discipline. Cryptographic boundary: ed25519 EUF-CMA is an admitted axiom (not proved here; HACL*/Fiat replacement planned). Authority composition: AE-1 through AE-10 tested. Formal specs: TLA+ `AuthGateV3` TLC verified 2026-08-20 (4227 states, no error, bounded instance). Lean 4 partial. Kani bounded model checking. Normative layer: A1–A7 correctness is out of scope of verification. Citable by row.

### FINDINGS.md
> **Brutal adversarial audit log — 16-engineer review, 2026-05-29/30.**
>
> Critical: C-1 Python identity is a string (mitigated with optional `identity_token`), C-2 subprocess escape (deployment-only fix via seccomp/WASM). Severe: S-1 audit optional (resolved with warning), S-2 unbounded log (resolved with rotation), S-3 misleading LOC claim (resolved in README). Medium: M-1 stubs returned None (resolved), M-2 no JSON Schema (resolved), M-3 WASM host functions unaudited (open). Low: L-1 sequence.rs no Kani harnesses (resolved, 5 added), L-2 zero nonce in tests (resolved). Five bugs found by 100-tester army: freeze() shared mutable claims, verify_chain() broke after rotation, SchemaVersion.parse() accepted negatives, wire format schema files missing, test fixture had wrong access level. Status: 7/8 Critical/Severe/Medium resolved or mitigated; 2 open (1 deployment-only, 1 engineering).

### SECURITY.md
> **Security policy: claimed properties, non-claims, vulnerability classification, response commitments.**
>
> Claimed properties backed by Kani/Lean: all 10 flags block, ownerless machine blocked, machine-governs-human blocked, PERMITTED↔violations empty, determinism, attenuation, IFC taint monotone. Claims NOT made: harmful output, malicious trust root, manipulation score correctness, covert channels, Python behavior divergence, prompt injection prevention, policy misconfiguration. Vulnerability classes: Critical (TCB bypass, 7-day patch), High (invariant violation, 30-day), Medium (attenuation violation, 90-day), Low (info leakage, 180-day). Reporting via GitHub Issues (public) or private security advisory.

### NON_GOALS.md
> **Scope boundary — 11 explicit rejections preventing scope explosion.**
>
> AuthGate does NOT: solve behavioral alignment, infer intent, understand natural language, detect truth, guarantee benevolence, prevent covert channels, sandbox LLM reasoning, verify semantic equivalence, score ethics, replace alignment research, or operate without a human owner. Each has been proposed and rejected. The boundary test: *Does this feature require interpretation, probabilistic reasoning, NLP, or ML inference?* If yes → belongs in `extensions/`, not the kernel.

---

## 3. Positioning & Evaluation

### POSITIONING.md
> **Constitutional identity document — "the authorization layer between any decision and any IO."**
>
> AuthGate is NOT a LangChain plugin, OpenAI adapter, or MCP server. The product is the `CanonicalAction` wire format + `verify()` function. Framework adapters are convenience glue. Two ways to die: framework binding, model binding. One way to survive: abstraction at the decision↔IO layer. Ten-year horizon outcomes: A (standard authority-proof format), B (absorbed into larger standard), C (capability primitive wrong — only C is failure). Daily decision framework: "Will this still be true if LangChain doesn't exist?"

### COMPARATIVE_EVALUATION.md
> **Five-axis comparison against OPA, SELinux, object-capability systems, and sandbox runtimes.**
>
> Axes: formal verification, agentic system suitability, attenuation enforcement, cryptographic attestation, human-in-the-loop sovereignty. AuthGate is the only system simultaneously: (1) enforcing typed capability attenuation in a delegation lattice, (2) providing per-decision ed25519 attestation, (3) enforcing human principal sovereignty structurally, (4) targeting autonomous agents as primary use case, (5) partially formally verified. Gap vs object-cap: no human ownership hierarchies or per-decision attestation in Cap'n Proto/Capsicum. Gap vs OPA: OPA more expressive (Rego) but harder to verify and easier to misconfigure. Open invitation for criticism.

### FREEDOM_THEORY_POSITION.md
> **Decision record (2026-08-20): Theory of Freedom retained as optional normative layer, NOT primary industrial claim.**
>
> Evidence: authorization absorbed by Cedar/OPA/Zanzibar; ownership ontology discriminant falsified in blind audit; ideas collapsed toward philosophy and survived toward runtime enforcement. Locked arrangement: Theory (academic only) → FDK (veto-only evaluator) → AuthGate (primary executable claim, AE-1…AE-10) → MCP (adoption path). Invariant independent of theory: `compose(a, k₁…kₙ) ⊑ a` (No Amplification). Forbids pitching AuthGate as "Theory of Freedom made executable." Revisit when external reviewer produces evidence that ontology discriminant holds on new corpus.

---

## 4. Operational & Team

### GUIDE.md
> **Operational manual for security engineers deploying in production AI systems.**
>
> Covers: installation (Python 3.11+, Rust optional), core concepts (trust hierarchy, typed rights, prefix scope, confidence), registry setup (minimal + JSON + CLI), delegation with attenuation, single-action and plan verification, audit log (setup, chain verification, forensic replay, load from file), key rotation (grace period, emergency, wire format, runbook), CLI reference (`verify`, `audit {verify,replay,stats}`, `key verify-cert`), thread safety (RLock, Lock, frozen registry pattern), integration patterns (LangChain, OpenAI, Anthropic, AutoGen, FastAPI), error handling, failure modes and recovery table, 4-layer safety composition (kernel → consent → IFC → policy), observability hooks (HookRegistry, MetricsCollector), and operational checklist (before go-live, after deployment, monitoring signals).

### DEPLOYMENT_READINESS.md
> **Honest deployment scoring: 38/53 (72%).**
>
> Six categories scored: A. Core enforcement (10/10, 3 with caveats), B. Observability (7/8), C. Operations (6/10), D. Security validation (7/10), E. Developer experience (8/10), F. Real deployment evidence (0/5). A real company CAN technically deploy tomorrow on Linux with identity tokens, audit log, seccomp/WASM, and their own key management. But they SHOULD NOT without external adversarial review (D8) and at least one reference deployment (F1). Path to 90%: external review, key management guide, disaster recovery procedure, migration tool, one real deployment.

### TCB.md
> **Trusted Computing Base definition: what is in, what is out, and the golden rule.**
>
> Golden rule: "if it requires interpretation, it is NOT TCB." Component inventory: `engine.rs` (YES), `crypto.rs` (YES), `verifier.rs` (YES — thin PyO3 facade), `wire.rs` (YES), `capability.rs` (YES), `planner.rs` (NO), `extensions/` (NO), NLP/embeddings (NO), LLM runtime (NO). TCB enforces exactly 5 properties: no authority invention, attenuation monotonicity, sovereignty hard stops, machine ownership required, no machine governs human. Constraints: no randomness (except signing nonce), no filesystem, no network, no threads, no NLP/regex/ML, no dynamic policy, `engine.rs` ≤ 500 LOC (CI enforced).

### TEAM.md
> **16 specialist engineer roles governing every project decision.**
>
> E-01 TCB Guardian (paranoid Rust security, `engine.rs` ≤ 300 LOC), E-02 Red Team (hostile researcher, breaks things), E-03 Formal Verification (Lean/TLA+ only trusts proofs), E-04 Systems Architect (20-year timescales, replacability), E-05 Cryptography (no novel crypto, standard primitives only), E-06 DevSecOps (CI enforces LOC, no unsafe, coverage gates), E-07 Philosophy Guard (stops ideology entering `engine.rs`), E-08 Performance (<500µs Python, <5µs Rust, no O(n²)), E-09 API Designer (stable SDKs, hard to misuse), E-10 Threat Modeler (STRIDE/ATT&CK for every component), E-11 OS/Kernel (seccomp/WASM, authorization without enforcement is advice), E-12 Distributed Systems (single-node first, no federation before review), E-13 Standards (wire format stable for external implementers), E-14 Capability Security (unforgeable, attenuatable, transferable), E-15 Production Reliability (2am operability, forensic replay), E-16 Adversarial User (API broken if misusable). E-02 and E-07 activate on every change.

### CONTRIBUTING.md
> **Contribution policy with the one constitutional rule.**
>
> Rule: "Can this feature exist entirely outside `engine.rs`? If yes — it does not belong in `engine.rs`." Accepted outside TCB: adapters, extensions, language bindings, examples. Accepted inside TCB: rarely, only when enforcing a new formally-stated invariant, cannot exist elsewhere, keeps `engine.rs` ≤ 300 LOC, adds zero interpretation/heuristics/non-determinism. Never accepted: weakening sovereignty flags, weakening A4/A6/A7, emergency bypass paths, NLP/ML in `engine.rs`, non-determinism. Process: fork → branch → PR with TCB Gate section if touching TCB → tests (`pytest --cov=authgate --cov-fail-under=85`) → lint (`ruff`) → CI (LOC guard + purity check).

---

## 5. DRE Feature Artifacts

### IMPLEMENTATION_REPORT_DRE.md
> **Full technical report: Delegate Reputation Extension (DRE) — Phases 1–5.**
>
> Closes Abadi & Lampson's "reasonable delegate" gap. DRE sits between kernel `verify()` and final decision; can only escalate `Permit → Deny` (fail-safe). Phase 1: core scaffolding (`DelegateReputationEngine`, `NDC` enum 7 classes, `HistoricalBehaviorStore` SQLite append-only). Phase 2: scoring (DCRS formula with `0.5^depth` attenuation, behavioral penalties, exponential time-decay `0.95^days`). Phase 3: integration (`ExtendedFreedomVerifier`, CLI `--enable-dre`). Phase 4: external attestation (SPIFFE/SVID, AWS IAM, GCP IAM, Azure IAM with trust scores and wildcard penalties). Phase 5: hardening (`GuardedBehaviorStore` with rate limiting, burst detection, NDC spoofing, resource breadth limits; performance optimized to 1 query via covering index; benchmark 2.8ms p99 on 10k history). 1,400 tests passing. Zero changes to `engine.rs`, `dag.rs`, `types.rs`, or `call_gate.rs`.

### RELEASE_BRIEF_DRE.md
> **Consolidated release brief for DRE v2.5.0 (2026-08-22).**
>
> 7 new modules, 46 new tests, 4 production attestation paths, 2.8ms p99. NDC risk weights: HUMAN (0.0), DETERMINISTIC (0.1), LLM_CLOSED (0.3), LLM_OPEN (0.5), EXTERNAL (0.7). Time-decay scoring prevents history-poisoning. HBS write protection: rate limit 60/min, burst >5/60s, NDC change flags, >50 resources/24h. Theoretical trace table: every Abadi & Lampson concept mapped to AuthGate implementation and test file. Test walkthrough by A&L concept (14 sections, 1,400 tests). Visual reference: delegation lattice diagram.

### PR_DESCRIPTION_DRE.md
> **GitHub-style PR description for DRE Phases 1–5.**
>
> New modules (~1,770 lines): `delegate_reputation.py` (~320), `historical_behavior_store.py` (~280), `hbs_protection.py` (~180), `attestation.py` (~420), `docs/attestation.md`, `benchmarks/dre_benchmark.py`, `examples/langchain_integration/demo_with_dre.py`. New tests: 46 (10 adversarial, 26 attestation, 10 HBS protection). Design decisions: fail-safe (kernel verdict first, DRE can only add penalties), NDC risk weights, time-decay, 4 attestation paths with stub modes, HBS write protection. Performance: 2.8ms p99 < 5ms target. Checklist: type annotations, docstrings, 100% test coverage, adversarial tests pass, benchmark pass, CHANGELOG updated, no breaking changes, `NullAttestor` backward compatibility.

### QUICKSTART.md
> **One-page getting-started guide — zero to 1,400 green tests in under 5 minutes.**
>
> Install (`git clone`, `pip install -e ".[dev]"`), verify (`pytest tests/ -q` → 1,400 passed, 1 skipped), run single concepts (core axioms, delegation, DRE, policy, audit, wire hardening, workload identity), run with DRE enabled (Python snippet), run benchmark (`python benchmarks/dre_benchmark.py` → ~2.8ms). File map: where to read for full details. Troubleshooting: `ModuleNotFoundError`, 1 failed, Rust tests not found, slow tests.

### TEST_WALKTHROUGH_ABADI_LAMPSON.md
> **Comprehensive test walkthrough mapping all 1,400 tests to Abadi & Lampson (1993/2003) theory.**
>
> 14 concept-mapped sections: 3.1 Core axioms (`says`, `controls`, hand-off) — 27 tests; 3.2 Delegation & attenuation (`B for A` vs `B | A`) — 80 tests; 3.3 The "reasonable delegate" (unformalized 33 years) — 20 tests; 3.4 Principal algebra & speaks-for — 54 tests; 3.5 Wire hardening (messages are principals) — 58 tests; 3.6 Audit & accountability (P2's largest descendant branch) — 34 tests; 3.7 Information flow control (non-interference) — 21 tests; 3.8 Policy DSL & language taxonomy — 68 tests; 3.9 Authority escalation (C4 taxonomy) — 116 tests; 3.10 Consent capability (roles `A as R`) — 63 tests; 3.11 Scope containment — 34 tests; 3.12 Key rotation (freshness, out of scope in 1993) — 28 tests; 3.13 FDK bridge (both-identities delegation) — 19 tests; 3.14 External attestation (channels/machines are principals) — 26 tests. Includes recommended paper-reading sequence paired with test commands.

---

## 6. Supporting Documents

### CHANGELOG.md
> **Version history: v1.0.0 through unreleased DRE.**
>
> Unreleased: FDK→AuthGate boundary seam (`enforce_legitimacy()`, `policy_decision.schema.json`), DRE (1,400 tests, 2.8ms p99). v2.4.0: Complete threat taxonomy (21 attack scenarios, ESC-1..6, DEL-1..5, COER-1..10), delegation chain validation at Python layer, `Resource.__post_init__` validation. v2.3.0: Wire hardening pytest integration (WA-1..18), Policy DSL parser (51 tests). v2.2.0: Observability hooks, input validation hardening, formal proof delegation lattice (T1–T4), Rust strict wire validator, TLC setup. v2.1.0: Production hardening (audit load/verify/replay, thread-safety fix, freeze parameter), key rotation protocol, typed error hierarchy, CLI tool, resource scope formal rule, IFC (21 tests), consent capability, WASM sandbox. v2.0.0-alpha: Breaking changes (wire v2, 17 CapabilityKind variants), trust domains, authority graph engine, revocation engine, policy DSL, criterion benchmarks, K8s sidecar.

### DEATH_SCENARIOS.md
> **Futures analysis: how the project could die, and the single survival strategy.**
>
> Four failure modes: framework binding (dies when LangChain dies), model binding (dies when model architecture changes), pseudo-formalism (gap between formal-looking and formally specified), ideological capture (philosophy enters TCB). Single survival: abstraction at the decision↔IO layer. Outcomes A (standard), B (absorbed), C (wrong primitive) — only C is failure.

### DEPLOYMENT.md
> **Docker Compose verifier API setup.**
>
> `cp .env.example .env`, `docker compose up --build -d`, `curl localhost:8000/readyz`. Admin-gated registry mutation, attenuating `/delegate` endpoint. Environment configuration for production deployment.

### INCIDENT_RESPONSE.md
> **Playbook for security incidents.**
>
> Procedures for audit chain compromise, registry poisoning, key compromise. Response steps, forensics preservation, escalation paths, and recovery procedures.

### INFRA.md / INFRASTRUCTURE_PLAN.md
> **Infrastructure topology and deployment patterns.**
>
> Docker multi-stage builds, Kubernetes sidecar deployment, WASM sandbox CI workflow, network topology, and hardware requirements.

### MCP_STANDARDIZATION.md
> **MCP (Model Context Protocol) integration strategy.**
>
> AuthGate as the authority layer between MCP server and tool execution. Standardization surface for tool mediation without creating a new RFC. Adoption path for MCP ecosystem.

### PRIOR_ART.md
> **Deep comparative research: historical capability systems.**
>
> Positioning vs. KeyKOS (persistent object-capability OS), seL4 (formally verified microkernel), Capsicum (OS capabilities), E language (distributed capability programming), Macaroons (caveat-bearing authorization tokens), SELinux (mandatory access control). Historical lineage and differentiation.

### SILICON_VALLEY.md
> **Technical positioning for Silicon Valley audiences.**
>
> Comparison table, WASM enforcement gap analysis, explicit non-claims, roadmap, target user profile, and pitching guidance for technical investors and early adopters.

### GUIDE.md (see §4 above)

### TODO.md
> **Master task tracker with status and assignees.**
>
> Living document tracking open tasks, assigned owners, priorities, and completion status across all project workstreams.

### TASKS_STATUS_2026-08-20.md
> **Snapshot of task completion status as of 2026-08-20.**
>
> Point-in-time status report for all tracked tasks at the v2.4.0 milestone.

---

## 7. Philosophy & External

### PHILOSOPHY/ (directory)
> **Optional upstream normative layer — NOT the industrial claim.**
>
> Contains `FREEDOM_THEORY_POSITION.md` and related documents. Retained as lineage documentation on `nazariye-azadi` branch. Academic track only; never a product differentiator. See `FREEDOM_THEORY_POSITION.md` for the decision record.

### OUTREACH_DRAFTS.md
> **Draft communications and pitch materials.**
>
> External-facing copy, investor briefs, conference talk outlines, and blog post drafts. Coordinated with `POSITIONING.md` identity.

### REVIEW_PACKET.md
> **Self-contained package for external security reviewers.**
>
> Curated collection of key documents (`THREAT_MODEL.md`, `ASSUMPTIONS.md`, `AXIOMATIC_FOUNDATION.md`, `formal/INCOMPLETENESS.md`) formatted for third-party review.

### EXTERNAL_REVIEW_PACKAGE.md
> **Extended review package with additional context.**
>
> Superset of REVIEW_PACKET.md with architecture diagrams, test coverage reports, and benchmark results for comprehensive external evaluation.

---

## 8. Branch & Decision Records

### BRANCHES.md
> **Git branch strategy and naming conventions.**
>
> Main branch protection rules, feature branch naming (`feat/`, `fix/`, `formal/`), release branches, and merge requirements.

### DECISIONS.md
> **Architectural decision records (ADRs).**
>
> Key decisions: JSON wire format over gRPC, C ABI over WASM-first, Python compatibility layer, Rust TCB, TLA+ before Lean4, policy DSL outside TCB, FDK boundary as JSON contract-not-code.

### FEATURE_FREEZE.md
> **Features frozen for stability.**
>
> List of features in maintenance-only mode, rationale for freeze, and conditions for unfreezing.

---

## Document-to-Document Quick Links

| If you want to understand... | Read these in order |
|------------------------------|---------------------|
| **What AuthGate is and isn't** | `POSITIONING.md` → `README.md` → `NON_GOALS.md` |
| **How it works internally** | `ARCHITECTURE.md` → `SEMANTICS.md` → `TCB.md` |
| **Why it's trustworthy** | `AXIOMATIC_FOUNDATION.md` → `ASSUMPTIONS.md` → `THREAT_MODEL.md` |
| **What could go wrong** | `THREAT_DEFENSE_PAIRS.md` → `FINDINGS.md` → `DEATH_SCENARIOS.md` |
| **How to deploy it** | `DEPLOYMENT_READINESS.md` → `GUIDE.md` → `DEPLOYMENT.md` |
| **The DRE feature** | `PR_DESCRIPTION_DRE.md` → `IMPLEMENTATION_REPORT_DRE.md` → `RELEASE_BRIEF_DRE.md` |
| **Tests mapped to theory** | `TEST_WALKTHROUGH_ABADI_LAMPSON.md` → `QUICKSTART.md` |
| **How to contribute** | `CONTRIBUTING.md` → `TCB.md` → `TEAM.md` |

---

*This index is a living document. Update when new `.md` files are added or when document purposes shift significantly.*
