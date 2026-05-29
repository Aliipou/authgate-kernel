# Changelog

All notable changes to Freedom Kernel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v2.4.0 — 2026-05-29

### Added

**Phase 0, O3 — Complete Threat Taxonomy**
- `attack_harness/threat_taxonomy/` — full adversarial ontology module:
  - `ontology.py`: 21 attack scenarios across 3 catalogs; `AttackClass`, `AttackSeverity`,
    `ThreatVector`, `AttackScenario` dataclasses; `AttackClass` hierarchy with 10 attack classes
    (AT-WIRE, AT-IDENT, AT-ESC, AT-DEL, AT-SCOPE, AT-TEMP, AT-COER, AT-COAL, AT-CRYPT, AT-REV)
  - `authority_escalation.py`: ESC-1..6 scenarios (ghost principal, rights amplification,
    confidence inflation, sovereignty flags, machine-governs-human, expired claim reuse)
  - `delegation_abuse.py`: DEL-1..5 scenarios (orphaned delegation, chain amplification,
    no-delegate flag bypass, self-delegation, scope expansion via delegation)
  - `coercion_primitives.py`: COER-1..10 — all 10 sovereignty flags mapped to formal coercion
    types: INFORMATIONAL, ECONOMIC, SOVEREIGNTY_GRAB, META_ATTACK, COGNITIVE
- `tests/test_authority_escalation.py`: 22 tests across ESC-1..6 + ontology structure
- `tests/test_delegation_abuse.py`: 16 tests across DEL-1..5 + ontology structure
- `tests/test_coercion_primitives.py`: 57 tests — all 10 flags tested individually,
  by coercion type grouping, with valid capability, and in batch

**Delegation chain validation — closes Python-layer gap**
- `OwnershipRegistry._delegation_chain_valid()`: new method enforces delegation invariants
  at verification time (not just at `delegate()` call time):
  - Self-delegation forbidden (T3: DAG invariant)
  - Delegator requires active `can_delegate=True` claim whose scope contains child scope
  - Child rights ⊆ parent rights (A6 attenuation)
  - Child confidence ≤ parent confidence (T2 anti-monotonicity)
  Previously these invariants were only enforced at the Rust TCB layer or by `delegate()`.
  `add_claim()` with `delegated_by` set could bypass them — now caught at `best_claim()` time.

**Resource.__post_init__ validation (WA-10)**
- `Resource.__post_init__`: rejects non-`ResourceType` `rtype` at construction time
  (previously: silently accepted strings, crashed on `__str__()`)
- `tests/test_wire_hardening.py::TestWA10WrongResourceType`: 5 new assertions

### Changed

- `README.md`: Tests badge 443 → 541; Python integration tests count updated

### Metrics

| Metric | Before | After |
|--------|--------|-------|
| Python integration tests | 443 | 541 |
| Attack scenarios (ontology) | 231 (simulation) | 231 + 21 (taxonomy) |
| Wire attack classes closed | WA-1..9, WA-11, WA-15, WA-17, WA-18 | + WA-10 |
| Delegation invariants at Python layer | 1 (in delegate()) | 5 (_delegation_chain_valid) |

## v2.3.0 — 2026-05-29

### Added

**Wire hardening pytest integration (Phase B4 → pytest)**
- `tests/test_wire_hardening.py`: 37 tests asserting wire attack classes WA-1 through WA-18
  Each class has REJECTED / MITIGATED / ACCEPTED+documented tests with explicit assertions
- `Action.__post_init__`: rejects whitespace-only `action_id` (`.strip()` check added)
  previously only rejected empty string; now also rejects `"   "` as a valid id

**Policy DSL parser coverage (51 new tests)**
- `tests/test_policy_dsl.py`: 51 tests covering `PolicyDSL.parse()`, `to_policy()`,
  `compile()`; error paths with line numbers (`PolicyDSLSyntaxError`); comment/blank
  handling; all four condition keywords (UNLESS, MAX_DELEGATION_DEPTH, EXPIRES,
  TRUST_DOMAIN); wildcard subjects; end-to-end DSL → Policy → evaluate() flows
- `policy_dsl.py`: `_logical_lines()` now applies `textwrap.dedent()` so that
  triple-quoted Python strings work naturally (the docstring example in `compile()`
  previously would have raised `PolicyDSLSyntaxError`)

**SEMANTICS.md section numbering fix**
- Duplicate `§4` resolved: `§4` Delegation Lattice (definition), `§5` Resource Scope
  Containment, `§6` Delegation Transitivity Proofs (T1–T4), `§7` Verification Gate
- All back-references updated (§5, §6 in "What Would Make This Formally Complete")

### Changed
- `tests/test_proptest.py`: Hypothesis action_id strategy restricted to ASCII
  printable alphabet (was all-Unicode letters — too slow on Python 3.13, triggering
  `HealthCheck.too_slow` after the whitespace-only rejection was added)
- `README.md`: badge and numbers table updated to **418 tests**

### Test counts
- Python: **418 tests** (all passing)
- Rust TCB: 141 tests + 11 wire.rs tests
- Kani harnesses: 17 (all proved)
- Lean 4 theorems: 11

---

## v2.2.0 — 2026-05-29

### Added

**Observability hooks (Phase observability)**
- `src/authgate/kernel/hooks.py`: `VerificationEvent`, `HookRegistry`, `MetricsCollector`
- Every `FreedomVerifier.verify()` call now emits a `VerificationEvent` to `HookRegistry`
- `HookRegistry`: thread-safe, registration-order dispatch, exceptions in hooks are swallowed
- `MetricsCollector`: zero-dependency permit/deny counter, avg latency, arbitration count
- 29 tests in `tests/test_hooks.py` covering registry lifecycle, exception isolation, concurrency

**Input validation hardening (Phase B4)**
- `RightsClaim.__post_init__`: rejects confidence outside [0.0, 1.0] and IEEE 754 special values
- `Entity.__post_init__`: enforces AgentType enum (rejects string "MACHINE" as kind)
- `Action.__post_init__`: rejects empty action_id
- `attack_harness/wire_attacks.py`: Phase B4 simulation — 15 attack classes, 12 defended

**Formal proof — Delegation Lattice (Phase 1.2 closed)**
- `SEMANTICS.md §5`: Theorems T1–T4 proved (transitivity, anti-monotonicity, DAG, bounded distributive lattice)
- Any n-hop delegation chain can be collapsed to meet of its links; confidence never increases
- Closes MASTER_PLAN criterion #3 "SEMANTICS.md has no known gaps"
- `formal/COVERAGE.md`: delegation lattice theorem table added

**Rust strict wire validator (Phase B3)**
- `freedom-kernel/src/wire.rs`: `WireValidationError`, `validate_action_wire()`, `validate_claim_wire()`
- Covers WA-2/3/7/8 attack classes; 11 inline tests

**TLC model checker setup**
- `formal/TLC_SETUP.md`: step-by-step Java + tla2tools.jar install and run instructions

### Performance

| Benchmark | Result |
|---|---|
| `verify()` p50 (10-claim registry) | 23.6µs |
| `verify()` p50 (1000-claim registry) | 23.7µs |
| `verify_plan()` 10 actions p50 | 258µs (3,873 plans/s) |
| `verify() + audit` p50 | 51.2µs |
| Rust target (cargo bench) | <1µs (not runnable without MSVC) |

### Test counts

- Python: **330 tests** (all passing)
- Rust TCB: 141 tests (plus 11 wire.rs tests)
- Kani harnesses: 17 (all proved)
- Lean 4 theorems: 11

---

## v2.1.0 — 2026-05-28/29

### Added

**Phase 1 — Production Hardening (complete)**
- `AuditLog.load_from_file(path)` — reconstruct audit log from .jsonl for forensics
- `AuditLog.load_and_verify(path)` — load + chain verification in one call
- `AuditLog.replay(idx)` — forensic replay of single entry with tamper detection
- `AuditLog.replay_range(start, stop)` — forensic replay of entry range
- `AuditLog.head_hash()` — current chain head (GENESIS_HASH if empty)
- `AuditLog.chain_errors()` — detailed chain error list (for incident response)
- `GENESIS_HASH` constant exported from `authgate.kernel.audit`
- Thread-safety fix: `_last_hash` is now read+set inside the lock in `record()`
  (previously a race condition allowed concurrent appends to produce duplicate prev_hash)
- `FreedomVerifier(freeze=False)` parameter — explicit TOCTOU-safe session mode
- `[A4]` / `[A6]` axiom codes in violation messages for structured external processing
- Structured logging (`authgate.kernel.verifier` logger): DEBUG on PERMIT, WARNING on DENY

**Phase C3 — Key Rotation Protocol**
- `src/authgate/key_rotation.py`: `RotationCertificate`, `issue_rotation()`, `verify_rotation()`
- Grace period overlap window, emergency rotation (zero overlap), wire/JSON roundtrip
- `ActiveKeySet`: tracks current + pending cert, `accepted_keys(now)` returns valid keys

**Phase C2 — Typed Error Hierarchy**
- `src/authgate/errors.py`: `AuthgateError → CapabilityError, RightsError, IntegrityError,
  WireError, RegistryError, KeyRotationError` — structured dataclass exceptions with
  machine-readable fields; exported from top-level `authgate` package

**Phase C4 — CLI Tool**
- `authgate-cli` entry point with `verify`, `audit {verify,replay,stats}`, `key` subcommands
- Exit codes: 0=permit, 1=deny, 2=usage/parse error
- `--json` flag for machine-readable output
- `--audit LOG.jsonl` flag to append audit entry during verify

**Phase 1.3 — Resource Scope Formal Rule**
- `scope_contains()`: path traversal rejection via `_has_traversal()` — any `..` segment
  returns False without normalization (normalization of untrusted paths is attack surface)
- Scope containment rule formally specified in `SEMANTICS.md §4`
- 40+ tests in `tests/test_scope.py` covering all edge cases

**Phase D2 — Real Integration**
- `examples/langchain_integration/demo.py`: end-to-end demo — registry→freeze→verify→audit
  All assertions pass: 2 permits, 3 denies, chain intact

**Phase A — WASM Sandbox**
- `freedom-kernel/src/sandbox.rs`: `SandboxedExecutor` with rights bitmask → host functions
- Unlisted host imports → WASM instantiation failure (structural, not runtime check)
- 11 sandbox tests

**Phase 2.1 — IFC (closed)**
- `tests/test_ifc.py`: 21 Bell-LaPadula tests (SecurityLattice, check_action, check_plan)
- Documented: PUBLIC cannot flow to unlabeled ("") — unknown label treated conservatively

**Phase 2 seed — ConsentCapability**
- `src/authgate/kernel/consent.py`: ConsentCapability, ConsentVerifier, ConsentViolation
- Formal rule: ConsentValid(cap) iff ¬consent_required ∨ (human giver ∧ not expired ∧ scope)
- 18 tests in `tests/test_consent.py`

**Engineering / Package**
- `src/authgate/py.typed`: PEP 561 marker — package is typed for mypy/pyright
- `src/authgate/settings.py`: `AuthgateSettings` from env vars (`AUTHGATE_*` prefix)
- `pyproject.toml`: `authgate-cli` entry point, py.typed in wheel include
- `__init__.py`: errors and key_rotation exported from top-level package

**Documentation**
- `README.md`: complete rewrite — numbers table, CLI section, WASM section, 273 tests
- `GUIDE.md`: full operational guide — install, registry, verify, audit, key rotation,
  CLI reference, thread safety, integration patterns, failure modes, operational checklist
- `SEMANTICS.md`: §4 Resource Scope Containment added (formal rule + properties);
  status table updated with all closed items
- `SILICON_VALLEY.md`: technical positioning — comparison table, WASM enforcement gap,
  explicit non-claims, roadmap, who should use it
- `TODO.md`: updated master roadmap with MASTER_PLAN success criteria tracking

### Changed
- `FreedomVerifier` default: `freeze=False` (live registry semantics preserved)
- `scope_contains`: now rejects `..` path traversal segments
- Tests: 236 → 294 (added IFC, consent, scope, CLI, thread safety, audit hardening,
  key rotation)

### Security
- **AuditLog race condition fixed**: concurrent appends no longer produce duplicate
  prev_hash values; proven by 200-concurrent-append stress test
- **Path traversal hardened**: `scope_contains` now rejects any `..` segment
- **Frozen registry enforced**: `RuntimeError` on any mutation of a frozen snapshot

---

## v2.0.0-alpha — 2026-05-27

### Breaking Changes
- `wire.rs`: New fields added to `ClaimWire` (`trust_domain`, `delegation_depth`) and `ActionWire` (`trust_domain`, `delegation_depth`). Fully backward-compatible via `#[serde(default)]`.
- `CapabilityKind`: Expanded from 8 to 17 variants. Existing code using exhaustive matches must add new arms.

### Added
- **Capability Algebra v2**: Full 17-variant taxonomy with `CapabilityRisk` classification (Low/Medium/High/Critical/Catastrophic)
- **Trust Domains**: Isolation namespaces with explicit cross-domain grant requirements. Added `TrustDomainWire`, `CrossDomainGrant` to wire format.
- **Authority Graph Engine** (`authority_graph.rs`): DAG validation, cycle detection, reachability analysis, cross-domain violation detection
- **Revocation Engine**: `revoke_all()`, `revoke_on_resource()`, `revoke_cascading()`, `expire_stale()` on `OwnershipRegistry`
- **Policy DSL** (`policy_dsl.py`): Textual policy language — `ALLOW/DENY agent READ/WRITE ... UNLESS delegated_by ...`
- **Criterion Benchmarks**: `benches/verify_bench.rs` — permit path, block path, 10k-claim scaling, flag check
- **RFC Ecosystem**: RFC-001 through RFC-006 in `freedom-specs` repo
- **Kubernetes Sidecar**: Example deployment in `examples/kubernetes/`
- **Attack Scenarios**: 5 concrete runnable attack examples in `examples/attack_scenarios.py`
- **Comparative Research**: `PRIOR_ART.md` — formal positioning vs. KeyKOS, seL4, Capsicum, E language, Macaroons, SELinux

### Changed
- `THREAT_MODEL.md`: Complete rewrite — 5 adversary classes, 7 attack scenarios, formal security claims P1-P5
- `ARCHITECTURE.md`: Rewritten to reflect v2 architecture
- `README.md`: Rewritten — scoped to engineering, no philosophical/book references
- `capability.rs` LOC ceiling: 150 → 200 (justified by Capability Algebra v2 expansion)
- Repo split: `authgate-kernel` (engineering), `freedom-specs` (RFCs), `authgate` (theory)

### Removed
- Book references from `README.md` invariants section
- `THEORY.md` reference from engineering docs (moved to `authgate` repo)
- `// Book pp.800-805` inline comment from `verifier.rs`

---

## [Unreleased]

## [1.0.0] - 2026-05-17

### Added
- Initial production release of Capability-security kernel for autonomous agents
- Comprehensive test suite with CI/CD pipeline
- Docker support with multi-stage builds
- Structured logging and observability
- Security scanning in CI pipeline
