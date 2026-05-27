# Changelog

All notable changes to Freedom Kernel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
