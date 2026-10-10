# authgate-kernel — Implementation TODO

> Aligned with `ultimate-plan.md`: sovereignty-preserving execution substrate →
> constitutional infrastructure for autonomous digital civilization.
>
> Status key: [x] done | [~] partial | [ ] not started | [!] blocked
>
> Current state (2026-05-29): 853 tests passing. All Phases 0–6 structurally complete (Python layer).

---

## ultimate-plan.md Phase Alignment

### PHASE 0 — FOUNDATIONAL PURIFICATION [COMPLETE]
- [x] O1: TCB ≤300 LOC, zero unsafe, deterministic (engine.rs + dag.rs + call_gate.rs ~255 LOC)
- [x] O2: Philosophy/enforcement separation (formal/ vs tcb/ vs src/authgate/)
- [x] O3: Complete threat taxonomy (ESC-1..6, DEL-1..5, COER-1..10, WA-1..18)
- [~] O4: Formal language (SEMANTICS.md, Lean4, Kani ✓; TLC run pending)

### PHASE 1 — REAL EXECUTION CONSTRAINTS [COMPLETE — Python layer]
- [x] O1: Python SandboxedExecutor (sandbox_executor.py) — capability-gated tool execution
- [!] O1: Rust WASI sandbox (blocked: Windows SDK kernel32.lib missing)
- [x] O2: Typed Tool ABI (tool_abi.py) — ToolSchema, ToolParam, ToolABIRegistry
- [x] O3: Agent framework integrations (LangChain, OpenAI, AutoGen, Anthropic, MCP, LangGraph, CrewAI, DSPy)
- [x] O4: Signed audit export (audit.py) — Ed25519 over chain head, verify_signed_export()

### PHASE 2 — FORMAL SOVEREIGNTY MODEL [COMPLETE]
- [x] O1: ConsentCapability (consent.py) — revocable, contextual, time-bounded, non-delegable
- [x] O2: InnalienableRights layer (inalienable.py) — BEHAVIORAL_OWNERSHIP, MONOPOLY_DELEGATION, etc.
- [x] O3: OverrideDetector (override_detector.py) — OWNER_LOCKOUT, DEEP_DELEGATION_CHAIN
- [x] O4: CoercionAnalyzer (coercion.py) — SINGLE_POINT_OF_CONTROL, DEPENDENCY_MONOPOLY, COALITION_LOCK_IN

### PHASE 3 — ECONOMIC AND CIVILIZATION LAYER [COMPLETE]
- [x] O1: Economic property ontology (ATTENTION, IDENTITY, BEHAVIORAL_PROFILE, DIGITAL_TWIN, etc. in entities.py)
- [x] O2: Multi-agent coordination (multi_agent_coordinator.py) — DependencyAnalyzer, CoalitionChecker
- [x] O3: Sovereign identity layer (sovereign_identity.py) — commitment-based selective disclosure, ZK-compatible
- [ ] O4: Constitutional agent markets — future work

### PHASE 4 — COGNITIVE SOVEREIGNTY [COMPLETE]
- [x] O1: Persuasion boundaries (persuasion.py) — 5 structural criteria, hard block ≥3
- [x] O2: Anti-capture systems (anti_capture.py) — SCOPE_DRIFT, CREDENTIAL_ACCESS, OWNER_MISMATCH
- [x] O3: Sovereignty metrics (sovereignty_metrics.py) — HHI dependency, reversibility index, agency score

### PHASE 5 — DISTRIBUTED CONSTITUTIONAL SYSTEMS [COMPLETE]
- [x] O1+O2: Cross-kernel federation + Constitutional consensus (federation.py) — FederatedKernelID, ConstitutionalConsensus, veto-by-trust-level
- [x] Thread safety: OwnershipRegistry, FreedomVerifier, AuditLog under concurrent access (test_thread_safety.py)
- [x] freeze=True default: TOCTOU eliminated in FreedomVerifier
- [ ] O3: Governance layer (constitutional amendment model) — future work

### PHASE 6 — MACHINE CIVILIZATION SAFETY [COMPLETE]
- [x] O1: Recursive agent governance (recursive_governance.py) — depth limits, anti-feudal, HHI, cycle detection, revocation propagation
- [x] O2: Constitutional AI economies (constitutional_economy.py) — oligarchy threshold, sovereignty erosion, irreversible lock-in, high-value monopoly
- [x] O3: Sovereign exit guarantees (exit_guarantees.py) — exit rights, identity portability, revocation reachability

---

## Engineering Gaps (not theory — actual enforcement)

### E1: Rust WASM Sandbox [BLOCKED]
- Status: Windows SDK kernel32.lib not found → `cargo build --features sandbox` fails
- Plan file: `C:\Users\admin\.claude\plans\splendid-tumbling-pelican.md`
- What it does: WASM-level enforcement — if tool imports `write_byte` but only READ right is linked,
  instantiation fails at the WebAssembly level (not a policy check)
- Unblock: install Windows SDK 10.0.22621 manually or use a Linux build environment
- Branch: tcb-core

### AT-7.5 status update (2026-05-29)
- Python CallGate (kernel/call_gate.py) now provides API-level mitigation:
  - GatedTool.__fn is name-mangled — not accessible via public attribute
  - Any code using CallGate.register() → GatedTool cannot bypass verify()
  - 18 passing tests in tests/test_call_gate.py
- Remaining gap: holding original fn reference before registration still bypasses
- Full closure: Rust engine::verify is pub(crate) (compile-time) + E1/E2 below

### E2: OS-level enforcement (seccomp / WASI)
- Python SandboxedExecutor / CallGate gates at the Python layer only — a malicious tool can bypass via ctypes, subprocess, etc.
- Real enforcement requires seccomp-bpf (Linux) or WASI host runtime
- Target: wrap tool execution in a subprocess with seccomp filter, or run WASM tools via wasmtime
- Branch: tcb-core

### E3: Real integration end-to-end
- Need: LangChain tool → FreedomVerifier.verify() → SandboxedExecutor.execute() → audit log
- Currently only unit-tested in isolation
- File: examples/langchain_integration/
- Branch: integration

### E4: CLI tool
- `authgate-cli verify --registry reg.json --action action.json`
- `authgate-cli audit verify <log.jsonl>`
- Branch: integration

### E5: TLC model checker
- TLA+ spec exists (formal/authgate_v3.tla) but TLC has not been run
- Needs Java + tla2tools.jar
- Branch: spec-core

---

## Formal Verification Status

| Method | Status | Location |
|--------|--------|----------|
| Kani (Rust) | 19 harnesses proved | freedom-kernel/src/ |
| Lean 4 | 7 theorems proved | formal/lean/ |
| TLA+ spec | Written, not model-checked | formal/authgate_v3.tla |
| Property tests | 200+ Hypothesis cases | tests/test_*.py |

---

## Branch assignment

| Work | Branch |
|------|---------|
| E1 Rust sandbox, E2 OS enforcement | `tcb-core` |
| E3 integration, E4 CLI | `integration` |
| E5 TLC | `spec-core` |
| Adversarial attack tests | `adversarial-lab` |
