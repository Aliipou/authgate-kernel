# Infrastructure Readiness Plan

**What "infrastructure" means here:**  
Not a product. Not an SDK. A primitive — like `seccomp`, `OAuth`, or `TLS` — that other systems depend on without thinking about it.

The gap between "interesting GitHub repo" and "infrastructure" is not features. It is:
- Reproducible enforcement (not just authorization)
- Survives hostile review
- Deployable in real systems without surprises
- Claims that are verifiable, not just asserted

This document is the engineering roadmap to cross that gap.

---

## Current honest state (2026-05-29)

| Dimension | Status | Gap |
|-----------|--------|-----|
| Formal authorization kernel | Strong | Python layer not formally checked |
| Attack coverage (231 scenarios) | Strong | AT-7.5 partial — full closure needs OS layer |
| Python CallGate (AT-7.5 mitigated) | Done | Python can't enforce at compile time |
| E2E demo (CallGate → audit) | Done | Uses Python layer only, no OS enforcement |
| Rust TCB (compile-time AT-7.5) | Done | Can't build WASM sandbox on Windows |
| OS-level enforcement | Missing | subprocess/ctypes bypass still possible |
| External adversarial review | Missing | Self-tested only |
| Deployable single-org example | Partial | Demo exists, not production-hardened |

---

## Phase I — Enforcement Reality (now → 6 months)

**Goal:** A skeptical security engineer says "this actually constrains execution."

### I-1: CLI tool (E4) — 1–2 weeks
The most underrated infrastructure signal. If a project has a good CLI, it is real.

```bash
authgate-cli verify --registry reg.json --action action.json
# → {"permitted": true, "decision_id": "abc123", "audit_hash": "..."}

authgate-cli audit verify chain.jsonl
# → chain intact: 47 entries, no tampering detected

authgate-cli registry add-machine --owner alice --machine bot --output reg.json
```

**Why now:** CLI is the primary interface for security engineers evaluating the system. Without it, the project is library-only — that limits adoption by the people whose opinion matters most.

**Branch:** integration

### I-2: WASM sandbox on Linux (E1) — 2–4 weeks
The CI workflow exists (`.github/workflows/sandbox.yml`). Needs a Linux runner.

```
cargo build --features sandbox
```

This closes AT-7.5 at the OS level: if a tool's WASM module tries to import a syscall it wasn't granted, instantiation fails before a single instruction runs.

**Why now:** Python enforcement is advisory (can be bypassed). WASM enforcement is structural. This is the boundary between "authorization" and "enforcement."

**Branch:** tcb-core

### I-3: Differential fuzzing (A5 mitigation) — 2–3 weeks
The most dangerous present gap: Python and Rust layers could diverge silently.

```python
# For 10,000 random (action, caps) inputs:
# Run against Python verify()
# Run against Rust verify() via PyO3
# Assert decisions are identical
```

Every divergence is a potential security gap. This must be automated in CI.

**Branch:** adversarial-lab

### I-4: seccomp wrapper for Python tools (E2) — 3–6 weeks
Wraps `SandboxedExecutor.execute()` in a subprocess with seccomp-bpf filter.

```python
# Before: tool runs in main process, can call subprocess.run()
# After:  tool runs in seccomp'd subprocess with allowlist:
#         {read, write, close, exit_group} only
```

This closes the Python subprocess escape. Requires Linux.

**Branch:** tcb-core

---

## Phase II — Credibility (6–12 months)

**Goal:** External engineers can evaluate and trust the project.

### II-1: External adversarial review
One or two security engineers who have no connection to the project. Their job: find ways to bypass the gate.

**Why this is the most important milestone in year 1:** Every other metric (tests passing, formal proofs, LOC ceilings) is self-reported. An independent bypass attempt is the first external signal.

**How to get this:**
- Reach out to capability security researchers (Capsicum, seL4 communities)
- Post the project on security forums with "here is the design, here is where I think it might be weak"
- Offer a public bug bounty (even small — the signal matters more than the amount)

### II-2: Benchmark publication
Public, reproducible benchmarks:

| Benchmark | Target | Current |
|-----------|--------|---------|
| `verify()` permit path | < 5 µs | ~2 µs |
| `verify()` deny (flag) | < 1 µs | ~0.3 µs |
| 10k concurrent verifications | < 100ms | untested |
| Registry with 10k claims | < 50 µs | ~30 µs |
| Cascading revocation, 100 agents | < 1ms | ~600 µs |

If the numbers hold under load, publish them. If they don't, fix them first.

### II-3: Proof versioning (A7 mitigation)
Before any breaking semantic change, implement `schema_version` in `CapabilityProof`. Required before v2.0.

---

## Phase III — Adoption (12–24 months)

**Goal:** Real deployments by people outside the project team.

### III-1: AuthoritySource adapter interface
Abstract the "who signs capabilities" layer (see `research/capability-model-extension.md`).

```python
class AuthoritySource(Protocol):
    def issue_capability(self, request: CapabilityRequest) -> CapabilityProof: ...
    def revoke(self, proof_hash: bytes) -> None: ...

# Implementations:
HumanDelegation(registry)   # current model
MarketOracle(endpoint)       # goal market grants
```

This makes the system extensible without touching the TCB.

### III-2: Typed Tool ABI stabilization
Stabilize `ToolSchema` and `ToolABIRegistry` into a versioned standard:

```python
@gate.register_typed("read_file", schema=ToolSchema(
    params=[ToolParam("path", str, required=True)],
    required_rights={CapabilityKind.READ},
    max_output_bytes=65536,
))
def read_file(path: str) -> str: ...
```

If this schema format stabilizes, it becomes a protocol — tools can declare their capability requirements in a standard way across frameworks.

### III-3: Framework integrations (complete set)
All adapters exist but are not fully tested against real framework versions:

| Framework | Status | Priority |
|-----------|--------|----------|
| LangChain | Exists | High |
| OpenAI Agents SDK | Exists | High |
| AutoGen | Exists | Medium |
| Anthropic (Claude) | Exists | High |
| LangGraph | Exists | Medium |
| CrewAI | Exists | Medium |

Each adapter needs: integration tests against real framework, documented limitations, example that runs without internet access.

---

## Phase IV — Standard (2–5 years)

**Goal:** AuthGate is the default way to gate agent tool calls. Other tools implement the interface.

### IV-1: Stable wire format
The `CanonicalAction` wire format becomes a published standard, not just an internal struct. Other systems can produce `CanonicalAction` JSON and AuthGate can verify it.

### IV-2: Cross-runtime capability transport
Portable `CapabilityProof` format — a proof issued by a Rust runtime can be verified by a Python runtime and vice versa. Currently only works within the same binary.

### IV-3: Multi-issuer trust policy
The trust root becomes configurable: `{Human, Market, DAO, Contract}` can all be trust roots with explicit precedence rules. This is the transition from single-org to shared infrastructure.

---

## What NOT to do (the failure modes)

**1. Adding philosophy to the TCB**  
`constitutional_economy.py`, `sovereignty_metrics.py`, `persuasion.py` are extensions. They must stay in `extensions/` and `analysis/`. If they move into the TCB enforcement path, the formal guarantees become meaningless.

**2. Claiming full formal verification before it's true**  
The Rust TCB has bounded model checking (Kani) and theorem proofs (Lean4) over specific properties. The Python layer has none. Claims must be scoped: "Rust TCB: engine.rs has mechanically verified core invariants."

**3. Premature distribution**  
Do not attempt distributed/federated deployment before:
- Single-node is externally reviewed
- Epoch integrity is solved
- The A5 divergence gap is closed

**4. Feature velocity over TCB discipline**  
Every line added to `engine.rs` must answer: "what attack does this prevent?" If the answer is "it makes the API cleaner," the line belongs elsewhere.

---

## The one metric that matters most right now

**Can a hostile actor bypass the gate on a real deployment?**

Everything else — tests, benchmarks, architecture docs, formal proofs — is preparation for this question. The answer is currently unknown because no hostile actor has tried. The most important engineering action right now is to find out.

---

## Branches and ownership

| Phase | Branch | What lives there |
|-------|--------|-----------------|
| I-1 CLI | integration | `src/authgate/cli.py`, `tests/test_cli.py` |
| I-2 WASM | tcb-core | Linux CI runner, `cargo build --features sandbox` |
| I-3 Fuzzing | adversarial-lab | `attack_harness/differential_fuzzer.py` |
| I-4 seccomp | tcb-core | `src/authgate/kernel/seccomp_executor.py` |
| II-1 Review | (external) | Bug reports → adversarial-lab |
| II-2 Benchmarks | main | `benchmarks/` |
| III-1 AuthoritySource | integration | `src/authgate/authority/` |
| III-2 Typed ABI | integration | stabilize `tool_abi.py` |

---

*Infrastructure is not built. It is grown — by surviving contact with reality, one deployment at a time.*
