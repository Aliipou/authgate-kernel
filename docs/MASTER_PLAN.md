# Freedom Kernel — Master Plan

## Current State (honest assessment)

The project sits between **research prototype** and **foundational infrastructure**.
This is the dangerous phase: overhype, complexity explosion, pseudo-formalism, and
ideological capture all happen here.

**What is genuinely good:**
- `engine.rs` separation — pure verification logic isolated from all I/O and bindings
- JSON wire + C ABI — verifier is a portable governance primitive, not a Python library
- Cryptographic attestation — audit chain, remote verification, tamper evidence
- Theory/kernel separation — kernel is independent of the theoretical framework; using or auditing the kernel requires no engagement with it
- Tiny verifier philosophy — currently ~200 lines of pure logic; this must be maintained

**The primary risk right now:** pseudo-formalism.
The project uses formal vocabulary (axiom, invariant, theorem, TLA+) but is not yet
formally complete. The gap between *formal-looking* and *formally specified* must be
closed or explicitly acknowledged. `SEMANTICS.md` does the latter. The former requires work.

---

## The One Rule

> **The verifier is sacred.**
> Small. Simple. Deterministic. Formally analyzable.
>
> Extensions: free to grow.
> Kernel: nearly untouchable.

If the kernel grows, auditability dies. Formal reasoning dies. Security collapses.
Every feature request for the kernel must pass: *does this belong in the gate, or in an
extension on top of the gate?*

---

## Phases

### Phase 0 — Complete (current state)
**Goal:** Prove the architecture is sound.

- [x] `engine.rs` — pure Rust verification core, zero I/O
- [x] JSON wire format — language-agnostic in/out
- [x] C ABI — `authgate_kernel_verify`, `authgate_kernel_pubkey`
- [x] ed25519 attestation — signed verification results
- [x] Python fallback — identical API, zero config
- [x] Attenuation (`delegate()`) — enforced in both Python and Rust
- [x] `ExecutionContext` — bounded authority scope per task
- [x] `verify_plan()` — per-action authority check with sovereignty cancellation
- [x] `GoalNode` + `verify_goal_tree()` — recursive authority attenuation
- [x] Framework adapters — OpenAI, Anthropic, LangChain
- [x] TLA+ spec — invariants stated (not yet model-checked)
- [x] `SEMANTICS.md` — honest scope: what is guaranteed vs what is not
- [x] CI green on Python 3.11 + 3.12, Rust backend, both branches

**Exit criterion:** CI green, architecture documented, scope honest. ✓

---

### Phase 1 — Mechanical Verification
**Goal:** Move from "stated invariants" to "verified invariants."

**Priority 1.1 — TLC model check**
Run the TLA+ spec through the TLC model checker on a finite instance:
- 2 humans, 2 machines, 3 resources, `MaxDepth = 3`
- Verify all 4 THEOREM declarations exhaustively
- Document any violations found (they are bugs in the spec, not edge cases to ignore)

This is the single highest-leverage action. It moves the project from
"we believe these invariants hold" to "we have checked them mechanically."

**Priority 1.2 — Delegation lattice proof**
Formally prove or disprove: does the delegation relation form a bounded distributive lattice?

Specifically, prove:
1. Transitivity: if A delegates to B and B delegates to C, then C's authority ⊆ A's authority
2. Anti-monotonicity: confidence can only decrease or stay equal through delegation chains
3. No cycles: the delegation graph is a DAG (currently enforced by construction, not proved)

This closes the "delegation underspecified" gap identified in the analysis.

**Priority 1.3 — Resource scope semantics**
Define formally what it means for resource scope `/data/alice/` to contain
sub-resource `/data/alice/file.csv`. Currently this is application-layer convention.
Options:
- Prefix matching (simple, current implicit behavior)
- Glob patterns (flexible, but harder to reason about)
- Explicit subset declarations (most precise, most verbose)

Decision: **prefix matching** for the kernel; extensions may add richer scope matching.
Write the formal rule and add a test suite for scope containment.

**Exit criterion:** TLC run documented (pass or counterexample found), delegation
lattice properties stated with proofs or falsification, scope semantics written as
formal rule with tests.

---

### Phase 2 — Information Flow
**Goal:** Add optional non-interference verification without touching the kernel gate.

The kernel currently enforces *authority* (who can act on what).
It does not enforce *information flow* (whether reading X and then writing Y is safe).

This is the missing layer for "no information leaks" guarantees. It belongs in
**extensions**, not the kernel. The kernel gate is a necessary precondition;
information-flow analysis is a separate pass.

**Priority 2.1 — IFC labels on resources**
Add optional security labels to `Resource`:
```python
Resource("alice-data", ResourceType.DATASET, scope="/data/alice/", ifc_label="SECRET")
Resource("public-report", ResourceType.FILE, scope="/outputs/", ifc_label="PUBLIC")
```

Non-interference rule: a machine that has read a SECRET resource may not write a PUBLIC
resource in the same execution context (information could flow from SECRET to PUBLIC).

This is the Bell-LaPadula model applied to agentic execution.

**Priority 2.2 — IFC checker (extension, not kernel)**
```python
from authgate.extensions.ifc import NonInterferenceChecker
checker = NonInterferenceChecker(verifier, lattice={"SECRET": ["PUBLIC"], ...})
checker.check_plan(actions)  # raises IFCViolation if flow would be violated
```

The kernel gate is called first. IFC is a second pass on top.

**Exit criterion:** IFC labels on Resource (optional, backward-compatible), NonInterferenceChecker
in extensions, 20+ tests covering flow violations.

---

### Phase 3 — Rust Formal Verification
**Goal:** Prove `engine.rs` implements the formal spec exactly.

Use a Rust verification tool to verify that the running code matches the mathematical
specification in `SEMANTICS.md`.

**Tool options:**
- **Kani** (AWS): bounded model checker for Rust, good for checking specific properties
- **Prusti** (ETH Zurich): Viper-based, good for functional correctness
- **Creusot**: Hoare logic for Rust, most expressive but highest effort

**Minimum target:**
- Prove `Permitted(a, R) = true` iff `engine::verify(R, a).permitted = true`
- Prove sovereignty flags always produce `permitted = false`
- Prove attenuation: `confidence` in result ≤ minimum `confidence` in all consulted claims

**Exit criterion:** At least one property of `engine.rs` mechanically verified by a
proof tool. Partial verification is acceptable; the goal is to establish the toolchain
and prove the most critical property (sovereignty flags always block).

---

### Phase 4 — Plan Semantics (research, not engineering)
**Goal:** Understand what verify_plan can and cannot be extended to check.

This is the hardest phase. Checking emergent behavior of action sequences is equivalent
to the halting problem in the general case. But restricted versions are tractable.

**What is tractable:**
- **Structural plan verification** (current): does each action have authority? ✓
- **Resource flow verification**: if action[i] writes resource R, does action[i+1]'s
  read of R require re-verification? This is a static dependency graph check.
- **Conflict detection**: does the plan contain two actions that would create a
  write conflict on the same resource? Detectable statically.

**What is NOT tractable without behavioral specification:**
- Emergent behavior from individually-permitted actions
- Side effects on external systems
- Hidden goals encoded in argument/description fields
- Temporal authority changes during execution

**Deliverable for this phase:** a research note in `formal/plan_semantics.md` that
formally characterizes the boundary between tractable and intractable plan verification.
This is a research document, not code. It defines scope for future work.

**Exit criterion:** `formal/plan_semantics.md` with formal characterization of the
tractable/intractable boundary. No code changes to the kernel.

---

### Phase 5 — Production Hardening
**Goal:** Make the kernel suitable for production deployment.

**Priority 5.1 — Thread safety audit**
The Rust `OwnershipRegistry` uses `Mutex<RegistryInner>`. Audit all lock acquisition
paths for deadlock potential. Add thread-safety tests with concurrent readers.

**Priority 5.2 — Registry snapshot / immutability**
Add `OwnershipRegistry.freeze() -> FrozenRegistry` that produces an immutable snapshot
for use in `verify()`. This eliminates TOCTOU (time-of-check/time-of-use) concerns where
the registry changes between planning and execution.

**Priority 5.3 — Audit log**
`FreedomVerifier.verify()` currently returns a result but does not persist it.
Add optional structured audit logging:
```python
verifier = FreedomVerifier(registry, audit_log=AuditLog(path="/var/log/kernel.jsonl"))
```
Every decision is appended with timestamp, action_id, actor, result, signature.

**Priority 5.4 — Benchmarks**
Add criterion benchmarks for `engine::verify()` in Rust.
Target: <1µs for a registry with 100 claims. This establishes that the kernel
is a negligible overhead on any real workload.

**Exit criterion:** Thread-safety tests, frozen registry, audit log, sub-microsecond
benchmark documented.

---

## What NOT to Build

These are explicit non-goals. Adding them would violate the tiny verifier principle.

| Feature | Why not |
|---|---|
| Natural language parsing of resource descriptions | Introduces NLP ambiguity into the gate |
| ML-based confidence scoring | Non-deterministic, unauditable |
| Distributed registry consensus | Different problem; use a coordination layer above |
| Policy language (Rego, Cedar) | Adds complexity; the ownership graph *is* the policy |
| Automatic goal decomposition | Belongs in the agent, not the gate |
| Runtime self-modification | Explicitly forbidden by sovereignty flags |
| GUI / dashboard | Extensions concern; not in this repo |

---

## Success Criteria for "Foundational Infrastructure"

The project exits the dangerous phase when:

1. **TLC has run** — at least one finite instance model-checked to exhaustion
2. **`engine.rs` has one mechanically verified property** — via Kani or Prusti
3. **`SEMANTICS.md` has no known gaps** — every claim in the README is backed by a
   formal statement in SEMANTICS.md or explicitly labeled as "not yet verified"
4. **Sub-microsecond benchmark** — kernel overhead is negligible
5. **One real integration** — a non-trivial AI system uses the kernel in production
   and the integration is documented (not a toy example)

Until all five are met, the correct description of the project is:
**"A well-architected research prototype with production-grade aspirations."**

After all five are met, the correct description is:
**"Foundational infrastructure for capability-security in agentic AI systems."**

---

## Current Honest Description

> Freedom Kernel is a deterministic, auditable authority gate for autonomous agents.
>
> It enforces typed ownership claims over a static registry snapshot.
> It does not verify emergent behavior, information flow, or plan safety.
> Its invariants are stated formally and partially verified.
> It is a necessary substrate for aligned agentic systems — not a sufficient one.
>
> Status: research prototype with sound architecture.
> Next milestone: TLC model check of core invariants.
