# authgate-kernel — Technical Positioning

> This document answers: what is this, why does it matter, and how is it different from everything else that claims to solve the same problem?

---

## The actual problem

AI agents execute tools. Tools have side effects. Current stacks have no principled answer to:

- Which agent may write to this database?
- Who authorized this tool call?
- When did the authorization expire?
- Can I prove post-hoc that every action was authorized?

Existing answers are: prompt engineering, system-prompt restrictions, behavioral filtering. All of these are **semantic** answers to a **structural** problem.

authgate-kernel is the structural answer.

---

## What we built

A capability-security kernel for agent tool execution.

The design constraint: **everything security-enforcing must fit in ~255 LOC of Rust, with no I/O, no state, and no LLM calls**. If it doesn't fit in that constraint, it doesn't belong in the gate.

The formal claim: **same action + same capability proof + same clock = same decision, always**.

The operational claim: **every permitted action leaves a cryptographically signed, hash-chained audit entry that a court or auditor can verify**.

---

## The architecture in one paragraph

Human principals sign `CapabilityProof` chains. Each proof covers: actor identity, resource hash, rights bitmask, expiry, epoch, and a chain of delegations with attenuation enforced at every step (`child.rights ⊆ parent.rights`). A `CanonicalAction` bundles the proofs with a binding hash covering all fields. `CallGate::execute()` — the only public TCB entry point — validates the binding hash, traverses the chain, checks nine invariants in order, and returns `Permit` or `Deny`. No exceptions, no overrides. Every call produces an audit entry chained to the previous one via SHA-256. The chain is tamper-evident — delete or modify any entry and `verify_chain()` fails.

---

## Comparison

| Property | authgate-kernel | Prompt restrictions | Role-based access | OAuth scopes |
|---|---|---|---|---|
| Formal invariants | 9 (Kani + Lean 4) | None | None | None |
| Tamper-evident audit | SHA-256 hash chain | No | No | Sometimes |
| Delegation with attenuation | Yes (enforced by Kani) | No | No | No |
| Expiry + epoch revocation | Yes (O(1)) | No | Manual | Manual |
| Thread-safe, concurrent | Yes (stress-tested) | N/A | Depends | Depends |
| WASM sandbox enforcement | Yes (rights bitmask → host functions) | No | No | No |
| TCB size | ~255 LOC Rust | N/A | Thousands of LOC | Thousands of LOC |
| LLM dependency inside gate | Zero | Yes | No | No |

---

## Why ~255 LOC matters

A gate you can read in one sitting is a gate you can audit. A gate you can audit is a gate you can trust.

The three security-enforcing files:
- `engine.rs` (114 LOC): invariant verification
- `dag.rs` (101 LOC): delegation chain traversal
- `call_gate.rs` (40 LOC): the only public entry point

Every security check has a test that verifies it fires. Every test is named after the attack tree node it closes. The full test suite (141 Rust + 273 Python) is auditable in an afternoon.

---

## The WASM enforcement gap

The largest gap in current AI agent security: **a capability check says "permitted", but the tool can still do anything after it runs**.

We close this with `SandboxedExecutor`:

1. `CallGate::execute()` checks the capability — if denied, zero WASM runs.
2. `build_linker(rights_bitmask)` links only the host functions covered by the bitmask.
3. `Module::instantiate()` — if the tool imports `write_byte` but the bitmask only has `RIGHT_READ`, instantiation fails with "unknown import".
4. This is a WebAssembly-level constraint, not a runtime check.

The key test: `write_tool_blocked_with_only_read_right` — tool imports `write_byte`, bitmask has only `RIGHT_READ`, result is `RuntimeError("unknown import")` before a single byte of tool code runs.

---

## What we don't claim

| Claim | Status |
|---|---|
| "We solve alignment" | No. Alignment is about values. This is about authority. |
| "We prevent all harmful actions" | No. We prevent unauthorized actions. A human can authorize a harmful action. |
| "The Python runtime is as secure as the Rust TCB" | No. The Python layer is a compatibility runtime — useful, tested, not formally checked. |
| "This replaces behavioral monitoring" | No. This is a structural precondition. Behavioral monitors belong on top. |
| "TLC has verified the TLA+ spec" | Not yet. The spec exists; TLC requires a Java runtime setup. |

---

## Where this is going

Phase 1 (current): In-process gate, Python runtime, CLI, WASM sandbox, audit chain.

Phase 2 (in progress): Information flow control (Bell-LaPadula over resource labels), consent algebra, inalienable rights layer.

Phase 3: Distributed consistency — federated capability validation, multi-node revocation, consensus-integrated epoch management.

Phase 4: Cognitive sovereignty — human consent verification for actions affecting humans directly.

Phase 5: Constitutional distributed systems — capability registries with formal governance, multi-stakeholder policy verification.

The kernel stays small. Each phase adds a layer on top. The 255 LOC critical path never grows.

---

## Who should use this

**Use authgate-kernel if:**
- You have agents executing tools with real side effects (file writes, API calls, database mutations)
- You need a post-hoc audit trail a regulator or auditor can verify
- You need formal guarantees about authorization correctness, not just policy documents
- You want revocation that works in O(1) when a machine is compromised

**Do not use authgate-kernel if:**
- You only need coarse behavioral filtering (use a content filter)
- You need multi-node distributed consensus out of the box (add a consensus layer on top)
- You need intent verification from natural language (different problem, different tool)

---

## The number that matters

273 tests, 141 Kani/Lean-covered, 255 LOC security path, p50=18µs Python latency.

All passing. No exceptions.
