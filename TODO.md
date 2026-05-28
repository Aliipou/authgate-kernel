# authgate-kernel — Implementation TODO

> Identity: "A formally constrained capability-security kernel for agent tool execution."
> Analogy: seccomp/SELinux for agentic AI. Narrow. Deployable. Operationally real.
>
> MASTER_PLAN.md success criteria (required to call this "foundational infrastructure"):
>   [ ] 1. TLC has run — at least one finite instance model-checked to exhaustion
>   [x] 2. engine.rs has one mechanically verified property — Kani, 19 harnesses
>   [ ] 3. SEMANTICS.md has no known gaps
>   [ ] 4. Sub-microsecond Rust benchmark + Python latency baseline documented
>   [ ] 5. One real integration — non-trivial AI system, documented
>
> Current honest label: "well-architected research prototype with production-grade aspirations."
> Target label:         "foundational infrastructure for capability-security in agentic AI."

---

## Status key
- [x] done and committed
- [~] partially done / exists but incomplete
- [ ] not started

---

## Phase 0 — Architecture (COMPLETE)

- [x] engine.rs — pure Rust verification core, zero I/O
- [x] JSON wire format + C ABI (authgate_kernel_verify, authgate_kernel_pubkey)
- [x] ed25519 attestation — signed verification results
- [x] Python fallback — identical API, zero config
- [x] Attenuation enforced in Rust dag.rs and Python layer
- [x] Framework adapters — OpenAI, Anthropic, LangChain (src/authgate/adapters/)
- [x] TLA+ spec — invariants stated (formal/authgate_v3.tla)
- [x] SEMANTICS.md — honest scope documentation

---

## Phase 1 — Mechanical Verification

### 1.1 TLC model check  ← BLOCKED (needs Java + tla2tools.jar)
- [ ] Install Java and download tla2tools.jar
- [ ] Run: `java -jar tla2tools.jar -tool MC_AuthGateV3`
- [ ] Verify all 9 invariants + PermitSoundness (or document counterexamples)
- [ ] Add CI job on spec-core branch: GitHub Actions with Java runner
- Branch: spec-core

### 1.2 Delegation lattice  ✅ DONE
- [x] Transitivity: attenuation enforced in dag.rs (rights ⊆ parent.rights)
- [x] Resource propagation: child cap cannot redirect root resource (dag.rs)
- [x] Chain depth bound: MAX_CHAIN_DEPTH = 16
- [x] AT-5.1: SHA-256(pubkey) = subject_id binding at every delegation node
- [x] Tests: hardening_tests.rs (31 tests including 6 proptest properties)

### 1.3 Resource scope formal rule + tests
- [ ] Write formal prefix-matching rule in SEMANTICS.md:
      "resource R1 contains R2 iff R2.scope starts with R1.scope"
- [ ] Add scope containment tests in tests/test_scope.py (20+ cases)
      - "/data/alice/" contains "/data/alice/file.csv" → True
      - "/data/" does NOT contain "/etc/passwd" → False
      - Exact match: "/data/alice/" contains "/data/alice/" → True
      - Trailing slash normalization
      - Path traversal rejection: "/data/../etc" → False
- Branch: spec-core (spec) + adversarial-lab (tests)

---

## Phase 2 — Information Flow

### 2.1 IFC labels  [~] exists but incomplete
- [~] src/authgate/extensions/ifc.py exists
- [ ] Read current IFC state and document gaps
- [ ] Wire IFC labels into Resource (optional field, backward-compatible)
- [ ] NonInterferenceChecker.check_plan() — full Bell-LaPadula enforcement
- [ ] 20+ tests covering flow violations (SECRET→PUBLIC denied)
- Branch: integration

---

## Phase 3 — Rust Formal Verification  ✅ DONE

- [x] Kani: 19 harnesses, all proved
      - All 10 sovereignty flags: always blocked
      - Ownerless machine: always blocked
      - Machine governs human: always blocked
      - Public resource read: always permitted
      - Write without claim: always denied
      - Attenuation two-node: all bitmask combinations
      - Epoch gate: total relation proved
      - Forged revocation: never flips Permit→Deny
- [x] Lean 4: 7 theorems (forbidden flags, attenuation, epoch gate,
      subject mismatch, determinism, stale epoch, rights sufficiency)

---

## Phase 4 — Plan Semantics  ✅ DONE

- [x] formal/plan_semantics.md — tractable vs intractable boundary documented
- [x] verify_plan() in verifier.py — structural authority check per action
- [x] Sovereignty propagation: flag in action[i] → cancel actions[i+1:]

---

## Phase 5 — Production Hardening  ← CURRENT FOCUS

### 5.1 Thread safety audit + tests
- [~] OwnershipRegistry uses threading.RLock — exists but untested concurrently
- [ ] tests/test_thread_safety.py — concurrent reader/writer tests:
      - 50 readers, 5 writers simultaneously — no deadlock, no data race
      - freeze() + read from snapshot while original mutates — no corruption
      - verify() concurrent calls return consistent results
      - AuditLog concurrent append — chain integrity preserved under concurrent writes
- Branch: integration

### 5.2 Frozen registry  ✅ DONE
- [x] OwnershipRegistry.freeze() → immutable snapshot (registry.py)
- [x] Frozen registry raises RuntimeError on any mutation attempt
- [x] Snapshot is independent copy — original mutations don't affect snapshot
- [ ] Wire freeze() into FreedomVerifier: verify() uses frozen snapshot by default
      Currently: verifier holds registry directly (live, can mutate under verify)
      Fix: in FreedomVerifier.__init__, call registry.freeze() and store snapshot

### 5.3 Audit log  [~] exists but needs hardening
- [x] AuditLog with hash-chain integrity (audit.py)
- [x] Wired into FreedomVerifier.verify()
- [ ] AuditLog.load_from_file(path) — reconstruct from persisted .jsonl
- [ ] AuditLog.verify_chain() test under concurrent writes (50 concurrent verifies)
- [ ] AuditLog.replay(entry_idx) — reconstruct decision context for forensics
- [ ] Test: tamper one entry → verify_chain() returns False
- [ ] Test: delete one entry → verify_chain() returns False
- Branch: integration

### 5.4 Benchmarks  ← MISSING — blocks "foundational infrastructure" label
- [ ] benchmarks/python_verify_bench.py — FreedomVerifier.verify() microbenchmark
      - Single verify() call: target <100µs (Python layer overhead is acceptable)
      - 1000-claim registry lookup: document actual p50/p95
      - verify_plan() on 10-action plan: document throughput
- [ ] Document Rust benchmark results (cargo bench --bench verify_bench)
      - Target <1µs per verify() call in Rust
- [ ] Add benchmark numbers to README in Benchmarks section
- Branch: integration

---

## Phase B — Wire Boundary Hardening (adversarial-lab work)

- [x] wire_attacks.py (27 tests) — JSON deserialization boundary
- [x] differential_tests.py (20 tests) — Python model semantics
- [ ] B3: Rust strict wire parser — mirror wire_attacks.py rejection classes in serde
      File: freedom-kernel/src/wire.rs
      Add: strict field validation, reject unknown fields, reject float-in-u64
- [ ] B4: --rust flag for differential_tests.py — wire format alignment needed first
- [ ] B5: WA-1 duplicate key — test Rust serde_json behavior explicitly,
           document last-wins or add explicit rejection
- Branch: adversarial-lab (tests) + tcb-core (Rust impl)

---

## Phase C — Production Reality

### C1: Wire audit log into FreedomVerifier default  (see 5.3 above)
### C2: Typed error hierarchy
- [ ] src/authgate/errors.py:
      AuthgateError → CapabilityError, RightsError, IntegrityError, WireError
      Each with structured fields (actor_id, resource_hash, failed_check, value)
- [ ] Replace bare string violations in verifier.py with typed exceptions
      (keep backwards-compat: VerificationResult.violations still contains strings)
- Branch: integration

### C3: Key rotation protocol
- [ ] docs/KEY_ROTATION.md — operational procedure:
      root key rotation via epoch advancement, grace period, emergency rotation
- [ ] src/authgate/key_rotation.py — KeyRotationManager
      rotate(old_sk, new_sk, new_epoch) → signed rotation certificate
      verify_rotation(cert, old_vk) → bool
- Branch: integration

### C4: CLI tool
- [ ] authgate-cli verify --registry reg.json --action action.json
- [ ] authgate-cli audit verify <log.jsonl>
- [ ] authgate-cli key rotate --old-key old.pem --new-key new.pem --epoch N
- Branch: integration

---

## Phase D — Success Criteria Completion

### D1: SEMANTICS.md gap closure  (criteria #3)
- [ ] Read SEMANTICS.md, list all informal claims
- [ ] For each claim: add formal statement, or label explicitly as "not yet verified"
- [ ] No claim left ambiguous
- Branch: spec-core

### D2: One real integration  (criteria #5)
- [ ] End-to-end test: LangChain tool → FreedomVerifier.verify() → SandboxedExecutor
- [ ] Audit log entry per action
- [ ] Document in examples/langchain_integration/
- Branch: integration

---

## Build order (this session)

1. [x] Phase A sandbox — DONE
2. [x] Phase B wire_attacks.py, differential_tests.py — DONE
3. [ ] **5.4 Benchmarks** — implement now (benchmarks/python_verify_bench.py)
4. [ ] **5.1 Thread safety tests** — implement now (tests/test_thread_safety.py)
5. [ ] **5.3 Audit log: load_from_file + tamper tests**
6. [ ] **5.2 Wire freeze() into verifier**
7. [ ] **1.3 Resource scope tests**
8. [ ] **C3 Key rotation**
9. [ ] **D2 Real integration test**

---

## Branch assignment

| Work | Branch |
|------|---------|
| 5.1, 5.2, 5.3, 5.4, C2, C3, D2 | `integration` |
| B3, B4, B5, 1.3 tests | `adversarial-lab` |
| 1.1 TLC, 1.3 spec, D1 | `spec-core` |
| B3 Rust | `tcb-core` |
| README, TODO | `adversarial-lab` then propagate |
