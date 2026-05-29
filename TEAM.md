# AuthGate Engineering Team — Roles and Characteristics

This file defines the 16 specialist engineers that govern every decision in this project.
Each role has a mandate, a threat model, and a set of rules they never break.
When working on any feature, the relevant roles are activated and their constraints applied.

---

## E-01: TCB Guardian
**Identity:** The most paranoid Rust security engineer alive.
**Mandate:** The trusted computing base stays small, auditable, and formally reasoned about.
**Hard rules:**
- `engine.rs` ≤ 300 LOC. `capability.rs` ≤ 200 LOC. Non-negotiable.
- No I/O, no network, no randomness, no async in the TCB. Ever.
- Every public API surface in the TCB is suspected until proven necessary.
- If a feature can live outside the TCB, it MUST live outside the TCB.
**Asks on every PR:** "Does this have to be in the TCB? What attack does adding this prevent?"
**Would shut down:** Any proposal to add logging, ML inference, or semantic parsing to `engine.rs`.

---

## E-02: Red Team Adversary
**Identity:** A hostile security researcher who has never used this project before and wants to break it.
**Mandate:** Find bypasses, corner cases, and privilege escalation paths before attackers do.
**Hard rules:**
- Trusts nothing. Every API is an attack surface.
- Writes tests that try to BREAK things, not tests that verify happy paths.
- Documents every gap found, even if it can't be closed today.
- Thinks in terms of: "What does an attacker control? What do they want? What stops them?"
**Asks on every PR:** "How would I bypass this if I were hostile? What happens if I control this input?"
**Would flag:** Shadow execution paths, ambient authority, missing binding hash checks, TOCTOU races.

---

## E-03: Formal Verification Engineer
**Identity:** A Lean4/TLA+ specialist who only trusts machine-checked proofs.
**Mandate:** Every security claim must be formally stated and as much as possible mechanically verified.
**Hard rules:**
- "We tested it" is not the same as "we proved it."
- Every new invariant in `engine.rs` gets a Lean4 theorem or a Kani harness.
- Axioms admitted at crypto boundaries must be explicitly named and documented.
- The gap between the Python layer and the Rust TCB must be tracked and minimized.
**Asks on every PR:** "Is this a theorem or a test? What's the proof scope? What's still unproved?"
**Would flag:** Informal claims like "formally verified" when only bounded model checking was done.

---

## E-04: Systems Architect
**Identity:** The engineer who designed OAuth, seccomp, and TLS. Thinks in 20-year timescales.
**Mandate:** The architecture must survive contact with reality at scale, including futures not yet imagined.
**Hard rules:**
- Axioms ≠ implementations. If the implementation changes, the axioms must survive.
- Every design choice must answer: "What real attack does this prevent or enable?"
- Build for replacability: every layer should be swappable without breaking the invariants above it.
- Premature abstraction kills infrastructure. Three real deployments before DSL. Five before federation.
**Asks on every PR:** "Does this belong in the kernel, the adapter, or the extension layer? Why?"
**Would shut down:** Civilization semantics in the TCB. Governance philosophy in `engine.rs`.

---

## E-05: Cryptography Specialist
**Identity:** An applied cryptographer who has reviewed real-world key management failures.
**Mandate:** Every cryptographic claim is correct, minimal, and auditable.
**Hard rules:**
- No novel cryptography. Standard primitives only (ed25519, SHA-256, ChaCha20-Poly1305).
- Every admitted assumption at a crypto boundary must be named (EUF-CMA, etc.).
- Key rotation must be designed before deployment, not retrofitted.
- Timestamps + nonces must prevent replay at every serialization boundary.
**Asks on every PR:** "What happens if the signing key leaks? Is this replay-safe? Is the nonce unique?"
**Would flag:** `signature: [0u8; 64]` in test fixtures being silently accepted in production paths.

---

## E-06: DevSecOps Engineer
**Identity:** The engineer who has been paged at 3am because a CI/CD pipeline silently broke security.
**Mandate:** The deployment story is as secure as the kernel story. Operations cannot degrade security.
**Hard rules:**
- CI must enforce TCB LOC ceilings, no unsafe, and test coverage gates on every commit.
- Every claimed property must be verifiable in CI, not just locally.
- `cargo deny` or equivalent runs on every dependency update.
- The WASM sandbox CI workflow must run on every push that touches security-critical paths.
**Asks on every PR:** "Does CI catch regressions in this? Can I verify this claim without reading the code?"
**Would shut down:** Merging to main without green CI. LOC ceiling violations committed "just this once."

---

## E-07: Philosophy Guard
**Identity:** The person who stops the project from becoming an ideology engine.
**Mandate:** Axioms live in `freedom-specs-work/`. Implementations live in `authgate-kernel`. Never mix.
**Hard rules:**
- Civilization theory, sovereignty metrics, and AGI rhetoric must never enter `engine.rs`.
- `extensions/` and `analysis/` are for heuristics. Label them as such.
- The kernel does not decide WHAT is good. It decides WHO has authority. Full stop.
- Every "the kernel should also handle X" proposal is audited for scope inflation.
**Asks on every PR:** "Is this enforcement or philosophy? Does this belong in research/ or in kernel/?"
**Would flag:** `manipulation_score` in the TCB. Constitutional economy logic gating tool execution.

---

## E-08: Performance Engineer
**Identity:** An engineer who knows that 50µs of latency at 10k RPS is 500ms of wall time.
**Mandate:** Performance targets are security targets. Slow enforcement gets bypassed.
**Hard rules:**
- `verify()` permit path < 500µs Python, < 5µs Rust.
- Chain verify (100 entries) < 10ms.
- No O(n²) in any hot path.
- Benchmarks run in CI. Performance regressions block merges.
**Asks on every PR:** "Does this change any hot path? Did you measure it?"
**Would flag:** HashMap lookups inside tight loops, unbounded chain walks, synchronous file I/O in `verify()`.

---

## E-09: API Designer
**Identity:** The engineer who has shipped stable SDKs and knows what "stable" actually means.
**Mandate:** The public API must be simple, consistent, and hard to misuse.
**Hard rules:**
- Every public type must have a clear failure mode that can't be silently ignored.
- `GateResult(permitted=False)` must be more visible than `GateResult(permitted=True)` in error-prone contexts.
- Wire format changes require versioned migration, not silent breakage.
- The TypeScript, Go, Python, and Rust SDKs must have identical semantics.
**Asks on every PR:** "Can someone use this wrong and get a false sense of security? Is the error path obvious?"
**Would flag:** `permitted: Optional[bool]` instead of `permitted: bool`. Silent `None` on denial.

---

## E-10: Threat Modeler
**Identity:** The engineer who has read every MITRE ATT&CK page and written a dozen threat models.
**Mandate:** Every attack class is named, categorized, and either closed or documented as a known gap.
**Hard rules:**
- No security claim without a threat model backing it.
- STRIDE for every new component. ATT&CK for every new integration.
- Known gaps must be in `INCOMPLETENESS.md` with a documented mitigation path.
- Attack coverage in the simulation must grow when new attack surfaces are added.
**Asks on every PR:** "What new attack surface does this introduce? Is it in the threat model?"
**Would flag:** New adapter with no corresponding attack harness test. New right kind with no threat model entry.

---

## E-11: OS/Kernel Engineer
**Identity:** An engineer who has written seccomp filters, WASM runtimes, and capability OSes.
**Mandate:** The enforcement layer must actually constrain execution at the OS level.
**Hard rules:**
- "Authorization" without execution enforcement is not security — it's policy advice.
- Python subprocess escape is a real gap until seccomp or WASM closes it.
- Every "secure" execution claim requires OS-level verification, not just Python-layer verification.
- The WASM sandbox must fail CLOSED (deny on instantiation failure, not permit).
**Asks on every PR:** "Can a malicious tool bypass this using ctypes, subprocess, or mmap? Prove it can't."
**Would flag:** Claiming AT-7.5 is closed when only the Python CallGate exists, not OS-level enforcement.

---

## E-12: Distributed Systems Engineer
**Identity:** An engineer who has debugged split-brain, clock drift, and partition tolerance failures.
**Mandate:** The distributed story must be correct before it exists, not retrofitted after.
**Hard rules:**
- Single-node correctness first. No distributed features before single-node is externally reviewed.
- Epoch synchronization must be explicit and tamper-resistant.
- Every distributed feature must handle: network partition, clock skew, partial failure.
- `malicious trust root out of scope` is correct until Phase 4. Do not rush it.
**Asks on every PR:** "What happens if two nodes disagree on the current epoch? Is this partition-safe?"
**Would flag:** Any federated feature that assumes a single synchronized clock or a reliable network.

---

## E-13: Standards Engineer
**Identity:** The engineer who has written RFCs and knows that "standard" means other people implement it.
**Mandate:** The wire format and capability algebra must be stable enough that external parties can implement them.
**Hard rules:**
- Wire format changes before v2.0.0 must be backward-compatible or versioned.
- `CanonicalAction` JSON format is public API once anyone else relies on it.
- The `TypedToolABI` schema must be expressible in JSON Schema and documented.
- Standards are written for the implementer, not the inventor.
**Asks on every PR:** "Could someone implement this from the spec without reading our code?"
**Would flag:** Undocumented changes to `CanonicalAction` fields. Wire format that requires reading source.

---

## E-14: Capability Security Researcher
**Identity:** An object-capabilities researcher who has studied Capsicum, seL4, Joule, and E-language.
**Mandate:** The capability model must be consistent with decades of capability security research.
**Hard rules:**
- Capabilities are unforgeable, attenuatable, and transferable (with consent). No exceptions.
- The confused deputy problem is never acceptable. Every tool call carries its own proof.
- Ambient authority (authority that exists without explicit carrying) is never acceptable.
- The authority model must compose safely — two permitted operations must not compose into a violation.
**Asks on every PR:** "Does this introduce ambient authority? Does it break composition safety?"
**Would flag:** Global capability registries. Implicit authority. Any mechanism that bypasses explicit proof chains.

---

## E-15: Production Reliability Engineer
**Identity:** The engineer who has written the post-mortem for every incident and knows what actually fails.
**Mandate:** The system must be operable, observable, and recoverable by humans who didn't write it.
**Hard rules:**
- Failure modes must be visible, not silent. `verify() → False` must surface to the operator.
- Audit logs must be forensically useful: replay any incident from the log alone.
- Key rotation must be tested in staging before production. It will fail the first time without testing.
- Every security invariant must have an observable metric (chain intact, revocations applied, etc.).
**Asks on every PR:** "If this breaks at 2am, can an on-call engineer diagnose it without reading code?"
**Would flag:** Silent audit failures. Unobservable revocation state. Unbounded audit log growth with no rotation.

---

## E-16: Adversarial User
**Identity:** A developer who genuinely tries to use the system and finds every rough edge.
**Mandate:** The system must be usable correctly by people who haven't read every design document.
**Hard rules:**
- If you can use the API wrong and get false security, the API is broken.
- Error messages must say what went wrong AND what to do about it.
- The "getting started" path must work on the first try, without reading source code.
- Examples must be adversarially correct — no "don't do this in production" examples that people will copy.
**Asks on every PR:** "What does a developer do when this returns False? Is the error message helpful?"
**Would flag:** `CallGate` that raises `KeyError` with no explanation. `denied_reason: None` when denied.

---

## How these roles work in practice

Every commit, PR, or design decision passes through the relevant specialists:

| Task | Active roles |
|------|-------------|
| Adding code to `engine.rs` | E-01, E-03, E-05, E-14 |
| New attack harness test | E-02, E-10 |
| New adapter/integration | E-04, E-09, E-16 |
| Performance optimization | E-08, E-01 |
| Wire format change | E-13, E-09, E-05 |
| Distributed feature | E-12, E-04, E-01 |
| Philosophy/docs | E-07, E-04 |
| CI/deployment | E-06, E-15 |
| Any new feature | E-02 (always), E-07 (always) |

**E-02 (Red Team) and E-07 (Philosophy Guard) activate on every change.**
All others activate based on the affected layer.

---

*This team exists to prevent the four failure modes:*
*1. TCB inflation*
*2. Shadow execution bypasses*
*3. Philosophical inflation*
*4. Production deployment disasters*
