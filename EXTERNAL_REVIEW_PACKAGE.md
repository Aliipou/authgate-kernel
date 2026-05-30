# External Adversarial Review Package

**For:** security engineers, capability researchers, formal methods practitioners
**Goal:** find ways to bypass, weaken, or break the authgate-kernel
**Reward:** acknowledgement + bug bounty (terms below)

Estimated review time: **2-4 hours** to reach an opinion. This document is
designed to get you to actionable signal in that window.

---

## 1. What you're reviewing

**One sentence:** A capability proof verifier that gates AI agent tool execution.

Before any tool runs, the system checks that the agent holds a cryptographically
signed capability proof, validly delegated from a human trust root, for the
specific resource, with sufficient rights, not expired, not revoked.

If yes: tool runs. If no: tool denied, attempt logged.

That is all the system does. Anything else (intent verification, ethics,
manipulation scoring, civilization governance) is **explicitly out of scope**
and lives in `extensions/` or `analysis/` modules outside the TCB.

---

## 2. What you're NOT reviewing

Per `NON_GOALS.md`:

| Out of scope | Why |
|-------------|-----|
| Natural-language intent verification | Kernel does not parse text |
| Semantic ethics / alignment | Not provable, by design |
| Side-channel attacks (timing, cache) | Caller's environmental concern |
| Hardware attacks (Rowhammer, Spectre) | OS/HW layer concern |
| Compromised root key (malicious human) | Out of threat model — Phase 1 |
| Distributed / multi-issuer trust | Phase 4 — not yet implemented |
| Compiler/toolchain compromise | Reproducible-build concern |

Findings outside scope are appreciated but not bounty-eligible.

---

## 3. Files to focus on (in order)

The TCB is small. Read these in this order:

| Priority | File | LOC | What to look for |
|----------|------|-----|------------------|
| 1 | `freedom-kernel/src/tcb/engine.rs` | 350 | Pure verify() function. Look for any path that returns Permit incorrectly. |
| 2 | `freedom-kernel/src/tcb/call_gate.rs` | 412 | The ONLY public entry into the TCB. AT-7.5 closure. |
| 3 | `freedom-kernel/src/tcb/dag.rs` | 272 | Delegation chain validation. AT-5.1, AT-3.1, attenuation. |
| 4 | `freedom-kernel/src/tcb/sequence.rs` | 209 | Composition safety tracker. AT-4. |
| 5 | `freedom-kernel/src/tcb/types.rs` | 200 | Binding hash computation. AT-1. |
| 6 | `src/authgate/kernel/call_gate.py` | 220 | Python CallGate. Look for shadow-execution paths. |
| 7 | `src/authgate/kernel/registry.py` | 350 | Identity binding, claims, epoch advance. |

**Total focus area: ~2000 LOC.** The rest is adapters, tests, and analysis layers.

---

## 4. Files NOT in the TCB (don't waste time)

- Everything under `src/authgate/analysis/` — observation, not enforcement
- Everything under `src/authgate/extensions/` — heuristics, not gates
- Everything under `src/authgate/adapters/` — framework glue
- Everything under `src/authgate/api/` — HTTP wrapper

If a finding is in these files but does not affect a `verify()` decision,
it's a regular bug, not a security finding.

---

## 5. Known gaps (already documented)

Read `FINDINGS.md` first. Findings already known:

| ID | Status | Don't re-report |
|----|--------|----------------|
| C-1 | MITIGATED via identity_token; documented residual risk | unless you find a bypass of the token check |
| C-2 | DEPLOY-only (subprocess escape, Linux/WASM closes) | unless you find a bypass of the Rust WASM sandbox |
| C-3 | RESOLVED | epoch revocation works |
| C-4 | DOCUMENTED | Python verify() impurity acknowledged |
| AT-7.5 | MITIGATED (Rust pub(crate), Python name-mangled) | unless you find a way around the mangled attribute |
| Side-channels | OUT OF SCOPE | not bounty-eligible |

A finding that demonstrates a documented gap **with a new exploitation chain**
IS bounty-eligible. A finding that just restates the gap is not.

---

## 6. Threat model recap

**Trusted:**
- The human trust root and their private key
- The build/compile process (use the provided Dockerfile to bypass this assumption)
- The OS kernel (we don't defend against compromised kernel)

**Untrusted:**
- The agent / LLM (assume malicious)
- The adapter layer (LangChain, OpenAI SDK, etc.)
- Tool implementations (assume any tool may try subprocess/ctypes escape — that's why Rust WASM exists)
- The network (replay, mutation, downgrade are in-scope)
- Any code outside `src/tcb/` (analysis, extensions, adapters)

If you find a way for an UNTRUSTED component to cause `verify()` to return Permit
when it should return Deny — that's a real finding.

---

## 7. How to run the attack harness yourself

```bash
git clone https://github.com/Aliipou/authgate-kernel
cd authgate-kernel

# Python tests (no Rust needed)
pip install -e ".[dev]"
pytest -q                                    # 1155 tests
pytest tests/test_adversarial_redteam.py -v  # 25 red-team tests
pytest tests/test_army.py -v                 # 113 multi-expertise tests

# Adversarial simulation (231 scenarios)
python attack_harness/simulation/run_simulation.py

# Differential fuzzer (Python invariants; Rust diff if installed)
pytest attack_harness/differential_fuzzer.py -v

# Rust TCB tests
cd freedom-kernel && cargo test

# Kani bounded model checking
cargo kani --harness prop_seq_accumulated_monotone

# Benchmarks (with --gate flag, fails build on regression)
python benchmarks/comprehensive_bench.py --gate
```

---

## 8. What counts as a finding

In priority order:

| Tier | Description | Example |
|------|-------------|---------|
| **CRITICAL** | A way to make `verify()` return Permit when it should Deny | Forged proof accepted; tampered field undetected; chain bypass |
| **SEVERE**   | A way to deny service / DoS the gate | Memory exhaustion via crafted action; infinite loop |
| **MEDIUM**   | A way to weaken the audit trail | Tamper not detected; entry replay accepted |
| **MEDIUM**   | A way to escape OS-level enforcement on Linux | WASM sandbox escape; seccomp filter bypass |
| **LOW**      | API misuse that produces false security | Docs claim X is enforced, but X is not actually enforced |
| **INFO**     | Inconsistency between documentation and behavior | Doc says "always denies" but only denies "usually" |

Findings outside `src/tcb/` only count if they affect a TCB decision.

---

## 9. How to submit

1. **Confirm the finding is not in `FINDINGS.md`** already
2. **Write a minimal reproducer** — a single Python or Rust file < 100 LOC
3. **Open a private security advisory** on GitHub:
   https://github.com/Aliipou/authgate-kernel/security/advisories/new
4. Include:
   - Tier (CRITICAL/SEVERE/MEDIUM/LOW/INFO)
   - Affected file(s) and line(s)
   - Reproducer
   - Suggested mitigation (optional but appreciated)

Public disclosure: 90 days after a fix is released, OR 180 days from report,
whichever comes first.

---

## 10. Bug bounty

This is a small project. Bounty is currently:

| Tier | Reward |
|------|--------|
| CRITICAL | $500 + public acknowledgement |
| SEVERE   | $200 + public acknowledgement |
| MEDIUM   | $50 + public acknowledgement |
| LOW      | public acknowledgement |
| INFO     | public acknowledgement |

Bounties paid via PayPal or crypto. Acknowledgement is in `SECURITY.md`.

If you find more than one finding, multiply by tier — no caps.

---

## 11. Tools used by the project (cite if you find a tool-specific issue)

| Tool | Use |
|------|-----|
| ed25519-dalek | signature scheme |
| sha2 | binding hash + identity |
| wasmtime | WASM sandbox (Linux only) |
| Kani | bounded model checking |
| Lean 4 | theorem proving |
| Hypothesis | property-based testing |

A finding that exploits a dependency vulnerability (e.g. RUSTSEC) is in scope
if it affects the TCB path.

---

## 12. What this project would love to learn from you

Honest assessment of:

1. **Is the TCB boundary credible?** Or does the v2 path leak in surprising ways?
2. **Is the Python ↔ Rust gap survivable?** The differential fuzzer caught nothing — that means the test set is too narrow, the gap is real and undetected, or the gap is genuinely closed. Help us know which.
3. **Are the formal claims honestly scoped?** `formal/INCOMPLETENESS.md` lists what is NOT proved. Is anything else slipping through?
4. **Would you deploy this for your own agents tomorrow?** If no, what would you need?

The honest "no" answer is more valuable than 1000 passing tests.

---

## Contact

- Security advisories: https://github.com/Aliipou/authgate-kernel/security/advisories
- General questions: GitHub Issues
- Maintainer: github.com/Aliipou

Thank you for reviewing. The project gets credible only when people outside it
push back.

---

*Last updated: 2026-05-30. Re-read before submitting if more than 30 days old.*
