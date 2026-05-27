# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | No        |

---

## Scope: Security Properties Claimed and Not Claimed

### Properties this kernel claims

The kernel makes narrow, mechanically verified claims about a specific
~200-line Rust function (`engine.rs`). Every claim below is backed by
either a Kani bounded model-checking harness or a Lean 4 proof with no
`sorry`. See [`formal/`](formal/) for the artifacts.

| Property | Mechanism |
|---|---|
| All 10 forbidden flags unconditionally produce BLOCKED for any input | Kani: 10 harnesses |
| A machine with no registered owner is always BLOCKED | Kani: `prop_ownerless_machine_blocked` |
| A machine that governs a human is always BLOCKED | Kani: `prop_machine_governs_human_blocked` |
| PERMITTED ↔ violations list is empty (and vice versa for BLOCKED) | Kani: `prop_permitted_implies_no_violations`, `prop_blocked_implies_violations_non_empty` |
| Verification is deterministic: same input always produces same output | Kani: `prop_permitted_deterministic` |
| Delegated authority cannot exceed delegator authority (attenuation) | Lean 4: `attenuation_cannot_escalate` |
| IFC taint is monotone across a plan | Lean 4: `taint_monotone` |
| ed25519 signing key is generated once per process; results carry timestamp + nonce | `crypto.rs` |

**Scope of these proofs:** `engine.rs` behaviors on typed inputs only.
The Python implementation, adapters, extensions, and anything involving
natural language are explicitly outside these proofs.

### Claims not made

The following are **not** security properties of this system and are
**not vulnerabilities** if observed:

- An agent produces harmful, offensive, or dangerous output text.
  The kernel does not inspect semantic content. This is intentional
  and documented in [`NON_GOALS.md`](NON_GOALS.md).
- A malicious human owner grants excessive capabilities to a machine.
  The kernel enforces structural constraints on delegation; it does not
  evaluate whether a trust root is itself trustworthy.
- The manipulation score returned by `ExtendedFreedomVerifier` is wrong
  or bypassable. `manipulation_score` is a heuristic signal in an
  extension that is explicitly outside the Trusted Computing Base.
- Covert channels, timing side-channels, or steganographic leakage.
  These are documented as out-of-scope in [`THREAT_MODEL.md`](THREAT_MODEL.md).
- The Python implementation behaves differently from `engine.rs`.
  The Python implementation is not formally verified and is not part of
  the TCB. It is provided for environments where the Rust build is not
  available.
- Prompt injection causes an agent to request a harmful action.
  The kernel blocks the action if the agent lacks authority regardless
  of what caused the agent to request it. Preventing prompt injection
  itself is the responsibility of the agent runtime, not this kernel.
- A policy rule in the DSL layer (`policy_dsl.py`) is misconfigured.
  The Policy layer is outside the TCB. Misconfiguration is an
  operational concern, not a kernel security defect.

---

## Vulnerability Classification

The following scale is adapted for capability-security systems.
CVSS base scores are provided as a rough external reference point.

### Critical — TCB bypass

The verifier can be circumvented: a BLOCKED result is changed to
PERMITTED without a legitimate authority grant, or the kernel can be
made to execute arbitrary code.

Examples:
- Memory safety violation in `engine.rs`, `capability.rs`, `wire.rs`,
  or `crypto.rs` reachable from untrusted input
- Deserialization gadget in the JSON wire format that bypasses invariant
  checks
- C ABI buffer overflow in `freedom_kernel_verify` reachable from an
  untrusted caller

CVSS analog: 9.0–10.0. Patch target: 7 days.

### High — Invariant violation

A valid, well-formed input can produce an incorrect PERMITTED result
without any TCB memory corruption. The logical invariants A4, A6, or
A7 can be made to return the wrong answer.

Examples:
- An actor with no owner entry in the registry obtains PERMITTED
- A machine can perform an action that governs a human and obtain PERMITTED
- A forbidden flag set to `true` yields PERMITTED for any input

CVSS analog: 7.0–8.9. Patch target: 30 days.

### Medium — Attenuation violation

A delegated agent can escalate its capability above what the delegator
holds. The child-capability ⊆ parent-capability invariant is broken.

Examples:
- `registry.delegate()` accepts a claim with `can_write=true` when the
  delegator holds only `can_read=true`
- Delegation depth counter overflows or wraps, allowing unlimited chains

CVSS analog: 4.0–6.9. Patch target: 90 days.

### Low — Information leakage

The verification outcome is correct, but information about the registry
state, policy structure, or timing is observable by an unauthorized party.

Examples:
- Audit log entries are readable without owner authentication
- Timing difference between PERMITTED and BLOCKED leaks resource existence
- Verification error messages reveal internal registry structure

CVSS analog: 0.1–3.9. Patch target: 180 days.

---

## Reporting a Vulnerability

This is open-source infrastructure. Report vulnerabilities by opening a
GitHub Issue with the **security** label:

https://github.com/Aliipou/freedom-kernel/issues/new?labels=security

Include in your report:
1. A minimal, self-contained reproduction (code or input that triggers
   the issue).
2. The expected behavior and the actual behavior observed.
3. Your assessment of the severity class (Critical / High / Medium / Low)
   and a brief justification.
4. Whether you believe the issue is in the TCB (`engine.rs`,
   `capability.rs`, `wire.rs`, `crypto.rs`) or outside it.

For issues where public disclosure before a fix would create meaningful
risk, use GitHub's private security advisory mechanism instead:

https://github.com/Aliipou/freedom-kernel/security/advisories/new

We will confirm receipt within the response times below. If you do not
receive a response within the stated window, follow up on the issue thread.

---

## Response Commitments

| Severity | Acknowledgement | Fix Target |
|----------|----------------|------------|
| Critical | 24 hours       | 7 days     |
| High     | 48 hours       | 30 days    |
| Medium   | 7 days         | 90 days    |
| Low      | 14 days        | 180 days   |

These are targets, not guarantees. Complex TCB issues may require
coordination with formal verification tooling (Kani, Lean 4) before
a fix can be shipped.

---

## Disclosure Process

1. Issue is filed (public with **security** label, or private advisory).
2. Maintainers reproduce and classify the issue.
3. Fix is developed, with updated Kani harnesses or Lean 4 proofs if the
   TCB is affected.
4. For Critical and High issues: a CVE is requested from GitHub or MITRE.
5. Fix is released; the public issue or advisory is updated with the
   patch version.
6. `CHANGELOG.md` entry is added with a `[Security]` prefix.

---

## TCB File List

The Trusted Computing Base is exactly these four files:

| File | Role |
|---|---|
| `freedom-kernel/src/engine.rs` | Core verification logic |
| `freedom-kernel/src/capability.rs` | Capability algebra (enums only) |
| `freedom-kernel/src/wire.rs` | Typed JSON wire format |
| `freedom-kernel/src/crypto.rs` | ed25519 attestation |

All other files — adapters, extensions, Python implementation, registry,
policy layers — are outside the TCB. Vulnerabilities in those files are
still in scope for this policy, but they are classified differently:
a bug in an extension cannot be Critical by definition, because the TCB
gate runs first, unconditionally, and cannot be bypassed by extension code.
