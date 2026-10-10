# Comparative Evaluation

**Phase:** 6 (Research Legitimacy)
**Status:** Initial draft — invite criticism.

---

## Systems Under Comparison

| System | Domain | Model |
|---|---|---|
| **authgate-kernel** | Agentic AI authority control | Capability ownership graph, delegation lattice |
| **OPA (Open Policy Agent)** | General-purpose policy engine | Rego language, ABAC/RBAC |
| **SELinux** | OS mandatory access control | Type enforcement, Bell-LaPadula variant |
| **Object-capability systems** (Cap'n Proto, E, Capsicum) | Language/OS capability systems | Unforgeable object references |
| **Sandbox runtimes** (gVisor, Firecracker) | Process/VM isolation | Syscall interception, hardware virtualization |

---

## Comparison Axes

### 1. Formal verification

| System | Formally verified? |
|---|---|
| authgate-kernel | Partial (Kani 19 harnesses, Lean 4 4 theorems) |
| OPA | No — Rego interpreter is not formally verified |
| SELinux | No — policy language is not formally verified |
| Object-cap | Varies — E language has theoretical proofs; Capsicum is not proved |
| Sandbox runtimes | No — host kernel interface is not formally verified |

### 2. Agentic system suitability

| System | Designed for autonomous agents? |
|---|---|
| authgate-kernel | Yes — primary use case |
| OPA | No — designed for human-operated services |
| SELinux | No — designed for OS-level isolation |
| Object-cap | Partial — capability model maps to agents, but no delegation lattice |
| Sandbox runtimes | No — isolates processes, not agent authority |

### 3. Attenuation enforcement

| System | Enforces attenuation (child ⊆ parent)? |
|---|---|
| authgate-kernel | Yes — structurally enforced at delegation |
| OPA | No — policy language can grant any authority |
| SELinux | Partial — via type transition rules |
| Object-cap | Yes — unforgeable references cannot be amplified |
| Sandbox runtimes | No — isolation only; no delegation model |

### 4. Cryptographic attestation

| System | Signed verification results? |
|---|---|
| authgate-kernel | Yes — ed25519 per decision |
| OPA | No |
| SELinux | No |
| Object-cap | No (references are attestation by construction) |
| Sandbox runtimes | No |

### 5. Human-in-the-loop sovereignty

| System | Enforces human ownership / corrigibility? |
|---|---|
| authgate-kernel | Yes — structural sovereignty flags |
| OPA | Policy-dependent (can be configured) |
| SELinux | No — no human principal concept |
| Object-cap | No — no human principal concept |
| Sandbox runtimes | No |

---

## authgate-kernel's Unique Position

authgate-kernel is the only system in this comparison that simultaneously:
1. Enforces typed capability attenuation in a delegation lattice
2. Provides cryptographic attestation of individual decisions
3. Enforces human principal sovereignty as a structural invariant
4. Targets autonomous agent systems as the primary use case
5. Is partially formally verified

**Gap vs object-capability systems:** Object-cap systems (Cap'n Proto, Capsicum) have
stronger theoretical foundations (confining power is unforgeable), but do not model
human ownership hierarchies or provide per-decision attestation.

**Gap vs OPA:** OPA is more expressive (Rego supports arbitrary policy logic), but
this expressiveness makes it harder to formally verify and easier to misconfigure.

---

## Invitation for Criticism

This evaluation is preliminary. We invite the community to:
- Identify systems not listed here that are closer competitors
- Challenge the comparison axes (are we selecting favorable ones?)
- Provide benchmark comparisons on enforce latency and policy expressiveness
- Identify use cases where existing systems are strictly better
