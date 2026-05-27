# freedom-kernel — Architecture v2

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  Human Principal (trust root)                                       │
│  - registers machines                                               │
│  - holds root claims on all resources                               │
│  - only entity that can modify REGISTRY or POLICY                   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ registers, delegates, revokes
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  OwnershipRegistry                                [not TCB]         │
│  - claims map: (actor, resource) → RightsClaim                      │
│  - machine → human owner entries                                    │
│  - delegation chains (DAG, cycle-detected)                          │
│  - trust domain memberships                                         │
│  - revocation engine (eager / lazy / cascading)                     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ registry snapshot (read-only view)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  engine.rs  — Trusted Computing Base                   [TCB]        │
│                                                                     │
│  Input:  ActionWire (typed, no natural language)                    │
│  Output: VerificationResult {permitted, violations[], signature}    │
│                                                                     │
│  Guards (in order, short-circuit on first BLOCKED):                 │
│    [1] sovereignty flag check     O(1)  — 10 unconditional flags    │
│    [2] machine ownership check    O(1)  — actor in registry?        │
│    [3] machine-governs-human      O(1)  — dominion check            │
│    [4] claim verification         O(n)  — per resource, per right   │
│                                                                     │
│  Properties: pure function, no I/O, deterministic, <300 LOC         │
└────────────┬────────────────────────┬───────────────────────────────┘
             │ PERMITTED              │ BLOCKED
             ▼                        ▼
┌────────────────────┐   ┌────────────────────────────────────────────┐
│  AuditLog          │   │  Violation surface                         │
│  append-only JSON  │   │  - structured ViolationRecord              │
│  ed25519 signed    │   │  - surfaced to human owner                 │
│  timestamp + nonce │   │  - halt: action does not execute           │
└────────────────────┘   └────────────────────────────────────────────┘

Outside TCB (extension layer):
  AuthorityGraphEngine  — DAG analysis, cross-domain checks
  TrustDomainManager    — isolation namespace enforcement
  PolicyDSL             — textual policy language (ALLOW/DENY rules)
  NonInterferenceChecker — Bell-LaPadula IFC
  ManipulationDetector  — heuristic score (signal only)
  Framework adapters    — LangChain, OpenAI Agents SDK, AutoGen, Anthropic
```

---

## 2. Trusted Computing Base (TCB)

The TCB is the minimal set of code that must be correct for the security properties to hold. Every line is subject to Kani model-checking and Lean 4 proofs.

### Components

| File | LOC ceiling | Role |
|---|---|---|
| `engine.rs` | 300 | Single exported function `verify()`. Pure, deterministic, no I/O. |
| `capability.rs` | 200 | Closed enum of all 17 `CapabilityKind` variants + `CapabilityRisk`. Enums only, no structs, no logic. |
| `wire.rs` | uncapped | Typed serde structs: `ActionWire`, `ClaimWire`, `RegistryWire`. No business logic. |
| `crypto.rs` | uncapped | ed25519 signing and verification via `ring`. No policy logic. |

### Why these four files and nothing else

`engine.rs` is the gate. It needs `capability.rs` to name kinds, `wire.rs` to deserialize inputs, and `crypto.rs` to sign outputs. No other component is on the PERMITTED/BLOCKED decision path.

`ffi.rs`, `verifier.rs`, and `registry.rs` wrap or feed the TCB — they are **not** in the TCB because a bug in them cannot cause `engine.rs` to emit a false PERMITTED verdict. They can cause incorrect inputs, which is a different failure mode and is handled by the registry's own validation layer.

### TCB inflation policy

Any PR that increases TCB LOC beyond the ceiling, adds a new TCB file, or adds a dependency to a TCB file is automatically blocked by CI. Justification requires a written argument that the addition cannot exist outside the TCB and a review from a second engineer.

---

## 3. Authority Graph Engine (v2)

`authority_graph.rs` provides DAG analysis over the ownership graph. It is **not** in the TCB — bugs here cannot produce false PERMITTED verdicts — but it guards the registry layer.

### Structure

```
OwnershipRegistry
  └── authority_graph: AuthorityGraph
        ├── nodes: HashMap<ActorId, Node>
        │     Node { actor, trust_domain, depth }
        ├── edges: Vec<DelegationEdge>
        │     DelegationEdge { from, to, rights, depth, expires_at }
        └── domain_map: HashMap<TrustDomainId, HashSet<ActorId>>
```

### Operations

| Operation | Complexity | Description |
|---|---|---|
| `reachability(actor, resource)` | O(V + E) | Can actor reach resource via any delegation path? |
| `cycle_detection()` | O(V + E) | Topological sort; cycles are rejected at `delegate()` time |
| `cross_domain_violations()` | O(E) | Edges crossing trust domain boundaries without explicit grant |
| `delegation_depth(actor)` | O(depth) | Distance from root human principal |
| `subgraph(root)` | O(V + E) | All agents reachable from a given principal |

### Cycle detection

Cycles in the delegation graph would allow authority amplification (A → B → A could bootstrap claims neither A nor B holds). `delegate()` runs topological sort before committing any new edge. If a cycle would be created, the delegation is rejected with `CyclicDelegationError`.

### Depth cap

Maximum delegation depth is 16 hops from the root human principal. An `AgentSpawnRequest` that would exceed depth 16 is rejected. This prevents unbounded recursive delegation chains in multi-agent systems.

---

## 4. Capability Algebra v2

The capability vocabulary is a closed enum in `capability.rs`. It is exhaustive — no runtime-defined capabilities exist.

### Full taxonomy

| CapabilityKind | CapabilityRisk | Delegable by machine? |
|---|---|---|
| `READ` | Low | Yes |
| `WRITE` | Medium | Yes |
| `EXECUTE` | Medium | Yes |
| `DELETE` | High | Yes, if granted |
| `DELEGATE` | High | Yes, if granted |
| `NETWORK_EGRESS` | High | Yes, if granted |
| `NETWORK_INGRESS` | High | Yes, if granted |
| `FILE_SYSTEM` | High | Yes, if granted |
| `PROCESS_SPAWN` | High | Yes, if granted |
| `MEMORY_WRITE` | High | Yes, if granted |
| `CREDENTIAL_READ` | Critical | Yes, if granted |
| `CREDENTIAL_WRITE` | Critical | Yes, if granted |
| `AUDIT_READ` | Critical | Yes, if granted |
| `AUDIT_WRITE` | Critical | No — human authorization required |
| `POLICY_READ` | Critical | Yes, if granted |
| `REGISTRY_MODIFY` | Catastrophic | No — human principal only |
| `POLICY_MODIFY` | Catastrophic | No — human principal only |

### Risk enforcement

`CapabilityRisk::Catastrophic` capabilities cannot appear in a `RightsClaim` where the grantor is a machine actor. The registry enforces this at `add_claim()` time. A machine attempting to grant `REGISTRY_MODIFY` or `POLICY_MODIFY` raises `EscalationError` regardless of what claims the machine holds.

### Attenuation algebra

For a delegation `Alice → Bot`:

```
granted_rights(Bot) ⊆ held_rights(Alice)
```

This is enforced structurally. The registry computes the intersection at delegation time and rejects any claimed right not present in the parent's grant. The `DELEGATE` right itself must be explicitly held to sub-delegate.

---

## 5. Revocation System

### Revocation modes

| Mode | Trigger | Scope | Latency |
|---|---|---|---|
| Eager | `registry.revoke(claim_id)` | Single claim | Immediate |
| Resource-scoped | `registry.revoke_on_resource(resource_id)` | All claims on resource | Immediate |
| Cascading | `registry.revoke_cascading(actor_id)` | Actor + all transitive delegates | BFS, O(reachable agents) |
| Expiry | `registry.expire_stale()` | All claims past `expires_at` | Called on verify or by background sweep |

### Cascading revocation

When a machine is revoked, all machines that received authority from it (directly or transitively) must also have their derived claims invalidated. This is a BFS over the delegation subgraph rooted at the revoked actor.

```
revoke_cascading(Bot_A):
  queue = [Bot_A]
  while queue not empty:
    current = queue.pop()
    revoke all claims where grantor == current
    queue.extend(all actors who received claims from current)
```

Worst-case: O(V + E) over the delegation subgraph. Benchmark target: < 1ms for 100-agent subgraph.

### Revocation and the TCB

`engine.rs` does not perform revocation. It receives a registry snapshot at call time. The snapshot excludes revoked and expired claims — this exclusion happens in `registry.rs` before the snapshot is passed to `verify()`. The TCB trusts the snapshot it is given; correctness of the snapshot is the responsibility of `registry.rs`.

---

## 6. Trust Domains (v2)

Trust domains are isolation namespaces. An agent in domain `D1` cannot act on resources owned by agents in domain `D2` without an explicit `CrossDomainGrant`.

### Wire format

```json
{
  "trust_domain": "research-sandbox",
  "delegation_depth": 3
}
```

Both `trust_domain` and `delegation_depth` are new fields in v2. They use `#[serde(default)]` — v1 wire messages deserialize with `trust_domain = "default"` and `delegation_depth = 0`.

### CrossDomainGrant

```
CrossDomainGrant {
  from_domain: TrustDomainId,
  to_domain:   TrustDomainId,
  capability:  CapabilityKind,
  resource:    ResourceId,
  granted_by:  ActorId,   // must be human principal
  expires_at:  Option<Timestamp>,
}
```

Cross-domain grants require the human principal of the target domain to countersign. No machine can unilaterally grant cross-domain access.

### Domain isolation enforcement

The `AuthorityGraphEngine` checks cross-domain violations at graph analysis time. `engine.rs` checks domain membership during claim verification — a claim is invalid if the claiming actor's domain does not match the resource's domain and no `CrossDomainGrant` exists.

---

## 7. Wire Protocol

All data crossing the TCB boundary is serialized via `wire.rs`. The wire format is JSON (serde_json internally; msgpack planned for performance-sensitive paths).

### ActionWire (v2)

```json
{
  "id": "action-uuid",
  "actor": "agent-id",
  "capability_kind": "WRITE",
  "resources_read": [],
  "resources_write": ["resource-id"],
  "resources_execute": [],
  "flags": {
    "increases_machine_sovereignty": false,
    "resists_human_correction": false,
    "bypasses_verifier": false,
    "weakens_verifier": false,
    "disables_corrigibility": false,
    "machine_coalition_dominion": false,
    "coerces": false,
    "deceives": false,
    "self_modification_weakens_verifier": false,
    "machine_coalition_reduces_freedom": false
  },
  "trust_domain": "default",
  "delegation_depth": 0
}
```

### ClaimWire (v2)

```json
{
  "actor": "agent-id",
  "resource": "resource-id",
  "can_read": true,
  "can_write": false,
  "can_execute": false,
  "can_delegate": false,
  "expires_at": null,
  "trust_domain": "default",
  "delegation_depth": 1
}
```

### Backward compatibility contract

v2 adds `trust_domain` and `delegation_depth` to both `ClaimWire` and `ActionWire`. Both fields use `#[serde(default)]`. A v1 message missing these fields deserializes as `trust_domain = "default"`, `delegation_depth = 0`. This is the "global default domain, root delegation depth" interpretation — semantically correct for v1 deployments.

Existing v1 code using exhaustive matches on `CapabilityKind` must add arms for the 9 new variants added in v2 (compile-time error, not silent breakage).

---

## 8. Extension Architecture

Extensions wrap the kernel. The kernel gate runs first, unconditionally. Extensions cannot modify the kernel's decision — they can only add signals, metadata, or secondary checks.

```
Action
  │
  ▼
engine.rs::verify()      ← TCB gate (always runs first)
  │
  ├── BLOCKED → halt (extensions do not run on BLOCKED)
  │
  └── PERMITTED
        │
        ▼
  [optional] ExtensionChain::run(action, permitted_result)
        ├── NonInterferenceChecker (IFC labels)
        ├── ManipulationDetector  (heuristic score)
        ├── PolicyVerifier        (ABAC rules)
        └── ConflictQueue         (contested resource tracking)
        │
        ▼
  EnrichedResult { base: VerificationResult, extensions: HashMap<String, Value> }
```

### Extension contract

An extension:
1. Receives a `PERMITTED` result from `engine.rs`.
2. May add metadata fields to the result.
3. May escalate to BLOCKED (but cannot de-escalate from BLOCKED to PERMITTED).
4. Must not modify the kernel's `signature` field.
5. Must be registered in the extension chain before the verifier is constructed.

Extensions that escalate to BLOCKED append a `ViolationRecord` with `source: "extension:<name>"` to distinguish extension-sourced blocks from TCB-sourced blocks. Callers can inspect this field to understand which layer blocked an action.

---

## 9. Multi-Agent Architecture

### Spawn model

Spawning a sub-agent is itself a verified action requiring `PROCESS_SPAWN` capability. The spawning agent must hold `PROCESS_SPAWN` on the target execution context.

```
AgentSpawnRequest {
  parent_actor:      ActorId,
  child_actor:       ActorId,         // pre-registered or registering now
  authority_ceiling: Vec<RightsClaim>, // child authority ⊆ parent authority
  trust_domain:      TrustDomainId,
  max_depth:         u8,              // capped at 16
}
```

`engine.rs` verifies spawn requests using the same `verify()` path. The `authority_ceiling` is checked against the parent's current claims — the child cannot receive rights the parent does not hold.

### Depth cap enforcement

Every agent carries its `delegation_depth` in `ActionWire`. The depth is incremented at each spawn. At depth 16, further spawning is blocked with `MaxDelegationDepthError`. This is checked in `engine.rs` as part of guard [4].

### Authority budget

Each spawned agent inherits a subset of the parent's claims. Claims do not "refill" — an agent can only sub-delegate what it currently holds. The ownership graph enforces this: after delegation, the parent's `can_delegate` right is consumed for that specific sub-delegation (it cannot be re-delegated to a different child without the parent re-acquiring `can_delegate` on that resource from its own parent).

---

## 10. Audit Architecture

### Append-only log

Every `verify()` call produces a `VerificationResult` that is appended to the audit log. The log is append-only — no entry can be modified or deleted. This is enforced by the log writer, not by the TCB.

```
AuditEntry {
  id:         Uuid,
  timestamp:  UnixTimestampMs,
  nonce:      [u8; 16],
  action_id:  String,
  actor:      ActorId,
  permitted:  bool,
  violations: Vec<ViolationRecord>,
  signature:  ed25519::Signature,
  signing_key: ed25519::VerifyingKey,
}
```

### Cryptographic attestation

Every result is signed with the kernel's ed25519 key pair. The signing key is generated at kernel initialization and held in memory — it is not persisted by default (production deployments should use a KMS-backed key).

Attestation properties:
- **Non-repudiation:** A signed PERMITTED result proves the kernel authorized the action at the given timestamp.
- **Replay detection:** Each result includes a random 16-byte nonce. The same action with a different nonce produces a different signature.
- **Chain verification:** A sequence of audit entries can be verified as a consistent chain by checking that each entry's `action_id` appears in the `AuditLog` in timestamp order.

### What the audit log does NOT provide

- Causal ordering in distributed deployments (requires external vector clock or consensus)
- Cross-kernel revocation notification (a PERMITTED from kernel A does not know about a revocation on kernel B)
- Content inspection (the audit log records what was authorized, not what was produced)

---

## Invariant summary

| Invariant | Source | Enforcement point |
|---|---|---|
| A4: every machine has a human owner | `engine.rs` guard [2] | TCB |
| A5: machine scope ⊆ owner scope | `registry.rs` at `add_claim()` | Not TCB |
| A6: no machine governs humans | `engine.rs` guard [3] | TCB |
| A7: machine acts only on delegated resources | `engine.rs` guard [4] | TCB |
| Attenuation: child ⊆ parent | `registry.rs` at `delegate()` | Not TCB |
| No cycles in delegation graph | `authority_graph.rs` at `delegate()` | Not TCB |
| Depth ≤ 16 | `engine.rs` guard [4] | TCB |
| Catastrophic capabilities: human-only | `registry.rs` at `add_claim()` | Not TCB |
| Sovereignty flags: unconditional block | `engine.rs` guard [1] | TCB |

Invariants enforced outside the TCB depend on `registry.rs` and `authority_graph.rs` being correct. These components are tested but not formally verified. See [`formal/INCOMPLETENESS.md`](formal/INCOMPLETENESS.md).
