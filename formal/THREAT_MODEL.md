# Threat Model — authgate-kernel v3

**Branch:** spec-core  
**Status:** Working draft — maps to authgate_v3.tla invariants

---

## 1. Security Target

authgate-kernel is a **stateless capability verification kernel** (TCB) for autonomous agent runtimes. Its single security claim is:

> *A `Decision::Permit` is returned if and only if all of the following hold: the action IR is unmodified (canonical gate), at least one cryptographically valid capability proof grants the required rights to the requesting actor for the requested resource in the current epoch, and no valid revocation covers that proof.*

Everything else (semantic correctness of the LLM's intent, correctness of the adapter, side-channel resistance) is explicitly outside the TCB.

---

## 2. Trust Boundary (hard lines)

```
┌───────────────────────────────────────────────────────┐
│                     INSIDE TCB                        │
│                                                       │
│  engine::verify()          dag::validate_chain()      │
│  types::CanonicalAction    types::CapabilityProof     │
│  types::compute_hash()     types::verify_binding()    │
│  sequence::SequenceContext  (composition tracking)    │
│                                                       │
│  Trusted assumptions:                                 │
│    • ed25519_dalek signature verification             │
│    • sha2 SHA-256 collision resistance                │
│    • subtle constant-time comparison                  │
└───────────────────────────────────────────────────────┘
         ↑ untrusted input boundary
┌───────────────────────────────────────────────────────┐
│                  OUTSIDE TCB (untrusted)              │
│                                                       │
│  Adapter layer (Python, LangChain, LangGraph, MCP)    │
│  LLM inference output                                 │
│  CanonicalAction construction (by adapter)            │
│  Root key custody and rotation                        │
│  Clock source (caller provides `now`)                 │
│  Session policy (caller sets min_epoch, session limit)│
└───────────────────────────────────────────────────────┘
```

**Non-TCB components must not be treated as trusted by callers.** The Python mirror is a test oracle, not a co-equal TCB component.

---

## 3. Threat Actor Model

| Actor | Capability | Goal |
|---|---|---|
| **Malicious adapter** | Can forge `CanonicalAction` fields before sealing | Escalate rights, reuse expired/revoked caps |
| **Compromised delegator** | Holds a private key for an expired/revoked epoch | Create new chains using stale authority |
| **Impersonating delegator** | Knows a parent proof but not the parent subject's key | Forge a child proof (AT-5.1) |
| **Replay attacker** | Captures a valid `CanonicalAction` from a prior session | Re-submit for a second Permit |
| **Composition attacker** | Submits individually-valid actions in sequence | Achieve globally-harmful capability accumulation |
| **Shadow executor** | Bypasses `verify()` entirely at the adapter boundary | AT-7.5 — requires architectural enforcement |
| **Semantic attacker** | Constructs valid IR that requests harmful operations | L1 — outside TCB scope |

---

## 4. Attack Surface Enumeration (MITRE-style)

### AT-1: IR Mismatch / Canonicalization
| ID | Attack | Mitigation | Status |
|---|---|---|---|
| AT-1.1 | Modify actor_id after sealing | binding_hash (SHA-256 over all fields) | ✅ closed |
| AT-1.2 | Modify resource_hash after sealing | binding_hash | ✅ closed |
| AT-1.3 | Modify nonce after sealing | binding_hash | ✅ closed |
| AT-1.4 | Modify timestamp after sealing | binding_hash | ✅ closed |
| AT-1.5 | Lower min_epoch after sealing | binding_hash | ✅ closed |
| AT-1.6 | Inject extra cap after sealing | length-prefixed list in binding_hash | ✅ closed |
| AT-1.7 | Remove cap after sealing | length-prefixed list in binding_hash | ✅ closed |

### AT-2: Proof Chain Manipulation
| ID | Attack | Mitigation | Status |
|---|---|---|---|
| AT-2.1 | Use another actor's cap | subject_id == actor_id filter | ✅ closed |
| AT-2.2 | Cross-resource cap reuse | cap.resource_hash == action.resource_hash | ✅ closed |
| AT-2.3 | Forge root signature | ed25519 verification | ✅ closed (crypto assumed) |
| AT-2.4 | Corrupt intermediate signature | ed25519 verify on every chain node | ✅ closed |
| AT-2.5 | Splice chain with missing parent | parent must be in bundle | ✅ closed |
| AT-2.6 | Rights escalation via delegation | attenuation: child.rights ⊆ parent.rights | ✅ closed |
| AT-2.7 | Depth overflow / infinite chain | MAX_CHAIN_DEPTH = 16 | ✅ closed |

### AT-3: Epoch / Revocation
| ID | Attack | Mitigation | Status |
|---|---|---|---|
| AT-3.1 | Stale intermediate delegation node | chain-wide epoch check in validate_chain | ✅ closed (this session) |
| AT-3.2 | Mixed-epoch bundle (one fresh, one stale) | each cap checked independently | ✅ closed |
| AT-3.3 | Revocation forgery | only root-signed revocations accepted | ✅ closed |
| AT-3.4 | Revocation of unrelated proof | proof_hash matching | ✅ closed |
| AT-3.5 | Replay across sessions | nonce committed in binding_hash | ✅ closed |

### AT-4: Composition / Sequence
| ID | Attack | Mitigation | Status |
|---|---|---|---|
| AT-4.1 | Stepwise privilege creep | SequenceContext.exceeds_limit() | ✅ closed |
| AT-4.2 | Read → execute → write exfiltration | accumulated_rights gate | ✅ closed |
| AT-4.3 | Multi-actor session accumulation | SequenceContext tracks all actors | ✅ closed (documented) |
| AT-4.4 | Rights fragmentation (split READ/WRITE across calls) | session accumulation | ✅ closed |
| AT-4.5 | Session policy bypass | caller must enforce session limit | open (policy layer) |
| AT-4.6 | Forgetting accumulated rights | monotone accumulation | ✅ closed |

### AT-5: Identity Binding
| ID | Attack | Mitigation | Status |
|---|---|---|---|
| AT-5.1 | Delegation impersonation (forge child without parent key) | SHA-256(issuer_pubkey) == parent.subject_id | ✅ closed (this session) |
| AT-5.2 | All-zeros actor identity confusion | distinct comparison | ✅ closed |
| AT-5.3 | Public key substitution in chain node | issuer_pubkey committed in signing_message | ✅ closed |

### AT-6: Crypto Boundary
| ID | Attack | Mitigation | Status |
|---|---|---|---|
| AT-6.1 | Nonce all-zeros (no special-casing) | nonce is committed, any value valid | ✅ closed |
| AT-6.2 | Cross-context proof reuse | resource_hash binding | ✅ closed |
| AT-6.3 | Timing oracle on binding_hash check | subtle::ConstantTimeEq | ✅ closed |
| AT-6.4 | Malformed signature bytes | Signature::from_bytes() error handling | ✅ closed |
| AT-6.5 | Nonce reuse (replay) | each action needs fresh nonce; kernel can't enforce uniqueness | open (caller) |

### AT-7: Integration / Adapter Boundary
| ID | Attack | Mitigation | Status |
|---|---|---|---|
| AT-7.1 | Post-seal action mutation | binding_hash | ✅ closed |
| AT-7.2 | Adapter bypasses verify() (shadow execution) | **AT-7.5** — architectural gap | ⚠️ open |
| AT-7.3 | Python mirror used as TCB | Python is test oracle only; not in trust boundary | documented |
| AT-7.4 | LLM generates malicious IR | semantic enforcement layer | out of scope (L1) |

---

## 5. Out-of-Scope (explicitly excluded from TCB claims)

- **AT-7.5 Shadow execution**: An adapter that skips `verify()` entirely bypasses the kernel. Fix requires a mandatory interception point at the adapter/kernel boundary (v3 architecture). The kernel itself cannot detect this.
- **L1 Semantic misalignment**: A valid IR requesting harmful operations (e.g., `required_rights = RIGHT_WRITE` on a sensitive resource). The kernel cannot evaluate semantic intent — only structural authority.
- **Side-channel attacks**: Timing, power, cache, EM — not addressed.
- **Root key compromise**: The kernel's security reduces to the root key. Key custody is out of scope.
- **Clock manipulation**: The kernel trusts `now` as passed by the caller.
- **Distributed consensus**: Epoch advancement in multi-node deployments requires consensus not modeled here.

---

## 6. Invariant-to-TLA+ Mapping

| Invariant | TLA+ name | Rust enforcement |
|---|---|---|
| I1 EpochSafety | `EpochSafety` | `engine.rs`: `cap.epoch < action.min_epoch` |
| I2 IdentityBinding | `IdentityBinding` | `dag.rs`: `SHA-256(issuer_pubkey) == parent.subject_id` |
| I3 Attenuation | `Attenuation` | `dag.rs`: `(child.rights & !parent.rights) != 0` |
| I4 RevocationSafety | `RevocationSafety` | `engine.rs`: layer 3 revocation check |
| I5 CompositionMono | `CompositionMono` | `sequence.rs`: `accumulated |= rights_used` |
| I6 ResourceBinding | `ResourceBinding` | `engine.rs`: `cap.resource_hash != action.resource_hash` |
| I7 ChainEpoch | `ChainEpoch` | `dag.rs`: `current.epoch < min_epoch` in chain walk |
| I8 ChainComplete | (inside ValidChain) | `dag.rs`: `parent proof not found in bundle` |

---

## 7. Formal Closure Conditions

The following conditions, if proven in TLA+ (TLC model-check + TLAPS), would formally close the core attack surface:

1. `THEOREM Spec => []EpochSafety` — no stale proof produces Permit
2. `THEOREM Spec => []IdentityBinding` — impersonation impossible
3. `THEOREM Spec => []Attenuation` — escalation impossible  
4. `THEOREM Spec => []RevocationSafety` — revoked proofs never Permit
5. `THEOREM Spec => []ResourceBinding` — cross-resource reuse impossible

These are stated in `authgate_v3.tla`. TLC model-checking on a small instance (|Actors|=3, |Resources|=2, MaxChainDepth=3, MaxEpoch=5) is the next step.
