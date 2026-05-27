# Cross-Runtime Attestation — Design

**Phase:** 4 (6–12 months)
**Status:** Design stub — not yet implemented.

---

## Problem

A PERMITTED result signed by Kernel Instance A cannot currently be verified by
Kernel Instance B, because B does not know A's public key and there is no
cross-instance revocation protocol.

---

## Requirements

1. Instance B can verify that a result was produced by a known, authorized kernel instance.
2. A result that was PERMITTED at T0 can be invalidated by a revocation at T1 > T0.
3. The attestation chain is auditable end-to-end across instances.

---

## Proposed Protocol

```
Kernel A:
  result = verify(action)
  attestation = {
    kernel_id: A.id,
    result_hash: sha256(canonical(result)),
    timestamp: T,
    nonce: random_16_bytes,
    signature: ed25519_sign(A.privkey, payload),
  }

Kernel B (verifying A's attestation):
  1. Fetch A.pubkey from the trust root registry (or PKI)
  2. Verify ed25519_verify(A.pubkey, attestation.signature, payload)
  3. Check attestation.timestamp within acceptance window
  4. Check nonce not in seen-nonce cache
  5. Check no revocation event for result_hash since T
```

---

## Trust Root for Public Keys

Options:
- Centralized PKI (simple, single point of failure)
- Distributed key registry (more resilient, higher complexity)
- Web-of-trust among registered kernel instances

---

## Open Questions

- How are kernel instances registered in the trust root?
- How does the revocation event propagate across instances?
- What is the maximum attestation acceptance window?
