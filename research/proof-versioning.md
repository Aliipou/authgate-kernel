# Proof Versioning — II-3 from INFRASTRUCTURE_PLAN.md

**Threat addressed:** A7 from future-threats.md — capability semantics change silently.

**Problem:**  
A `CapabilityProof` signed under v1.0 semantics (where `RIGHT_EXECUTE` means "run a WASM module") 
could be replayed under v2.0 semantics (where `RIGHT_EXECUTE` means "run a subprocess with full
OS access"). The proof is cryptographically valid. The semantic meaning has changed. The
attacker gets more power than was originally granted.

**Solution:**  
Every capability proof includes a `schema_version` field. Version upgrades that change the
meaning of any right require proof reissuance. Old proofs with old schema versions must be
explicitly accepted or rejected by policy.

---

## Schema version format

```
MAJOR.MINOR.PATCH

MAJOR: breaking semantic change — old proofs incompatible
MINOR: additive change — new right kinds, new metadata fields
PATCH: documentation/tooling only — no semantic change
```

## Current version: 1.0.0

Rights semantics defined in `SEMANTICS.md`. The meaning of each right at v1.0.0:

| Right | v1.0.0 Meaning | Notes |
|-------|---------------|-------|
| `RIGHT_READ` | Read a named resource (file, dataset, etc.) | |
| `RIGHT_WRITE` | Write/mutate a named resource | |
| `RIGHT_DELEGATE` | Delegate owned rights to another agent | |
| `RIGHT_EXECUTE` | Execute a WASM module | Specifically WASM, not subprocess |
| `RIGHT_SPAWN` | Spawn a child agent (with attenuation) | |
| `RIGHT_NETWORK` | Make outbound network connections | |
| `RIGHT_MODEL_INVOKE` | Call an AI model API | |
| `RIGHT_POLICY_MODIFY` | Modify kernel policy (catastrophic right) | Requires explicit human |

## What would trigger a MAJOR version bump

- `RIGHT_EXECUTE` expanded to include subprocess execution (not just WASM)
- `RIGHT_NETWORK` expanded to include server sockets (not just client connections)
- `RIGHT_SPAWN` semantics changed from attenuated to unattenuated
- Any existing right REMOVED from the bitmask (changes all existing proofs)

## Implementation in Python layer

The `VerificationResult` and audit entries include `schema_version: "1.0.0"`.
When the system is upgraded to v2.0.0:

```python
# Reject proofs with schema_version != current if policy requires
if proof.schema_version.major < CURRENT_MAJOR:
    return Decision(False, f"proof schema {proof.schema_version} is incompatible with v{CURRENT_MAJOR}")
```

## Implementation in Rust TCB

Add `schema_version: u32` to `CapabilityProof` (major version only in the wire format).
The `engine.rs` verify function includes a version check before processing proofs.

Currently `engine.rs` has no version field — this is the gap to close before v2.0.

## Migration protocol (when MAJOR bumps)

1. Announce deprecation of current MAJOR version
2. Run both versions in parallel for a grace period (overlap window)
3. Issue new proofs with new schema version
4. After grace period, reject proofs with old MAJOR version
5. Document in `CHANGELOG.md`

## Current gap

The Python layer does not yet check `schema_version` in capability proofs.
The Rust TCB does not yet include `schema_version` in `CapabilityProof`.

**Before v2.0.0, this must be implemented.** The semantics are stable enough
at v1.0.0 that this is not urgent — but any breaking semantic change without
proof versioning would be a silent security regression.

---

*Created: 2026-05-29. Activate before any MAJOR semantic change.*
