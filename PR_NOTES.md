# ind/protocol-domain-separation — PR notes

**Branch:** `protocol/domain-separation` · **Base:** `assumptions-table` (`ebf4b99`)

> ## ⚠️ THIS BRANCH IS UNVERIFIED. DO NOT MERGE AS-IS.
> Rust does not compile in the environment this was written in: `cargo` fails at
> link time because the MSVC linker is absent (*"please ensure that Visual Studio
> ... Build Tools were installed with the Visual C++ option"*). **Nothing here
> has been compiled, and no test has been run against it.** The acceptance
> criterion "tests green" is NOT met and could not be attempted. Treat this as a
> reviewed design with a candidate implementation attached.

## What

Binds a domain-separation preamble under every signature and every canonical
hash in the protocol:

```
preamble = len(ctx) ‖ ctx ‖ alg_id ‖ schema_version
```

| Surface | File:line (pre-change) | Context |
|---|---|---|
| Chain link signature | `tcb/types.rs:63` | `authgate/v2/chain-link` |
| Capability canonical bytes / `proof_hash` preimage | `tcb/types.rs:82` | `authgate/v2/cap-canonical` |
| Revocation notice signature | `tcb/types.rs:120` | `authgate/v2/revocation` |
| Revocation canonical bytes | `tcb/types.rs:112` | `authgate/v2/rev-canonical` |
| Action binding hash | `tcb/types.rs:163` | `authgate/v2/action-binding` |
| Signed verification result / audit entry | `crypto.rs:47` | `authgate/v2/audit-entry` |

`ALG_ED25519 = 0x01`, `SCHEMA_VERSION = 0x02`. The context is length-prefixed so
that one context string being a prefix of another cannot reintroduce ambiguity.

## Why

`signing_message()` carried no version, no algorithm identifier and no domain
tag, while its own doc comment claimed *"Field order is fixed — any change is a
protocol version bump."* The version was not in the signed bytes, so that was
not true: old signatures stayed valid under a new field order.

Cross-type confusion was prevented **only by accident of field sizes** — a
revocation signing message is exactly 40 bytes and a chain-link message is at
least 121, and both are signed by the same root key. That is not an enforced
property; any future field change could have made a signature over one valid as
a signature over the other. This makes it structural.

Binding the algorithm is what makes post-quantum migration possible without the
JWT `alg`-confusion failure mode: a verifier accepting two schemes must be able
to tell which scheme produced a signature, and that is only sound if the
algorithm is inside the signed bytes.

## Risk

**This is a breaking wire-format change, deliberately.** Every capability,
revocation and signed result produced before this commit fails verification
after it. That is the intended behaviour (old-format signatures must not
verify), but it means:

- Any deployed capability must be reissued. There is no compatibility window.
- Rust and any other implementation must change in lockstep or they will
  disagree on every signature.

## Test evidence

**None.** See the warning above. What a reviewer must run on a machine with
MSVC Build Tools installed:

1. `cargo test` — expect failures anywhere a test hardcodes an expected hash or
   signature byte string; those are the change, not a regression. Tests that
   compute via `signing_message()`/`to_canonical_bytes()` should pass unchanged.
2. `cargo clippy -D warnings`.
3. The cross-type confusion test named in the task spec is **not yet written**
   (see Not done, below).

## Not done — remaining scope, and why

1. **Distinct error for old-format proofs.** The spec asks that old-format
   signatures deny *with a distinct error*. That is not achievable with the
   preamble alone: a pre-v2 signature is simply a signature over different
   bytes, so it fails identically to a forgery, and the verifier cannot tell
   them apart. Distinguishing them requires an **unsigned wire version field**
   read before verification (for the diagnostic) in addition to the signed
   version (which prevents downgrade). That means adding a field to
   `CapabilityProof`, which touches every struct-literal construction site in
   `call_gate.rs`, `dag.rs`, `engine.rs`, `tests.rs` and `hardening_tests.rs`.
   Deliberately not attempted blind on a machine that cannot compile.
2. **Kani cross-type confusion harness.** Not written. Kani is also not
   installed (0 of 32 existing harnesses have ever run), so it could not be
   executed either.
3. **Python mirror — the premise does not hold.** There is no Python mirror of
   the v2 TCB proof chain: `grep` for `binding_hash|capability_proofs|
   target_proof_hash` across `src/**/*.py` returns nothing. Python's signing
   surfaces are `kernel/audit.py`, `key_rotation.py` and `distributed/*`, which
   are separate v1-era formats. Each needs its own domain separation as its own
   piece of work; this branch does not touch them. **Confirm this before
   assuming the two implementations agree** — today they are not signing the
   same thing at all.
4. **Wire-format docs and CHANGELOG.** Not updated, pending the decisions above.

## Sequencing note

This must land **before** the Tamarin work (Session 8). Tamarin would otherwise
model the pre-v2 message format and verify a protocol that is about to be
replaced — and key-reuse questions, which are the reason for the Tamarin model,
are exactly the questions domain separation changes.
