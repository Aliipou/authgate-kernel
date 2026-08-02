# ind/protocol-domain-separation — PR notes

**Branch:** `protocol/domain-separation` · **Base:** `assumptions-table` (`ebf4b99`)

> ## ✅ VERIFIED — `213 passed; 0 failed`
> Built and tested with the **GNU** toolchain:
> `cargo +stable-x86_64-pc-windows-gnu test`.
>
> The MSVC toolchain was the default but was never installed on this machine (no
> `link.exe`, no `cl.exe`, no VS Installer — `winget` reported the Build Tools
> package as "already installed", which was a false match against a VC++
> *redistributable*). `stable-x86_64-pc-windows-gnu` plus TDM-GCC was already
> present and builds the crate cleanly. `ASSUMPTIONS.md` had recorded
> `cargo build` working "(gnu toolchain)" all along.
>
> **The GNU toolchain is the supported build path on this machine.** CI must pin
> it explicitly, or a fresh clone will pick the broken MSVC default.

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

`cargo +stable-x86_64-pc-windows-gnu test` → **213 passed; 0 failed.**

Before the test fixes: 206 passed, 2 failed. **Both failures were this change,
and both were exactly the predicted size delta** — the two tests that hardcode a
serialised byte length:

| Test | Was | Now | Delta |
|---|---|---|---|
| `types_cap_canonical_bytes_length_is_fixed` | 216 | 244 | +28 |
| `types_revocation_canonical_bytes_length_is_fixed` | 104 | 132 | +28 |

+28 is exactly `1 + 25 + 1 + 1` — length byte, a 25-character context string,
algorithm, version. Both tests now **derive** the expected length from
`domain_preamble(...)` instead of hardcoding it, so changing a context string
cannot silently invalidate the arithmetic.

Every signature-verification test passed untouched, because they compute through
`signing_message()` rather than asserting literal bytes. That is the evidence
that the change is format-wide and not partial: had any signing path been missed,
its verification test would have failed.

Five new tests assert the security property directly:

- `domain_every_context_is_distinct`
- `domain_no_context_is_a_prefix_of_another` — preambles pairwise differ
- `domain_revocation_message_can_never_equal_a_chain_link_message` — and neither
  is a prefix of the other, so no truncation or extension yields the other
- `domain_preamble_is_actually_present_in_signed_bytes`
- `domain_preamble_binds_algorithm_and_version` — asserts the byte layout

Not yet run: `cargo clippy -D warnings`.

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
