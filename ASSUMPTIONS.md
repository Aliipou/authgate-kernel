# ASSUMPTIONS — formal status of axioms A1–A7

**Generated 2026-08-01. Every cell was re-derived from the artifacts on that date.
Nothing in this table is inherited from another document in this repository.**

This is the single reference for what AuthGate has actually proved. Where it
disagrees with `AXIOMATIC_FOUNDATION.md`, `README.md`, `formal/COVERAGE.md`,
`formal/INCOMPLETENESS.md`, or `formal/TLC_SETUP.md`, **this document is correct
and those are stale** — §7 lists the specific conflicts.

---

## 0. The adjudication rule

> Every "proven" claim must cite a specific theorem with file and name. If
> coverage is partial, mark it "partial" and state exactly what is missing. When
> in doubt, round down. Never mark an axiom as proven based on a theorem that
> captures only a weakened version of its meaning.

Applied strictly. Three consequences worth stating up front, because they are
what the rule actually cost:

1. **A theorem of the form `theorem t (h : P) : P := h` is not evidence.** Two
   such theorems exist and were previously cited as proof of A6 (§3, A6).
2. **A theorem whose conclusion is `True` is not evidence.** Three such
   "theorems" and two such "axioms" exist (§6).
3. **A theorem about a 2-line model of a check is not a theorem about the
   check.** This is the most common pattern here and the easiest to miss,
   because such theorems are real, sorry-free, and genuinely proved — of
   something much smaller than the axiom they are filed under.

Status vocabulary, strongest to weakest:

| Status | Meaning |
|---|---|
| `PROVEN` | A named, mechanically-checked theorem, re-checked on 2026-08-01, whose statement covers the axiom's meaning |
| `PARTIAL` | A real proof exists but covers strictly less than the axiom says — the shortfall is named in the row |
| `ASSUMED` | An explicit, non-vacuous axiom, stated and referenced |
| `CHECKED-BOUNDED` | Exhaustively model-checked, but at a bound so small the result covers far less than the axiom — the bound is stated in the row |
| `STATED-ONLY` | A property is written down (TLA+ invariant, Kani harness) but has never been executed |
| `NONE` | No formal counterpart exists |
| `BROKEN` | An artifact exists and is cited as proof, but does not compile or depends on `sorryAx` |

**No axiom in this table is `PROVEN`.**

---

## 1. Reproduction — what was actually run

Unlike every prior status document here, this one is based on execution.

| Tool | Available 2026-08-01 | Ran it? | Result |
|---|---|---|---|
| Lean 4 | **Yes** — 4.32.2 and 4.31.0 via elan | **Yes** | **5 of 6 Lean files fail to compile.** Identical errors on both toolchains, so this is not version drift. §2 |
| `cargo build` | **Yes** (gnu toolchain) | **Yes** | `authgate-kernel` compiles clean, exit 0. Note: harness code is `#[cfg(kani)]` and was **not** compiled |
| Kani | **No** — not installed, `cargo kani` → `no such command` | No | 0 of 32 harness functions have ever been compiled or run |
| TLC | **Yes** — Java 17 on PATH; `tla2tools.jar` v1.8.0 fetched | **Yes** | **First TLC run in this project's history.** The committed spec does not parse; at a reduced bound it completes. §2A |

**The stated blocker for TLC was false.** `README.md:358` ("Java not installed"),
`formal/TLC_SETUP.md:174` ("pending Java setup") and
`REVIEW_PACKET/04:21` ("Java availability unverified") are all falsified — Java 17
is installed and on PATH. TLC has now been run (§2A). All runs were performed on
copies in a scratch directory; `git status --ignored formal/` is empty, so the
repository was not modified by the audit.

**No CI job runs Lean, Kani, or TLC.** A recursive grep over
`.github/workflows/` for `lean|lake|kani|tlc|tla2tools` returns zero matches.
Nothing in this repository's formal layer is gated on anything.

---

## 2A. TLA+ / TLC — first execution, and what it showed

Every result below was reproduced directly from pristine repo files, not taken
on report. Copies only; the repo was never written to.

### The committed spec does not parse

Running the exact command the docs give (`TLC_SETUP.md:53`, `README.md:358`):

```
Cannot find source file for module AuthGateV3 imported in module MC_AuthGateV3.
*** Errors: 1
```

`MC_AuthGateV3.tla:42` says `EXTENDS AuthGateV3`. TLA+ requires filename to match
module name. The module on line 1 of `formal/authgate_v3.tla` is `AuthGateV3`;
the **file** is `authgate_v3.tla`. They differ by more than case, so this fails
on every platform.

**This converts "TLC has never been run" from inference to proof.** Anyone who
had ever typed the documented command once, anywhere, would have hit this in
under a second. It also falsifies `formal/TLC_SETUP.md:176` ("complete and ready").

**One-line fix:** rename `formal/authgate_v3.tla` → `formal/AuthGateV3.tla`.
Not done here — it is a rename in a file this audit was not scoped to change.

### The committed bound is not checkable

At the shipped constraint `MCConstraint == Len(audit_log) <= 3`
(`MC_AuthGateV3.tla:277`): 26.5M states generated / 2.3M distinct after 10
minutes on 4 workers, **queue still growing**, throughput collapsing as the
fingerprint set went to disk. Reachable state count is on the order of 10⁹.
This falsifies `formal/TLC_SETUP.md:8` ("Estimated runtime: <5 minutes on a
4-core machine") and `MC_AuthGateV3.tla:11` ("feasible on a laptop in ~minutes").

### The first completed result this project has ever had

Reducing **only** the constraint to `Len(audit_log) <= 1`, nothing else changed,
against the repo's unmodified 10-invariant cfg:

```
Model checking completed. No error has been found.
77257 states generated, 4227 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 9.
Finished in 03s
```

All ten cfg-listed invariants hold exhaustively. **This is real and citable.** It
is also very small: an audit log of **at most one entry**, so no multi-decision
interaction — no revoke-then-use, no epoch-advance-then-replay — is reachable at
all. It is weaker than the bound the project itself chose to ship.

### Mutation testing: the suite is blind to A1 and to signature checking

A suite that constrains an axiom must fail when that axiom's enforcement is
deleted. Deleting the A1 canonical gate — `authgate_v3.tla:132`,
`IF ~action.binding_valid THEN "Deny"` → `IF FALSE THEN "Deny"` — and running
the repo's **unmodified** cfg:

```
Model checking completed. No error has been found.
77257 states generated, 4227 distinct states found, 0 states left on queue.
```

Identical to baseline. To rule out a no-op edit, A1 was then stated as a real
invariant and added to the cfg:

```
NoPermitOnTamperedBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" => audit_log[i].action.binding_valid
```

Baseline: passes. Mutant: **`Error: Invariant NoPermitOnTamperedBinding is
violated`**, with a concrete counterexample — a `Permit` on an action carrying
`binding_valid |-> FALSE`. The mutation is live and produces a genuinely unsafe
decision. **The repo's ten invariants cannot see it.** The same holds for
deleting `sig_valid` at both chain-walk sites.

### The full mutation matrix

Each enforcement check was deleted individually and the repo's **unmodified**
10-invariant cfg run against the mutant. "Reproduced" marks the rows executed
directly in this audit; the rest are reported and consistent with the two root
causes below, but were not individually re-run.

| Enforcement check deleted | Axiom | Repo's invariants | Reproduced here |
|---|---|---|---|
| `binding_valid` canonical gate | A1 | **NOT CAUGHT** | ✔ |
| root signature `current.sig_valid` | A5(a) | **NOT CAUGHT** | ✔ |
| intermediate signature | A5(a) | **NOT CAUGHT** | ✔ |
| **attenuation `rights ⊆ parent.rights`** | **A6** | **NOT CAUGHT** | ✔ |
| `c.expiry >= now` | A5(b) | **NOT CAUGHT** | — (structurally unstatable, see below) |
| leaf epoch `c.epoch >= min_epoch` | A5(c) | **NOT CAUGHT** | — |
| chain epoch | A5(c) | **NOT CAUGHT** | — |
| `HasParent` chain completeness | I8 | **NOT CAUGHT** | — |
| resource binding | A6/I6 | **NOT CAUGHT** | — |
| identity binding | A3 | CAUGHT (`IdentityBinding`) | — |
| rights coverage | A7 | CAUGHT (`PermitSoundness`) | — |
| revocation | I4 | CAUGHT (`RevocationSafety`) | — |
| actor match | A7 | CAUGHT (`EpochSafety`) | — |

**Two distinct root causes, needing different fixes:**

1. **Self-reference** (binding, both signatures, both epochs). `PermitSoundness`
   and `ChainEpoch` re-invoke the very `Verify`/`ValidChain` definitions that
   computed the decision, so weakening enforcement weakens the invariant in
   lockstep and nothing can fire. Fix: write independent invariants, like the
   two probes above.
2. **Missing test data** (attenuation, `HasParent`, resource binding, expiry).
   The invariant is fine; the model contains no input that could violate it.
   **All six model capabilities carry `rights |-> {"READ"}`** — identical — so
   no capability can escalate relative to its parent. Deleting the attenuation
   check changes nothing, and an independently-written attenuation probe also
   passes on the mutant. `MC_AuthGateV3.tla:31` documents
   `EscalationCap  delegated cap claiming WRITE but parent only has READ
   (triggers I3)` — **that capability is never defined.** Only the comment
   exists. Fix: write the adversarial capabilities the header already promises.

The second cause is the more dangerous of the two, because the invariant *looks*
correct and *is* in the cfg. `Attenuation` passing is not evidence about A6.

### Expiry is structurally unverifiable in this spec

All six model capabilities carry `expiry |-> 2` (`MC_AuthGateV3.tla:73,88,102,
116,131,145`) and `now` is drawn from `0..MCMaxEpoch` = `{0,1,2}`, so
`c.expiry >= now` is **universally true in every reachable state** — the model
contains no expired capability. Worse, `ExecuteVerify` records only
`[action, decision, revoked_at]` (`authgate_v3.tla:269-272`) and **never records
`now`**. No invariant over `audit_log` can constrain expiry, because the value it
would need was never written down. This is not "unchecked"; it is unstatable
without changing the spec.

---

## 2. Lean 4 — compile status, as committed

Method: `lean <file>` directly, then `#print axioms` on each theorem to detect
`sorryAx` introduced by error recovery.

| File | Compiles? | Blocking error |
|---|---|---|
| `formal/lean4/FreedomKernel/Ed25519.lean` | **YES** | — *(added by this change, §5)* |
| `formal/lean4/FreedomKernel/Incompleteness.lean` | YES | *(contains only comments and one axiom)* |
| `formal/FreedomKernel.lean` | NO | `:109` unknown constant `Float.max`; `:148` `simp` made no progress |
| `formal/lean4/FreedomKernel/TCB.lean` | NO | `:112` unknown constant `Bool.eq_false_iff_ne_true.mpr` |
| `formal/lean4/FreedomKernel/MultiAgent.lean` | NO | `:30,:42` cannot synthesize `Membership ?m Authority` — `Authority` is a `def`, not an `abbrev` |
| `formal/lean4/FreedomKernel/Temporal.lean` | NO | `:29` unknown tactic — uses Mathlib's `split_ifs`, but the file imports nothing and no lakefile provides Mathlib |
| `formal/lean4/FreedomKernel/Scope.lean` | NO | `:29` application type mismatch — `normalize path.dropRight 1` is missing parentheses |
| `formal/lean4/{Core,Invariants,Proofs}.lean` | **NO — unbuildable** | Import `Authgate.Core` / `Authgate.Invariants`; those module paths **do not exist** (files are flat at `formal/lean4/`, not `formal/lean4/Authgate/`). `Core.lean` imports Mathlib, which no lakefile requires |

Build infrastructure gaps: no `lean-toolchain`, no `lake-manifest.json`, no
Mathlib dependency declared anywhere, and the sole lakefile
(`formal/lean4/FreedomKernel/lakefile.lean`) has `roots := #[\`FreedomKernel\`]`,
which **excludes `Core.lean`, `Invariants.lean` and `Proofs.lean` entirely.**

### Per-theorem verdicts

To distinguish "the proof is wrong" from "the file has an unrelated typo", each
file was probed with the minimum repair needed to elaborate — the repair is named
so the result can be reproduced and challenged.

| Theorem | File:line | `#print axioms` | Verdict |
|---|---|---|---|
| `forbidden_flags_always_block` | `TCB.lean:81` | `[propext]` | **PROVED** — but about `verifyFlags`, a 2-line model |
| `sovereignty_flag_blocks` | `TCB.lean:87` | `[propext]` | PROVED (corollary) |
| `coercion_flag_blocks` | `TCB.lean:92` | `[propext]` | PROVED (corollary) |
| `deception_flag_blocks` | `TCB.lean:97` | `[propext]` | PROVED (corollary) |
| `verify_deterministic` | `TCB.lean:105` | none | **TRIVIAL** — `verifyFlags a = verifyFlags a := rfl`. True of every function |
| `permitted_implies_no_forbidden_flag` | `TCB.lean:109` | **`[sorryAx]`** | **BROKEN** |
| `ownerless_machine_must_have_owner` | `TCB.lean:124` | none | **VACUOUS** — `: True := trivial` |
| `machine_cannot_govern_human` | `TCB.lean:135` | none | **VACUOUS** — `: True := trivial` |
| `ownerless_machine_blocked` | `FreedomKernel.lean:162` | `[propext, Classical.choice]` | **PROVED** — strongest real result in the repo |
| `public_read_permitted` | `FreedomKernel.lean:184` | `[propext, Classical.choice, Quot.sound]` | PROVED |
| `sovereignty_always_blocks` | `FreedomKernel.lean:143` | **`[…sorryAx…]`** | **BROKEN** — cited for A2 |
| `permitted_decidable` | `FreedomKernel.lean:154` | `[propext, Classical.choice]` | **TRIVIAL** — `b = true ∨ b = false` |
| `attenuation_cannot_escalate` | `MultiAgent.lean:38` | none | **TAUTOLOGY** — body is `:= h`; assumes attenuation, concludes attenuation. Cited for A6 |
| `delegation_depth_bounded` | `MultiAgent.lean:50` | none | **TAUTOLOGY** — `(h : d ≤ MAX) : d ≤ MAX := h` |
| `taint_monotone` | `Temporal.lean:26` | — | **BROKEN** — does not elaborate |
| `no_downward_write` | `Temporal.lean:39` | — | **VACUOUS** — `: True := trivial` |
| `traversal_in_parent_always_false` | `Scope.lean:76` | `[propext, Classical.choice, Quot.sound]` | **PROVED** (T-SC3a) |
| `traversal_in_child_always_false` | `Scope.lean:80` | `[propext, Classical.choice, Quot.sound]` | **PROVED** (T-SC3b) |
| `scope_contains_root_universal` | `Scope.lean:63` | **`[sorryAx]`** | **BROKEN** (T-SC2) — *not* disclosed by the file |
| `prefix_implies_containment` | `Scope.lean:90` | **`[sorryAx]`** | **BROKEN** (T-SC4) — *not* disclosed by the file |
| `scope_contains_reflexive` | `Scope.lean:47` | `[sorryAx]` | broken (T-SC1) — file discloses this |
| `scope_contains_antisymmetric` | `Scope.lean:112` | `[sorryAx]` | broken (T-SC5) — file discloses this |
| `attenuation_transitive` | `Proofs.lean:18` | none | **PROVED** — transitivity of `⊆`, in an unbuildable file |
| `subject_mismatch_violates_binding` | `Proofs.lean:55` | none | PROVED, in an unbuildable file |
| `rights_sufficiency_correct` | `Proofs.lean:28` | **`[sorryAx]`** | **BROKEN** — passes 8 fields to the 7-field `CanonicalAction` |
| `epoch_gate_total` | `Proofs.lean:38` | **`[sorryAx]`** | **BROKEN** — proof term has the disjuncts in the wrong order |
| `stale_epoch_implies_deny` | `Proofs.lean:46` | **`[sorryAx]`** | **BROKEN** |
| `accepted_signature_has_an_honest_signer` | `Ed25519.lean` | `[ed25519_euf_cma]` | PROVED from the new explicit axiom (§5) |

**Also not proved:** `PermitImpliesAllInvariants` (`Invariants.lean:62`) — the
file's own "master safety theorem" — is a `def`, never a theorem, never proved.
`attenuationHolds` (`FreedomKernel.lean:173`) is likewise a `def`, never proved.
And `ValidSignature` (`Invariants.lean:48`) and `ValidRevocation`
(`Invariants.lean:56`) **do not typecheck at all** (`List Char` supplied where
`List Nat` is expected), so INV-SIGCHAIN and INV-REVOCATION are not even
well-formed statements.

Repairs used for probing (each is one line, semantics-preserving):
`Float.max` fold → `if`-expression; `Authority` `def` → `abbrev`;
`normalize` → a terminating equivalent; `Finset` → `List` with
`List.Subset.trans` for the Mathlib-dependent set.
The `Finset`→`List` substitution could in principle affect
`attenuation_transitive` and `rights_sufficiency_correct`; it cannot affect the
pure-`Nat` results or the `List Char`/`List Nat` type errors.

**Tally: 27 theorems. 9 genuinely proved, 4 trivial or tautological, 3 vacuous
(`: True`), 10 broken, 1 new.** The repo claims "16 Lean theorems"
(`AXIOMATIC_FOUNDATION.md:217`).

---

## 3. The table — A1 through A7

### A1 — Action Integrity (canonical binding)

> *Every action is sealed by a binding hash covering every field. Any post-seal
> mutation is detected before any other check runs.*

| | |
|---|---|
| **Status** | **`NONE`** |
| Lean translation | **None.** No Lean theorem in the repo mentions binding, hashing, or field coverage |
| TLA+ translation | `binding_valid : BOOLEAN` (`formal/authgate_v3.tla:80`), gate at `:132`. An **uninterpreted Boolean handed to the model as part of the action** — there is no hash function, no field enumeration, and no relation to the other fields |
| Checked by TLC? | **No — and now proven blind.** Not among the 10 invariants in `MC_AuthGateV3.cfg:24-34`. TLC has now been run (§2A): deleting the gate at `authgate_v3.tla:132` leaves all ten invariants passing with byte-identical state counts, while an audit-added probe invariant fails on the mutant with a concrete `binding_valid |-> FALSE` Permit |
| Kani | **None.** No harness targets binding |
| Proven | **Nothing.** `AXIOMATIC_FOUNDATION.md:51` lists Python attack simulations under a row labelled "Proof" |
| Assumed | — |
| No formal counterpart | The entire content of the axiom: that the hash *covers every field*, and that mutation is *detected* |

**Why this rounds to `NONE` rather than `PARTIAL`:** the TLA+ model is not merely
weak, it is **unfalsifiable — now demonstrated, not argued**. Deleting the gate
at `authgate_v3.tla:132` and running the repo's own cfg yields
`Model checking completed. No error has been found.` `PermitSoundness`
(`:336-347`) does not mention `binding_valid`, so a Permit on a tampered action
violates nothing.
`attack_harness/ATTACK_MATRIX.md:52` grades AT-1 coverage "**Full** … TLC
verifies this always produces Deny". Nothing asserts that, and TLC has not run.

**Implementation note (unproved, but real):** `authgate-kernel/src/tcb/engine.rs:35`
does perform `if !action.verify_binding()`. **The Python layer performs no
binding check whatsoever** — `AXIOMATIC_FOUNDATION.md:49` cites
`src/authgate/kernel/verifier.py:verify()` for this and is simply wrong; the
first check in that function is the sovereignty-flag block. Separately,
`binding_hash` is an **unkeyed** SHA-256 (`tcb/types.rs:163-186`), so it detects
accidental mutation and third-party tampering in transit, not an adversary who
assembles the action and recomputes the hash.

---

### A2 — Sovereignty / corrigibility flags are unconditional denials

> *If an action carries any of the 10 hard sovereignty flags, it is denied. No
> claim, no proof, no context overrides this.*

| | |
|---|---|
| **Status** | **`PARTIAL`** |
| Lean — proven | **`forbidden_flags_always_block`**, `formal/lean4/FreedomKernel/TCB.lean:81`, `#print axioms` → `[propext]`. Plus corollaries `sovereignty_flag_blocks` `:83`, `coercion_flag_blocks` `:88`, `deception_flag_blocks` `:93`. All 10 flags are in `hasForbiddenFlag` (`TCB.lean:54-64`) |
| Lean — broken | **`sovereignty_always_blocks`** (`formal/FreedomKernel.lean:143`) → **`sorryAx`**. This is the one cited by `AXIOMATIC_FOUNDATION.md:68` and the only one ranging over the fuller `permitted` gate. **`permitted_implies_no_forbidden_flag`** (`TCB.lean:109`) → **`sorryAx`** |
| TLA+ | `SovereigntyAlwaysBlocks`, `formal/freedom_kernel.tla:127`. **Orphan module** — no `.cfg`, no MC instance; `MC_AuthGateV3.tla:42` extends `AuthGateV3`, and `grep -i sovereign formal/authgate_v3.tla` returns **zero hits**. Also enumerates only **7** of the 10 flags, and is a **propositional tautology**: `Permitted` (`:116`) opens with `~SovereigntyFlags(a)`, so the invariant unfolds to `P ⇒ ¬(¬P ∧ …)` |
| Kani | 10 harnesses, `authgate-kernel/src/kani_proofs.rs:102-111`. **Never compiled, never run** |
| **What is proven** | If a forbidden flag is set, the model function `verifyFlags` returns `Blocked`. `verifyFlags` is `if hasForbiddenFlag a then .Blocked else .Permitted` (`TCB.lean:75-76`) |
| **What is missing** | (a) Any link from `verifyFlags` to the deployed verifier. The theorem is about a model of the check, and that model is nearly the check's own definition — it is close to `rfl`. (b) The word **"unconditional"**. The one theorem quantifying over the full gate is broken. (c) The 10 Kani harnesses are **fully concrete** — `base_action()` (`kani_proofs.rs:57-78`) pins every other field to a literal, contradicting `kani_proofs.rs:82-83` ("regardless of all other action fields") |
| No formal counterpart | Nothing formal connects the flag check to *any* running code |

**Layer warning:** `AXIOMATIC_FOUNDATION.md:66` concedes sovereignty flags are
"out-of-scope for Rust v2 TCB (Python only)". `:189` says the Python layer is not
formally checked. So the axiom the document calls *structural* is enforced only
in the layer the same document says is unverified.

---

### A3 — Cryptographic identity binding

> *An actor's identity is `SHA-256(public_key)`. Two principals with the same
> display name but different keys are distinct and cannot impersonate each other.*

| | |
|---|---|
| **Status** | **`CHECKED-BOUNDED`** — audit log ≤ 1 entry |
| Lean | **None.** No theorem concerns key-to-identity derivation. `subject_mismatch_violates_binding` (`Proofs.lean:55`) is about `subject ≠ actor`, a different property, in an unbuildable file |
| TLA+ | `IdentityBinding`, `formal/authgate_v3.tla:181-187`. **Is** in the cfg (`MC_AuthGateV3.cfg:27`) — the strongest TLA+ position of any axiom |
| Checked by TLC? | **Yes, at `Len(audit_log) <= 1`** (§2A) — `IdentityBinding` holds exhaustively over 4227 distinct states. Not checked at the committed bound of 3, which does not terminate |
| Kani | None |
| **What is proven** | **Nothing mechanically.** |
| **What is assumed** | Hash injectivity, as an explicit TLA+ `ASSUME`: `authgate_v3.tla:45` — `\A k1,k2 \in PublicKeys : Hash(k1) = Hash(k2) => k1 = k2`. `Hash` is uninterpreted, instantiated as a 4-entry lookup table (`MC_AuthGateV3.tla:56-61`). Preimage and collision resistance are assumed, not modelled |
| **What is missing** | (a) SHA-256 itself. (b) **Root capabilities are never identity-checked.** The binding applies only to `c.issuer.type = "Delegated"`. `RootKey` is declared (`authgate_v3.tla:36`) and assumed (`:43`) but appears in **no executable expression** — a cap with `issuer.type = "Root"`, `sig_valid = TRUE` and an arbitrary `issuer_pubkey` validates with no identity check at all. (c) The bounded model has 4 public keys and `MCHash`'s `OTHER` branch maps unknown keys to `"a0"` (`MC_AuthGateV3.tla:61`), which would violate the injectivity `ASSUME` if reached |

**Implementation note:** the Rust TCB does implement this correctly and
untruncated — `authgate-kernel/src/tcb/dag.rs:94`,
`Sha256::digest(current.issuer_pubkey).into()`, full 32 bytes. **The Python layer
does not**: identity is `name + kind + optional identity_token`, and
`identity_token` is a **bearer secret compared by equality** — anyone who
observes it can impersonate. Documented at `src/authgate/kernel/entities.py:105-110`.
`AXIOMATIC_FOUNDATION.md:84` cites `dag.rs:95`; the SHA-256 is on `:94` (off by one).

---

### A4 — No ownerless machine

> *Every machine actor must have a registered human owner. A machine with no
> owner cannot perform any action.*

| | |
|---|---|
| **Status** | **`PARTIAL`** — the best-supported axiom in the set |
| Lean — proven | **`ownerless_machine_blocked`**, `formal/FreedomKernel.lean:162-167`, `#print axioms` → `[propext, Classical.choice]`. Statement: `a.actor.kind = Machine → reg.hasOwner a.actor = false → permitted reg a = false` |
| Caveat on that proof | `formal/FreedomKernel.lean` **does not compile as committed** (`:109`, `Float.max`). The result above was obtained after replacing that one fold with an `if`-expression. The theorem's own proof is sound; the file it lives in is not currently buildable |
| Lean — vacuous | `ownerless_machine_must_have_owner`, `TCB.lean:124` — `: True := trivial`. Cited nowhere, worth nothing |
| TLA+ | `OwnerlessMachineBlocked`, `formal/freedom_kernel.tla:131`. Orphan module, no cfg, and **tautological** (restates `Permitted`'s own conjunct at `:118`). `grep -i "machine\|owner" formal/authgate_v3.tla` → **zero hits** |
| Kani | `prop_ownerless_machine_blocked`, `kani_proofs.rs:116`. Single concrete input, targets the **superseded v1 engine**, never run |
| **What is proven** | That the Lean model function `permitted` (`FreedomKernel.lean:129-139`) returns `false` for an unowned machine. Unlike A2's `verifyFlags`, `permitted` is a genuine composite gate — flags, ownership, dominion, read claims, write claims — so this result has real content |
| **What is missing** | Any refinement linking `permitted` to `src/authgate/kernel/verifier.py:172-180` or to the Rust TCB. The Lean model is hand-written alongside the implementation, not derived from it and not checked against it |
| No formal counterpart | The `AuthoritySource` / constitutional-trust-root extension named in the axiom's own text is not modelled anywhere |

---

### A5 — Capability proofs are signed and time-bounded

> *Valid only if (a) the signature verifies against the issuer's public key,
> (b) it has not expired, (c) its epoch ≥ the action's required minimum epoch.*

| | |
|---|---|
| **Status** | **`ASSUMED` for (a); `NONE` for (b); `STATED-ONLY` for (c)** |
| **(a) Signature — `ASSUMED`** | **`ed25519_euf_cma`**, `formal/lean4/FreedomKernel/Ed25519.lean` — added by this change (§5). Explicit, non-vacuous, compiles, and demonstrably load-bearing. On the TLA+ side there is **nothing**: replacing `current.sig_valid` with `TRUE` at both chain-walk sites leaves all ten invariants passing (§2A) |
| **(a) — superseded** | `sig_euf_cma`, `formal/lean4/Proofs.lean:66`. **VACUOUS** — its conclusion is `True`, which is provable without it. It assumes nothing and can support no theorem. `AXIOMATIC_FOUNDATION.md:119,203` and `REVIEW_PACKET/04:96` all cite it as the project's cryptographic assumption. It never was one |
| **(b) Expiry — `NONE`, and unstatable** | **No invariant anywhere**, and §2A shows one cannot be written without changing the spec: every model capability has `expiry |-> 2` while `now \in {0,1,2}`, so the guard is universally true, and `ExecuteVerify` never records `now` into the audit log at all. `grep -n expiry formal/authgate_v3.tla` yields the record field (`:66`), a comment (`:121`), and the gate (`:137`) — no named property. `PermitSoundness` (`:341-346`) **deliberately omits** the expiry conjunct that `Verify` has, so an expired-cap Permit violates nothing. No Lean theorem. `formal/COVERAGE.md:11` tracks "I3 ExpiryGate" — **that operator does not exist in any `.tla` file** |
| **(c) Epoch — `CHECKED-BOUNDED`** | `EpochSafety` (`authgate_v3.tla:173`) and `ChainEpoch` (`:233`), both in the cfg (`:26`, `:31`). **Both now hold exhaustively at `Len(audit_log) <= 1`** (§2A). Lean side is still broken: `stale_epoch_implies_deny` (`Proofs.lean:46`) → `sorryAx`; `epoch_gate_total` (`Proofs.lean:38`) → `sorryAx` |
| Kani | **`prop_epoch_check` does not exist.** Cited at `AXIOMATIC_FOUNDATION.md:122` as `(✓ proved)`. The nearest match, `proof_epoch_check` (`formal/kani/prop_chain.rs:67`), is in a directory that **belongs to no crate** — there is no `Cargo.toml` under `formal/` — so `cargo kani` cannot resolve it. Its body asserts `(a<b) != (a>=b)`, a fact about `u64`. `proof_forged_revocation_ignored` (`prop_revocation.rs:35`) is literally **`kani::assert(true, …)`** |
| **What is missing** | Expiry has no formal counterpart at all. The epoch invariants have never been executed. The signature half is an assumption, not a result — and see §5 for six things that assumption does **not** give you |

---

### A6 — Attenuation: child rights ⊆ parent rights, and no machine governs any human

| | |
|---|---|
| **Status** | **`PARTIAL` for clause 1 (`CHECKED-BOUNDED` in TLA+); `NONE` for clause 2** |
| Lean — proven | **`attenuation_transitive`**, `formal/lean4/Proofs.lean:18-23`, sorry-free. Statement: `Attenuated b a → Attenuated c b → Attenuated c a`. Real, but it is **transitivity of `⊆`** — it takes pairwise attenuation as a *hypothesis* and concludes the chain property. It does not prove that anything checks attenuation. It also lives in an unbuildable file (§2) |
| Lean — tautology | **`attenuation_cannot_escalate`**, `MultiAgent.lean:38`. Cited by `AXIOMATIC_FOUNDATION.md:139` as "(proved)". Its body is **`:= h`** — it assumes `authorityAttenuated child parent` and concludes `∀ cp ∈ child, ∃ pp ∈ parent, permissionSubset cp pp`, which is that hypothesis unfolded. It proves nothing. The file also does not typecheck as committed |
| Lean — broken | `rights_sufficiency_correct` (`Proofs.lean:28`) → `sorryAx`. `attenuationHolds` (`FreedomKernel.lean:173`) is a `def`, never proved |
| **Clause 2 — Lean** | **`machine_cannot_govern_human`**, `TCB.lean:135`, is **`: True := trivial`**. This is the entire Lean content for "a machine cannot govern any human" |
| **Clause 2 — TLA+** | **Nothing.** `grep -in "govern" formal/*.tla` returns zero hits in every TLA+ file |
| **Clause 2 — Kani** | `prop_machine_governs_human_blocked` (`kani_proofs.rs:130`) — one concrete input, v1 engine, never run |
| TLA+ (clause 1) | `Attenuation`, `authgate_v3.tla:190-196`, **is** in the cfg (`:28`) and passes at `Len(audit_log) <= 1` — **but the pass carries no information.** Every model capability has `rights \|-> {"READ"}`, so escalation is unrepresentable; deleting the attenuation check entirely is not caught, and neither is it caught by an independently-written probe (§2A). The model's own documented escalation test case, `EscalationCap` (`MC_AuthGateV3.tla:31`), was never defined |
| Kani (clause 1) | **`prop_attenuation_two_node` does not exist.** Cited at `AXIOMATIC_FOUNDATION.md:141` as "(✓ proved)". The nearest match, `proof_attenuation_two_node` (`formal/kani/prop_chain.rs:39`), is in the crate-less directory, and its own comment (`:44-46`) says *"we stub the chain validation and only verify the rights check logic"*. It imports `validate_chain` at `:18` and **never calls it**. Its body proves `x & ~y == 0 ⟹ x & y == x` — elementary Boolean algebra over two integers. **It does not prove attenuation for arbitrary chains, and it does not prove it for 2 nodes either** |
| **What is proven** | Set-subset transitivity, given pairwise attenuation as an assumption |
| **What is missing** | That the implementation performs the pairwise check; the entire second clause of the axiom; and the resource-propagation restriction — `ValidChain` compares only rights and epoch across a parent edge, so a delegator redirecting a child cap to a *different resource* is not blocked by the modelled check |

---

### A7 — No ambient authority (default deny)

> *Access requires a registered, valid claim. Absence of an applicable claim =
> denial. Default-deny. Always.*

| | |
|---|---|
| **Status** | **`CHECKED-BOUNDED`** — audit log ≤ 1 entry |
| Lean | **No theorem states "no claim ⇒ deny".** The closest result, `public_read_permitted` (`FreedomKernel.lean:184`), is sorry-free but proves the **opposite direction** — that public reads *are* permitted. It is the axiom's documented exception, not the axiom |
| TLA+ | Default-deny is a property of `Verify`'s definition (`authgate_v3.tla:142`: `IF valid_caps = {} THEN "Deny"`). Nearest named invariant is `PermitSoundness` (`:336-347`), in the cfg (`:34`). **Holds exhaustively at `Len(audit_log) <= 1`** (§2A) |
| Fidelity of that invariant | **Near-tautological.** `PermitSoundness` re-states the same `valid_caps` set-builder that `ExecuteVerify` used to compute the decision (`:268`). It checks that the log agrees with `Verify`, not that `Verify` is right. It is strictly *weaker* than `Verify` — it drops `binding_valid` and `expiry` — so it cannot detect the failures A1 and A5(b) care about |
| Kani | `prop_read_denied_without_claim` (`kani_proofs.rs:179`), `prop_write_denied_without_claim` (`:160`), `prop_delegation_denied_without_delegate_claim` (`:198`) all exist. All use **fully concrete inputs** — not one `kani::any()` appears in `kani_proofs.rs`. All target the **superseded v1 engine**. None has ever been compiled or run |
| **What is proven** | Nothing about default-deny |
| **What is missing** | The axiom's core direction. Also unmodelled: the `is_public=true` exception (`AXIOMATIC_FOUNDATION.md:161`) appears in no TLA+ file |

---

## 4. Summary

| Axiom | Status | One-line reason |
|---|---|---|
| A1 Action integrity | **`NONE`** | **Demonstrated by mutation testing:** delete the gate, all ten invariants still pass with identical state counts (§2A) |
| A2 Sovereignty flags | **`PARTIAL`** | Real proof, but about a 2-line model of the check; the theorem over the full gate is broken |
| A3 Identity binding | **`CHECKED-BOUNDED`** | `IdentityBinding` holds exhaustively — but at an audit log of ≤1 entry; hash injectivity is assumed, not modelled; root caps are never identity-checked |
| A4 No ownerless machine | **`PARTIAL`** | Genuinely proved over a composite gate model — the strongest result here — but its file does not compile and nothing links the model to code |
| A5 Signed + time-bounded | **`ASSUMED` / `NONE` / `CHECKED-BOUNDED`** | Signature explicitly assumed (§5) and the TLA+ suite is provably blind to deleting it; expiry is **unstatable** in this spec, not merely unchecked; epoch holds at ≤1 log entry |
| A6 Attenuation + no dominion | **`PARTIAL` / `NONE`** | Only real Lean content is transitivity of `⊆`; the cited theorem is `:= h`; clause 2's entire Lean content is `: True := trivial`. The TLA+ `Attenuation` invariant passes but is **unfalsifiable** — no model capability can escalate (§2A) |
| A7 No ambient authority | **`CHECKED-BOUNDED`** | `PermitSoundness` holds at ≤1 log entry, but it restates the decision procedure; no Lean theorem states the axiom's direction |

**Zero axioms are `PROVEN`. Zero formal artifacts in this repository are executed
by CI. Kani has never been installed. TLC had never been run before this audit;
it now has, and the result is a real but very small one (§2A) plus proof that the
invariant suite is blind to two of the axioms it is supposed to constrain.**

---

## 5. The explicit Ed25519 axiom

Added: **`formal/lean4/FreedomKernel/Ed25519.lean`**, axiom **`ed25519_euf_cma`**.
Referenced by **A5(a)** above.

It compiles cleanly under Lean 4.32.2 — one of only two files in `formal/` that
does — and carries a non-vacuity check: the lemma
`accepted_signature_has_an_honest_signer` is provable only via the axiom, and
`#print axioms` confirms `[ed25519_euf_cma]`. If a future edit makes that lemma
provable without the axiom, the axiom has gone vacuous and the check will say so.

**Statement.** If the deployed checker accepts `(pk, m, s)`, and `pk` is not a
low-order point, and `pk`'s private half has not leaked, then the holder of that
private key signed exactly `m`. The conclusion is `Signed pk m` — a real
proposition. This is what `sig_euf_cma` should have said; that axiom's conclusion
is `True`.

**Why the two hypotheses are load-bearing, not decoration.** They are precisely
the guarantees the code does not establish for itself:

- **`¬ SmallOrder pk`.** The TCB calls non-strict **`verify`**
  (`tcb/dag.rs:62`, `:71`, `tcb/engine.rs:110`), which **accepts small-order
  public keys**; `verify_strict` rejects them. `verify_strict` appears exactly
  once in the crate — in dead code, with its result discarded via `let _ =`
  (`crypto.rs:125`). The repo never calls `is_weak()`, and `CallGate::new`
  (`tcb/call_gate.rs:32`) accepts any `VerifyingKey`, so **the root trust anchor
  itself is never validated**. Nothing in the codebase discharges this hypothesis.
- **`¬ Compromised pk`.** Standard key custody, declared out of scope.

*(S-malleability specifically **is** excluded: `legacy_compatibility` is off, so
dalek's `check_scalar` enforces `S < ℓ`. That is the one thing in this area the
implementation gets right by construction.)*

**Six things this axiom does not give you**, each verified in code (full detail
in the file's own comments):

1. **No signature or key uniqueness** — one signature ⇒ one signer, but not one
   message, and not a well-formed key.
2. **No proof of possession by the requester.** `CanonicalAction` carries no
   signature and `binding_hash` is unkeyed, so **capability bundles are bearer
   credentials** — whoever copies one can replay it, bounded only by `expiry` and
   `min_epoch` against a **caller-supplied clock** (`call_gate.rs:13-15`).
3. **`proof_hash` is signed by nobody.** `signing_message()` (`types.rs:63-79`)
   omits it and the TCB never recomputes it — yet it resolves chain parents
   (`dag.rs:76`) and matches revocations (`engine.rs:99`).
4. **Revocation is fail-open and unbound to its target.** An invalid revocation
   signature hits `continue` with no log, no error, no metric
   (`engine.rs:93-96`). Combined with (3), a valid signature gives **no**
   assurance a capability has not been revoked.
5. **No domain separation.** The same root key signs capability grants (121/153 B),
   revocations (40 B), and Python rotation certificates (84 B) with no context
   string, version byte, or type tag. Cross-protocol confusion is blocked **only
   by those three lengths happening to be distinct** — an accident of the current
   field layout, untested, and not preserved by any future field addition.
6. **`crypto.rs:97-127` is not a verifier.** Named `verify_signature`, it
   re-signs with the **private** key and byte-compares (`:123-124`). Currently
   unreachable (private module, zero callers), so not a live vulnerability — but
   any future caller expecting to check a third party's signature gets a function
   that cannot.

**Scope.** This axiom constrains `tcb/dag.rs` and `tcb/engine.rs` and nothing
else. The Python capability path performs **no** signature verification; the Go
client never checks the `Signature` field it carries; the CLI has no crypto
dependency; `distributed_kernel.py`'s "threshold signatures" count dict entries
(`:164-174`); and `audit.py::verify_signed_export` defaults to verifying against
the key **embedded in the artifact being checked** (`:307-336`) — which proves
internal consistency, never authenticity.

The concrete artifact assumed correct is **ed25519-dalek 2.2.0**
(`Cargo.lock:564-566`). It carries no machine-checked proof of correctness or
constant-timeness. There is no HACL*, Fiat, or EverCrypt anywhere in the
dependency graph. Replacing this axiom with a verified implementation is
`AXIOMATIC_FOUNDATION.md:207`'s stated long-term goal and remains open.

---

## 6. Every vacuous artifact, in one place

Cited as evidence somewhere in this repo; worth nothing. Listed so they cannot
be re-cited by accident.

| Artifact | Location | Why it is worth nothing |
|---|---|---|
| `axiom sig_euf_cma` | `formal/lean4/Proofs.lean:66-69` | Conclusion is `True` |
| `axiom forged_revocation_harmless` | `formal/lean4/Proofs.lean:75-78` | Conclusion is `True` |
| `theorem machine_cannot_govern_human` | `formal/lean4/FreedomKernel/TCB.lean:135` | `: True := trivial` |
| `theorem ownerless_machine_must_have_owner` | `formal/lean4/FreedomKernel/TCB.lean:124` | `: True := trivial` |
| `theorem no_downward_write` | `formal/lean4/FreedomKernel/Temporal.lean:39` | `: True := trivial` |
| `theorem attenuation_cannot_escalate` | `formal/lean4/FreedomKernel/MultiAgent.lean:38` | Body is `:= h` |
| `theorem delegation_depth_bounded` | `formal/lean4/FreedomKernel/MultiAgent.lean:50` | Body is `:= h` |
| `theorem verify_deterministic` | `formal/lean4/FreedomKernel/TCB.lean:105` | `f a = f a`, true of every function |
| `proof_forged_revocation_ignored` | `formal/kani/prop_revocation.rs:35` | Body is `kani::assert(true, …)` |
| `proof_attenuation_two_node` | `formal/kani/prop_chain.rs:39` | Bitmask tautology; imports `validate_chain`, never calls it |
| `proof_subject_resource_binding` | `formal/kani/prop_confinement.rs:30` | `if !(a==b) { assert(a != b) }` |
| `proof_canonical_gate_completeness` | `formal/kani/prop_confinement.rs:53` | `if r != t { assert(r != t) }` |
| `proof_rights_sufficiency` | `formal/kani/prop_confinement.rs:70` | Restates its own `let` binding |
| `proof_epoch_gate_priority` | `formal/kani/prop_revocation.rs:52` | Restates its own `let` binding |
| `SovereigntyAlwaysBlocks` | `formal/freedom_kernel.tla:127` | `P ⇒ ¬(¬P ∧ …)` — `Permitted`'s own conjunct |
| `OwnerlessMachineBlocked` | `formal/freedom_kernel.tla:131` | Same shape |
| *(whole module)* | `formal/freedom_kernel.tla:77` | **Does not typecheck.** Line 77 uses `IsSeq`, which is not an operator in `Naturals, FiniteSets, Sequences, TLC` (its `EXTENDS`, line 27) — nor anywhere else. The module cannot be checked even in principle without editing it, which is why the two tautologies above have never been detected as such |
| `RevocationSafety` | `formal/authgate_v3.tla:206` | Re-checks the same filter that produced the decision |

All 7 files in `formal/kani/` belong to **no crate** — there is no `Cargo.toml`
under `formal/` — and **no harness in that directory executes a single line of
kernel code**.

---

## 7. Corrections this table makes to other documents

Each is a specific, checkable claim elsewhere in the repo that this audit
falsifies. Fix or delete them before the review packet ships.

| Document | Claim | Reality |
|---|---|---|
| `AXIOMATIC_FOUNDATION.md:217` | "24 Kani harnesses and 16 Lean theorems" | 23 `#[kani::proof]` attributes / 32 harness functions; 27 Lean theorems. Seven different harness counts appear across the repo (10, 13, 14+, 17, 19, 20, 24) |
| `AXIOMATIC_FOUNDATION.md:122,141` | `prop_epoch_check`, `prop_attenuation_two_node` marked "(✓ proved)" | **Neither name exists.** Near-matches are in a crate-less directory and are tautologies |
| `AXIOMATIC_FOUNDATION.md:49` | Python `verifier.py:verify()` enforces A1 | No binding check exists anywhere in Python |
| `AXIOMATIC_FOUNDATION.md:119,203` | `sig_euf_cma` is the cryptographic assumption | Its conclusion is `True`. It assumes nothing. Superseded by §5 |
| `AXIOMATIC_FOUNDATION.md` (all Rust rows) | Paths under `freedom-kernel/src/tcb/` | **That directory does not exist.** The crate is `authgate-kernel/`. Content is otherwise correct; `dag.rs:95` and `:101` are off by one |
| `AXIOMATIC_FOUNDATION.md:100,155` | Python line ranges for A4 and A7 | `152-165` contains no `[A4]` text (the actual string is at `:175`); `184-217` starts inside the ownership tracer and excludes the write loop |
| `formal/INCOMPLETENESS.md:10` | "All formal proofs apply to `freedom-kernel/src/tcb/engine.rs`" | **Zero** Kani harnesses target `tcb/`. 20 target the superseded v1 `src/engine.rs`; 5 target `sequence.rs`, which `tcb/mod.rs:12-13` declares **not** in the TCB |
| `formal/INCOMPLETENESS.md:87-94` | 8 harnesses marked "Unconditional" | All use fully concrete inputs. "Unconditional" is exactly what they lack |
| `formal/lean4/FreedomKernel/Scope.lean:140-141` | "T-SC3 and T-SC4 are fully proved without sorry" | **T-SC4 depends on `sorryAx`.** T-SC3 does hold. T-SC2, undisclosed, is also broken |
| `formal/TLC_SETUP.md:66-82` | Quotes `MC_AuthGateV3.cfg`'s invariant list | **Not one of the nine names is in the actual cfg.** Four exist in no `.tla` file at all. Following this document verbatim produces a config TLC rejects |
| `formal/TLC_SETUP.md:174`, `README.md:358`, `REVIEW_PACKET/04:21` | TLC blocked on Java | **Java 17 is installed and on PATH.** The real blocker was a filename/module mismatch that makes the spec unparseable (§2A) |
| `formal/TLC_SETUP.md:176` | Spec is "complete and ready" | **It does not parse.** `MC_AuthGateV3.tla:42` extends `AuthGateV3`; the file is `authgate_v3.tla` |
| `formal/TLC_SETUP.md:8`, `MC_AuthGateV3.tla:11` | "<5 minutes on a 4-core machine", "feasible on a laptop in ~minutes" | **Does not terminate.** 26.5M states in 10 min at the committed bound, queue still growing (§2A) |
| `attack_harness/ATTACK_MATRIX.md:52` | AT-1 TLA+ coverage "Full" | **Measured false.** Deleting the A1 gate leaves all ten invariants passing (§2A) |
| `formal/COVERAGE.md:11,9` | Tracks "I1 CanonicalBinding", "I3 ExpiryGate" | Neither operator exists in any `.tla` file |
| `formal/COVERAGE.md:34` | "Run `cargo kani` from `freedom-kernel/`" | Directory does not exist |
| `formal/INVARIANT_LATTICE.md:246` | "cfg is wired to check all 10 invariants (I1–I8 + …)" | I5 `CompositionMono` is **not** in the cfg's list |
| `formal/README.md:89` | "`MC_AuthGateV3.tla` — pending creation" | It exists and is 279 lines |
| `SEMANTICS.md:276` | "`formal/authgate_kernel.tla` specifies the five core invariants" | No such file; the four listed belong to the orphan module |
| `formal/freedom_kernel.tla:192` | `THEOREM Spec => []AttenuationHolds` | **A false theorem, not merely an unproved one.** `AttenuationHolds` (`:137-144`) quantifies over *every* pair of claims with different holders and the same resource where the delegator has `can_delegate` — **it requires no delegation relation between them**, so two entirely unrelated claims must be confidence-ordered. Reported violated by TLC within seconds once `IsSeq` is patched. The definition is verified here; the run is reported, not reproduced |
| `MC_AuthGateV3.tla:31` | Documents `EscalationCap` as the attenuation test case | **Never defined.** Only the comment exists; all six model caps have `rights \|-> {"READ"}` (§2A) |
| `MASTER_PLAN.md:63-67` | Top-priority TLC task | Describes `freedom_kernel.tla`'s constants and theorem count, but **that module has no `.cfg`**. The plan's highest-leverage action targets the model that cannot be run |
| `attack_harness/ATTACK_MATRIX.md:52,251` | "TLC verifies…", "Verified by `ResourceBinding` in TLC" | TLC has never run. For `:52`, no invariant constrains `binding_valid` at all; for `:251`, `MCResources = {"r1"}` makes a cross-resource attack inexpressible |
| `kani_proofs.rs:82-83` | "regardless of all other action fields" | `base_action()` five lines later pins every other field to a literal |

**Accurate as written, and the model to follow:**
`REVIEW_PACKET/04_FORMAL_VERIFICATION_STATUS.md` — it marks everything `NOT RUN`
and names its blockers (only the Java one has since become false).
`SEMANTICS.md:285-294`, `README.md:100`, `AXIOMATIC_FOUNDATION.md:246`, and
`formal/freedom_kernel.tla:20-21` also state their status honestly.

---

## 8. What would actually move a cell

In cost order. Note that the top three are hours, not months.

1. **Rename `formal/authgate_v3.tla` → `formal/AuthGateV3.tla`.** One line. Until
   this is done the spec **does not parse** and TLC cannot run at all (§2A). This
   is the single highest-value change in the repository right now.
2. **Fix the invariant suite so it can fail.** Mutation testing (§2A) shows the
   ten invariants pass unchanged when the A1 binding gate and both signature
   checks are deleted. Add the two probe invariants from §2A to the cfg, and
   record `now` in the audit log so expiry becomes statable at all. An invariant
   suite that cannot fail is not evidence, and this one demonstrably cannot fail
   for A1 or A5(a).
3. **Pick a checkable bound.** `Len(audit_log) <= 3` does not terminate;
   `<= 1` runs in 3s but admits no multi-decision interaction. `<= 2` is untried
   and is the obvious next experiment.
4. **Make the Lean build.** Add `lean-toolchain`, a lakefile covering all files,
   and a Mathlib dependency; fix the ~8 compile errors; delete or repair the 3
   vacuous `: True` theorems and the 2 tautologies. Then add `lake build` to CI so
   this cannot regress. Until this is done, **no Lean claim in this repo is
   reproducible by a reviewer.**
5. **Install Kani and run the harnesses.** They have never been compiled. Two
   mutually inconsistent Kani APIs are in use (`kani::assert!` macro form in
   `kani_proofs.rs` vs `kani::assert(cond, msg)` function form in `formal/kani/`),
   so expect compile errors before any proof runs.
6. **Replace concrete Kani inputs with `kani::any()`.** Only 5 of 32 harnesses —
   all in `tcb/sequence.rs`, which is explicitly outside the TCB — quantify over
   symbolic inputs. The other 27 are unit tests wearing a model checker's hat.
7. **Point the harnesses at the v2 TCB.** Currently zero harnesses touch
   `tcb/engine.rs`, `tcb/dag.rs`, or `tcb/call_gate.rs`.
8. **Write the missing statements.** A1 needs an invariant that fails when the
   binding gate is removed. A5(b) needs any expiry property at all. A6 clause 2
   needs a real theorem instead of `: True := trivial`. A7 needs a theorem in the
   axiom's own direction.
9. **Refinement.** Nothing connects the Lean models to the Rust or Python code.
   `A4` is proved about `permitted`, a hand-written model. Closing this is the
   contextual-refinement work, and it is the real project.

---

## 9. Read this before citing the green TLC run

The run in §2A is real. These are the reasons it proves much less than
"TLA+ verified" would suggest — the first three are now measured, not predicted:

- **Bounds:** 4 actors, **1 resource**, `MaxChainDepth = 2`, `MaxEpoch = 2`,
  **`Len(audit_log) ≤ 1`** (the committed bound of 3 does not terminate),
  `CHECK_DEADLOCK FALSE`, no `PROPERTY` section (so **no liveness is checked at
  all**). Only `"READ"` and `"WRITE"` of the 8 rights appear.
- **The suite is blind to A1 and to signature checking** — measured by mutation,
  §2A. This is the single most important caveat: for those two axioms a green
  run carries no information whatsoever.
- **Expiry is never exercised**: every model capability has `expiry |-> 2` and
  `now ∈ {0,1,2}`, so the guard is universally true (§2A).
- **The action space is hand-enumerated.** `MC_AuthGateV3.tla:269` replaces
  `\E a \in CanonicalAction` with `\E a \in MCActions` — a fixed 9-element set
  built from 6 hand-written capability records. TLC would explore only the
  scenarios the author already thought of.
- **Only 2 of the 9 actions can ever reach `Permit`.** All eight safety
  invariants are implications guarded by `decision = "Permit"`, so on the other
  seven they are **vacuously true**. The entire positive safety claim rests on
  two hand-built happy-path bundles.
- **Three invariants are unfalsifiable at these bounds.** `ResourceBinding` needs
  two resources; there is one. `EpochSafety`'s failure case needs two caps for
  one actor; no bundle has that.
- **`RevocationSafety` and `PermitSoundness` cannot fail by construction** — each
  re-checks the filter that computed the decision.
- **One latent abort:** `IdentityBinding` (`:186`) and `Attenuation` (`:195`)
  call `FindParent` without guarding on `HasParent`. On an empty candidate set
  TLC raises a runtime error and **aborts rather than reporting a violation**.
  Every model bundle happens to include `RootCap`, so it is never hit.

A green run would establish that two hand-constructed bundles satisfy eight
invariants over ≤3 log entries at depth ≤2. That is worth having — it would catch
gross spec errors and exercise the `Revoke` interleaving. It is **not** what
"TLA+ verified" conveys to a reader, and no outreach message should let it read
that way.

---

## 10. Note on the theory→axiom step

`PHILOSOPHY/COVERAGE_MATRIX.md` row 1 maps "Axioms A1..A7" of نظریه آزادی to this
kernel and marks the row **Enforced**. Whether A1–A7 faithfully render the
theory's commitments is a translation judgement with **no formal counterpart and
no mechanical check** — as `formal/INCOMPLETENESS.md:63-67` already says: *"The
kernel is sound relative to A1–A7. It cannot verify A1–A7 themselves."*
That row should read *Enforced (relative to A1–A7)*. The kernel's A1–A7 are the
only axiom set in the repository; there is no second, separate theory-level list.

---

*Maintenance: this table is only worth its harshness. Any cell moved up must cite
a theorem by file and name, or a tool invocation with recorded output. Round down
on ties. Next review: after the Lean build is fixed, or after TLC's first run.*
