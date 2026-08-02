# Infrastructure readiness and the proof roadmap

Written 2026-08-02, against the merged `assumptions-table` tree (`9de41c4`).
Every "current" claim below is checked against an artifact in this repository.

---

## 0. The ceiling, stated once

The goal "all axioms PROVEN" is not reachable, and the reason is not effort.

Two of the seven axioms bottom out in **computational hardness assumptions**:

- **A5(a) — `rfc8032_euf_cma`.** That Ed25519 signatures are unforgeable without
  the private key. Established in the literature by reduction to discrete log in
  the random-oracle model. `formal/lean4/FreedomKernel/Ed25519.lean:145` already
  states the position: *"No implementation proof — not HACL\*, not Fiat-Crypto,
  not EverCrypt — discharges it."*
- **A3 — hash injectivity.** `Hash(pubkey) = subject_id` is treated as injective.
  That is SHA-256 collision resistance, the same class of claim.

Discharging either means proving an unconditional lower bound — an open problem
in complexity theory, not a sprint item. Every verified system in production has
an axiom base: seL4 assumes its compiler and hardware model, CompCert assumes its
operational semantics, HACL\* assumes the F\* logic, Cedar assumes Lean's kernel.
A capability kernel claiming a zero-axiom base would not be more rigorous; it
would be advertising that nobody had audited it.

**So the target that replaces it, and is strictly stronger than today's state:**

> Every axiom is either mechanically proven, or reduced to a **named, minimal,
> explicitly-listed assumption base that `#print axioms` can enumerate on
> demand** — and every proof is connected to the **running Rust code**, not only
> to a hand-written model.

The second clause is the one that actually matters, and it is the one this
repository has not started. Today's green results all live on the model side of
a gap that nothing crosses.

---

## PART 1 — Infrastructure readiness

Ordered by value per unit effort. Phase 1 is days; it is also the single largest
credibility gain available right now.

### Phase 1 — CI, so that none of this can rot (days)

**The problem.** Everything green in `ASSUMPTIONS.md` was produced by hand on
2026-08-02: `lake build`, `MC_AuthGateV3_b1.cfg`, and `mutation_matrix.sh`. A
recursive grep over `.github/workflows/` for `lean|lake|kani|tlc|tla2tools`
still returns zero matches. Nothing prevents tomorrow's commit from silently
undoing all of it, and a reviewer has no way to tell.

**Deliverable:** `.github/workflows/formal.yml` running on every push:

| Job | Command | Failure condition |
|---|---|---|
| Lean | `cd formal/lean4 && lake build` | non-zero exit, **or** `sorryAx` appears in the log |
| TLC | `java -jar tla2tools.jar -config MC_AuthGateV3_b1.cfg MC_AuthGateV3.tla` | any invariant violation, or non-completion |
| Mutation | `bash formal/mutation_matrix.sh MC_AuthGateV3_mut` | any row not `CAUGHT`, **except** the known-redundant `leaf_epoch` |
| Rust | `cargo test` in `authgate-kernel/` | any test failure |

Three details that decide whether this is real:

1. **Pin `tla2tools.jar` by hash.** The matrix header already records
   `jar sha256: e22f8ff…`. CI must verify it, or "TLC passed" means nothing.
2. **The mutation job is the important one.** A green TLC run whose checks can
   all be deleted proves nothing — that was the 2026-08-01 finding. The
   allowlist must be exactly one entry (`leaf_epoch`) with the redundancy
   argument from `formal/MUTATION_NOTES.md` cited inline, so that a *second*
   escape appearing can never be waved through as "also probably redundant."
3. **Upload `formal/tlc_runs/` as a build artifact.** That is what turns
   "we ran it" into "here is the run, reproduce it."

### Phase 2 — Reviewer reproducibility (days)

A reviewer must reproduce every claim with one command and no local setup
knowledge. Today `tla2tools.jar` is gitignored and hand-fetched, and the Lean
toolchain is assumed resident.

- `Dockerfile.formal` / devcontainer pinning Lean `v4.32.2`, Java 17, the exact
  jar hash, and the Rust toolchain.
- `make verify` running all four jobs above locally, identically to CI.
- `REVIEW_PACKET/` gains a one-page "reproduce every table in ASSUMPTIONS.md"
  with exact commands and expected output.

### Phase 3 — Close the build's coverage holes (a week)

The green build is narrower than it looks. `formal/lean4/lakefile.lean` globs
`FreedomKernel/` submodules only, so these are **still outside the build**:
`formal/lean4/{Core,Invariants,Proofs}.lean` and `formal/FreedomKernel.lean`.
Every `BROKEN` verdict in `ASSUMPTIONS.md §2` citing them still stands.

- Bring them into the build or **delete them**. Files that no build touches, but
  that status tables cite, are exactly how the 2026-08-01 situation happened.
- Repair or delete the vacuous theorems (`: True := trivial`) and the two
  tautologies. A vacuous theorem in a green build is worse than a red build.
- Then: **no file in `formal/` may be outside CI.** Make that a rule.

### Phase 4 — Kani, actually installed (a week)

0 of 32 harnesses have ever been compiled. Two mutually inconsistent Kani APIs
are in use (`kani::assert!` macro form in `kani_proofs.rs` vs
`kani::assert(cond, msg)` in `formal/kani/`), so expect compile errors before
any proof runs. Until then, every Kani row in every table is unevidenced.

### Phase 5 — Raise the bound (ongoing)

All current TLC results are at `MCConstraintMut` / `b1`: one audit entry, one
prior revocation. `Len(audit_log) <= 3` does not terminate. `<= 2` is untried and
is the obvious next experiment — it is the first bound admitting multi-decision
interaction (revoke-then-use, epoch-advance-then-replay). Report the bound beside
every result, always.

---

## PART 2 — Per-axiom: where each one can actually get to

| Axiom | Today | Maximum reachable | What it takes | Blocked by |
|---|---|---|---|---|
| **A1** Action integrity | `CHECKED-BOUNDED`, mutation-caught | **PROVEN** (modulo Lean kernel) | Refinement: the Rust canonical-hash gate implements the model gate | model-to-code gap |
| **A2** Sovereignty flags | `PARTIAL` — proof is about a 2-line `verifyFlags` model | **PROVEN** | State it over the real composite gate, then refine to Rust | Phase 3 + gap |
| **A3** Identity binding | `CHECKED-BOUNDED` | **PROVEN modulo SHA-256 collision resistance** | Make hash injectivity an explicit named axiom, exactly as Ed25519 now is | irreducible core |
| **A4** No ownerless machine | `PARTIAL` — strongest Lean result, in an unbuilt file | **PROVEN** | Phase 3, then refine `permitted` to the Rust gate | Phase 3 + gap |
| **A5** Signed + time-bounded | `ASSUMED` / `CHECKED-BOUNDED` | **(a) split: impl-correctness PROVEN, hardness ASSUMED forever; (b)+(c) PROVEN** | Verified Ed25519 (HACL\*/libcrux, or the fiat backend) discharges `ed25519_verify_matches_rfc8032` only | **irreducible core** |
| **A6** Attenuation | `PARTIAL` / `CHECKED-BOUNDED` | **PROVEN** | Real Lean content (today it is `:= h` and `: True := trivial`), then refinement | Phase 3 + gap |
| **A7** No ambient authority | `CHECKED-BOUNDED` | **PROVEN** | State the axiom's direction in Lean; refine | gap |

**Read the A5 row carefully — it is the whole argument.** `proof-toolchain`
already split that axiom into `ed25519_verify_matches_rfc8032` (dischargeable, a
code-vs-spec claim) and `rfc8032_euf_cma` (irreducible). Swapping in a verified
implementation moves the first to PROVEN and leaves the second exactly where it
is, forever. Any future status table that flips A5 to "verified" after a library
swap is wrong, and the docstring now says so in the file itself.

**End state, stated the way it should be said to a reviewer:**

> Five axioms proven against the running code. Two reduced to named standard
> assumptions — Ed25519 EUF-CMA and SHA-256 collision resistance — both explicit
> in the Lean development and enumerable by `#print axioms`.

That is a claim Watson, Klein or Miller can check and would respect. "All seven
proven" is a claim they would disbelieve on sight, and correctly.

---

## PART 3 — The model-to-code gap: the only barrier that matters

Everything in Part 1 makes the *existing* results trustworthy. None of it makes
them say anything about `authgate-kernel/src/tcb/*.rs`. Nothing in this
repository connects `AuthGateV3.tla` or the `FreedomKernel` Lean library to the
Rust: no refinement proof, no extraction, no differential testing, not even a
checked correspondence of field names. **If the Rust diverges from the model,
every green result in `ASSUMPTIONS.md` stays green and reports nothing.**

Four routes, cheapest first. They are not exclusive; do 3.1 immediately.

### 3.1 Differential testing — the cheap bridge (weeks, do this first)

Generate random `CanonicalAction` + capability bundles; run them through **both**
the Rust `engine::verify` and an executable form of the model; assert the
decisions agree. Shrink any divergence to a minimal counterexample.

This is precisely Cedar's verification-guided development (*How We Built Cedar*,
arXiv:2407.01688), and it is the honest answer to the question every reviewer
will ask — *"how is this different from Cedar?"* — which
`REVIEW_PACKET/07_COMMUNITY_CHANNELS.md` already flags as unanswered.

It proves nothing. It is also the only item here that would catch a real
divergence **this month**, and it converts the mutation matrix from a statement
about the model into evidence about the code.

### 3.2 Kani — bounded, mechanical (months)

Bounded model checking of `engine.rs` properties directly. Genuine machine
checking of the real code, with the bound stated. Document the
Kani-bounded/Verus-unbounded frontier per Parno's formulation.

### 3.3 Aeneas — Rust to Lean (months)

Aeneas translates Rust into Lean, which matches the Lean investment already made
here. This is the natural route given `formal/lean4/` exists and now builds.
Inria Prosecco is the contact.

### 3.4 Iris / RefinedRust — the real thing (1–1.5 years)

Krebbers' own estimate for an experienced team, which is why the two-track plan
files it as a **doctoral project**, not a sprint. It is the route that ends in
"proven against the code" with no bound and no caveat.

---

## PART 4 — If this is meant to be long-lived infrastructure

Taking that framing seriously raises the standard rather than lowering it, and it
changes *which* items above are load-bearing. Four things become non-optional,
and the first is a concrete defect found while writing this document.

### 4.1 The signed message has no version, algorithm, or domain tag — fix before adoption, not after

`CapabilityProof::signing_message()` (`authgate-kernel/src/tcb/types.rs:63-79`)
signs exactly: `subject_id ‖ resource_hash ‖ rights ‖ expiry ‖ epoch ‖
issuer-discriminant ‖ issuer_pubkey`. The doc comment above it says *"Field order
is fixed — any change is a protocol version bump."* **The version is not in the
signed bytes.** Neither is an algorithm identifier, nor a domain-separation
prefix.

Three consequences, none of them exploitable today, all of them structural:

1. **No crypto agility.** Ed25519 will have to be replaced — post-quantum
   migration is a *when*. A verifier that accepts two schemes cannot tell which
   scheme a signature was produced under, because the algorithm is not bound
   into the signed message. This is the JWT `alg`-confusion class of failure, and
   it is the standard way long-lived signed formats die.
2. **No domain separation.** `signing_message()` and `to_canonical_bytes()`
   (`:82-93`) serialise overlapping field sets with no distinguishing prefix.
   They cannot collide *given today's field choices* — but that is an accident of
   which fields each happens to include, not an enforced property. Any future
   field change can silently make a signature over one valid as a signature over
   the other.
3. **The version bump the comment promises does not work.** Old signatures stay
   verifiable under a new field order, because nothing in the signed bytes says
   which order was intended.

**Fix, and it is cheap now and expensive later:** prefix the signed message with
a fixed domain string, a format version, and an algorithm identifier — e.g.
`b"AuthGate/cap/v1" ‖ alg_id ‖ …` — and a *different* domain string for the
canonical-action hash and the audit-log entry. Do it before anyone deploys, since
afterwards it is a flag day for every issued capability.

This is exactly the kind of thing that is invisible at prototype scale and
unfixable at infrastructure scale.

### 4.2 Infrastructure means a spec and a second implementation

TCP, TLS and HTTP are infrastructure because they are **written specifications
with independent interoperating implementations**. One codebase, however well
verified, is a product. This is what makes Track B of the two-track plan
structural rather than commercial: AuthZEN and WIMSE participation is not
marketing, it is the mechanism by which a design becomes something others can
implement and check. A second implementation — even a deliberately simple one in
another language, checked against the first by the differential harness of §3.1
— is worth more than another invariant.

### 4.3 The root key is a governance question wearing a technical costume

The model has one `RootKey`, and epoch advance invalidates every capability
beneath it. Whoever holds that key, and whoever can advance the epoch, governs
every agent the kernel gates. At civilizational scale that is not a key
management detail; it is a constitutional one. The questions a serious reviewer
will ask, and which no document here answers yet:

- Who holds the root key, and under what process can it be used?
- Is there threshold or multi-party control, or is it one key on one machine?
- What is the blast radius of root-key compromise, and what is the recovery path
  besides "advance the epoch and reissue everything"?
- Can two mutually distrusting parties share a kernel, or does the design assume
  a single sovereign?

The philosophy work in this repository is precisely about who may legitimately
hold authority. It should be the thing that answers this, and right now the
technical layer and the theory layer are not connected at this point.

### 4.4 Longevity: formats outlive code

An audit log meant to be checkable decades later needs a versioned,
self-describing wire format and a written parse specification — not a Rust struct
whose field order is the spec. Same for the capability format. The 4.1 fix is the
first instalment of this.

---

## Appendix — "Is Ed25519 really necessary?"

Asked 2026-08-02. It is the right question, because signatures are the *only*
reason A5(a)'s irreducible half exists. Remove them and the crypto axiom goes
with them. So it deserves a real answer rather than a reflex.

**Signatures are not necessary for capability security as such.** The classical
object-capability systems — E, Capsicum, seL4, KeyKOS — use **no cryptography at
all**. A capability there is an unforgeable *reference*: a pointer or handle
whose unforgeability comes from memory safety and a kernel-managed table, not
from a hardness assumption. If AuthGate's kernel is a single trusted process that
mediates every tool call, it could do exactly the same: hand out opaque 256-bit
random handles, keep the capability table itself, and never sign anything.

That variant's assumption base is strictly weaker and much more elementary:
handle unguessability (a birthday bound over the RNG) plus memory safety, instead
of EUF-CMA reduced to discrete log in the ROM. A5(a) would disappear.

**What it costs is the entire differentiation.** Signatures buy four properties
that a kernel-side handle table cannot:

| Property | Signed chain | Handle table |
|---|---|---|
| Offline / third-party verification | anyone with the root key can check a decision | only the issuing kernel can |
| Delegation without contacting the issuer | yes — attenuate and sign | no, must call the kernel |
| Tamper-evident audit anyone can check | yes, hash-chained + signed | trust the kernel's own log |
| Multiple mutually distrusting kernels | yes | no, single trust domain |

`REVIEW_PACKET/07_COMMUNITY_CHANNELS.md` states the project's claimed
differentiation against Cedar as *"capability chain cryptographically verified,
**no trusted evaluator**"*. Dropping signatures makes the kernel a trusted
evaluator — which is precisely Cedar's model, done with less maturity and no
Lean specification. The design would lose the answer to the first question every
reviewer asks.

**Three conclusions.**

1. **Ed25519 is necessary for the system as claimed**, and not necessary for a
   single-trust-domain reference monitor. Which one is being built is an
   architectural decision, not a proof-engineering one.
2. **There is no zero-assumption design.** Handles assume RNG quality and memory
   safety; signatures assume EUF-CMA. The axiom base changes shape; it does not
   vanish. A3's SHA-256 assumption also survives either way, as long as the audit
   log is meant to be tamper-evident to anyone but the kernel itself.
3. **Do not drop signatures to improve the status table.** That optimises the
   document rather than the system, and a reviewer of Watson's or Miller's
   calibre will read the substitution for exactly what it is. The correct move is
   the one `proof-toolchain` already made: split the axiom, discharge the half
   that is dischargeable, and state the other half plainly.

If a single-trust-domain deployment *is* a real target — an in-process gate for
one agent runtime, say — then the honest framing is two profiles sharing a
kernel: a **local profile** with handles and no crypto axiom, and a
**distributed profile** with signed chains. That is a legitimate design, and it
would let the local profile reach a genuinely smaller axiom base. It should be a
deliberate product decision, not a side effect of wanting a cleaner table.

---

## Sequencing

1. **Phase 1 CI** — days, largest credibility gain, blocks nothing else.
2. **Phase 2 reproducibility** — days, needed before the packet goes wide.
3. **3.1 differential testing** — weeks, the first evidence about the Rust, and
   the answer to the Cedar question.
4. **Phase 3 + 4** — clean out unbuilt files and vacuous theorems, install Kani.
5. **3.2 → 3.3 → 3.4** — the long climb, in that order.

Nothing in steps 1–4 requires a research collaboration. All of it is engineering,
and all of it is the part that makes the research legible when it lands.
