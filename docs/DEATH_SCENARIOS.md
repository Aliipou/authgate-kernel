# Death Scenarios — How the Project Becomes Irrelevant

> "What kills this project is not technical failure. What kills it is
> picking the wrong abstraction for the world that actually emerges."
> — Synthesis of architect reviews, 2026-05-30

This document is the honest accounting of every way the project could become
worthless over the next 20 years, and what — if anything — defends against each.

It is NOT a marketing document. It exists to keep the team honest.

---

## How to read this

For each scenario:

- **Probability** — rough estimate (high/medium/low)
- **Mechanism** — what change in the world makes us irrelevant
- **What survives** — the parts of the project that still apply
- **What dies** — the parts that become worthless
- **Defense** — whether anything we can do now reduces the risk

---

## Scenario 1: Frameworks change, project is framework-bound (HIGH probability, LOW impact)

**Mechanism:** LangChain dies. OpenAI restructures their SDK. CrewAI rebrands.
A project tightly coupled to these dies with them.

**What survives:**
- The `CanonicalAction` wire format
- The `verify()` function
- The capability algebra
- The audit chain primitives

**What dies:**
- Every framework adapter
- Tests tied to framework specifics
- Marketing copy that named frameworks

**Defense:** STRONG, and we've already taken it.
- `POSITIONING.md` explicitly says we are NOT a framework plugin
- Adapters are conveniences, not the contract
- The wire format (JSON Schema in `spec/`) is what external systems implement
- Every adapter can be deleted without breaking the project identity

**Verdict:** Manageable. Annual framework churn is expected; we route around it.

---

## Scenario 2: Models "solve" authorization internally (MEDIUM probability, LOW impact)

**Mechanism:** Vendors say "GPT-12 is permission-aware, constitution-aware,
ethics-aware — you don't need an external gate."

**Why this is not actually a kill scenario:**

Security is not probability. A model that says "I am 99.97% confident this
is authorized" is not security — it is regulatory theater. Real authorization
requires:

```
Permit OR Deny.
Same input → same output.
Independently verifiable.
```

CPUs have not become "ethical." That is why SELinux, seccomp, capabilities,
sandboxes still exist 50 years after they were proposed. Models becoming
"smarter" does not change this.

**What survives:** Everything. The whole project.

**What dies:** Nothing structural. Some PR work to push back against the
"models will handle it" narrative.

**Defense:** Keep the kernel deterministic. Never accept a probabilistic
authorization decision into the TCB.

**Verdict:** Not a real death scenario. A marketing battle, not an existential one.

---

## Scenario 3: OS absorbs the layer (MEDIUM probability, ABSORPTION not death)

**Mechanism:** Linux, seL4, CHERI, or a successor OS adds first-class agent
capability primitives. Authgate becomes redundant as a separate library
because the OS does it natively.

**What survives:**
- The design (capability semantics, attenuation, epoch revocation)
- The contributors' credibility
- The wire format may influence the eventual standard

**What dies:**
- The independent library / standalone project
- The independent commercial story (if there was one)

**Why this is NOT failure:** This is success absorption. Like network
namespaces in Linux making LXC less essential, or like SSL/TLS being
absorbed into the kernel via kTLS. The work was right; the layer moved.

**Defense:** Stay aligned with capability security tradition. Make the
design citable. Publish the formal model. Be the prior art the eventual
standard cites.

**Verdict:** Acceptable. Better than irrelevance.

---

## Scenario 4: Fully autonomous agents without human trust root (HIGH-impact, HIGH-uncertainty)

**Mechanism:** Thousands of agents operate without human owners. They form
companies, sign contracts, transact with each other:

```
Agent → Agent → Agent
```

The chain has no human at the root.

**The deep problem this exposes:**

The current architecture assumes:

```
Human (trust root)
  ↓ delegates capability
Agent
  ↓ may sub-delegate
Sub-agent
```

Remove the human, and the trust root collapses. The kernel's foundational
invariant (`A4: ownerless machines are denied`) becomes either:
- vacuously true (no machines act, system unused) — death by irrelevance
- or violated (machines act without human root) — death by lying

**What survives:**
- Capability delegation algebra (still valid between any actors)
- Attenuation invariant (`child ⊆ parent`) (still valid)
- Revocation primitives (still valid)
- Audit chain (more valuable than ever)

**What dies:**
- The single-human-trust-root assumption (`A4`)
- The current `OwnershipRegistry` structure
- The "ownerless machine blocked" check, in its current form

**Defense paths (LATER — explicitly deferred, see layer discipline below):**

1. **Constitutional authority** — multi-party signed bootstrap; quorum trust roots.
2. **Distributed authority** — federated trust roots with cross-trust policies.
3. **Threshold authority** — k-of-n signature schemes.

**Layer discipline — why these stay deferred:**

The current project is fighting layer-1 question:
> *"Who is authorized?"*

Constitutional / distributed / threshold authority fight layer-2 question:
> *"Who decides who is authorized?"*

The classic engineering mistake is jumping from layer 1 to layer 5 before
layer 1 is solved. We are not jumping.

Today:
- 0 external users
- 0 known public deployments
- 0 independent audits

In this state, building "constitutional consensus" or "federated governance"
is premature architecture. The real risk today is not that the authority
model is insufficient — it is that nobody uses the authority model at all.

These two failure modes are completely different.

**The discipline:**

| Layer-2 work | Allowed where | Forbidden where |
|--------------|---------------|----------------|
| Distributed authority | `research/` branch, paper drafts | TCB |
| Constitutional consensus | `research/` branch, spec drafts | `main` / `integration` |
| Threshold trust roots | `research/` branch | Kernel implementation |
| Federation | `research/` branch | Production code path |

The current TCB does not implement any of these and **must not** until
layer 1 is validated by real deployment + external review.

The architecture IS shaped to accept them later (`AuthoritySource` interface
exists). But "shaped to accept later" ≠ "implemented now." Keep the shape;
defer the substance.

**Verdict:** Real existential risk for the **current trust model**, but NOT
for the kernel's core algorithms. The defense is to keep the trust root pluggable
**and to refuse to build layer-2 features prematurely.**

**Engineering timeline:**

| Period | Layer-2 stance |
|--------|---------------|
| 2026-2028 | Only `Capability + Delegation + Revocation + Audit + Sandbox`. No multi-tenant. |
| 2028-2031 | If real adoption exists: start `Multi-tenant authority`, `Cross-org delegation`, `Federation` |
| 2031+ | If agent networks emerge: `Threshold authority`, `Constitutional authority`, `Distributed trust roots` |

Each gate is opened only when the prior layer is proven by adoption,
not by speculation.

---

## Scenario 5: Paradigm shift from permission to market (HIGH-impact, MEDIUM-probability)

**Mechanism:** The question changes from:

> "Is this actor permitted to do X?"

to:

> "Can this actor afford to do X?"

Economic agents staking capital to perform actions. Reputation as authority.
Consensus as legitimacy. Markets replacing permission systems.

Example shift:

```
Today:  Can Agent read file?           (permission question)
Future: Can Agent afford reading file? (market question)
```

These are fundamentally different questions. If the world goes the second way,
authgate's whole framing (permission gate) becomes the wrong primitive.

**What survives:**

Surprisingly — most of the algebra still applies, because:
- "Capability proof signed by stake-holder" is structurally the same as "capability proof signed by trust root"
- An economic contract is a capability with payment as the issuance precondition
- Revocation maps to refund / forfeiture
- Audit maps to ledger

The `CanonicalAction` wire format does not change. The trust source
(`AuthoritySource`) does. We anticipated this in `research/capability-model-extension.md`:
`MarketOracleSource` is a stub for exactly this scenario.

**What dies:**
- The "Human as primary trust root" framing
- The free-permission model (everything becomes paid)
- The current default that revocation is unilateral (markets need bilateral semantics)

**Defense:**
1. Keep `AuthoritySource` interface stable so market-oracle implementations slot in
2. Keep the kernel agnostic about *why* a proof was issued — just verify it
3. Don't entangle the kernel with permission-specific assumptions

**Verdict:** The real existential risk, but the architecture has the right
shape to survive it IF discipline holds.

---

## Scenario 6: Capability is the wrong primitive (LOW probability, TOTAL impact)

**Mechanism:** Capability security turns out to have been the wrong abstraction
all along. A successor primitive (we cannot name it now) replaces it across
all of computer security.

**What survives:**
- The contributors' formal methods skills
- The architectural discipline
- The published threat models
- Some Lean theorems (universal mathematical content)

**What dies:**
- Everything else
- Including the project name

**Defense:** None. This is a Black Swan. You cannot defend against the
abstraction itself being wrong. You can only ensure the work was honest,
the proofs were real, and the contributions are citable when the next
paradigm cites prior art.

**Probability:** Low (capability security has held since the 1970s in
systems like seL4 and CHERI). But non-zero.

**Verdict:** Out of our hands. Stay honest. Be cite-able prior art if it happens.

---

## The 20-year survival kernel

If the project lives 20 years, only these parts likely survive:

| Surely survives | Likely survives | Likely rewritten | Likely gone |
|----------------|----------------|------------------|-------------|
| Capability delegation algebra | The wire format | Adapters | Framework-specific code |
| Attenuation invariant | Audit chain semantics | Trust root model | "manipulation_score" if it ever returned |
| Revocation primitives | Formal proofs | Identity binding (cryptographic shape may change) | Constitutional/governance layers |
| Resource binding | Threat model document | Default `Action` schema | Any heuristic |
| Deterministic verify() contract | The 16 Lean theorems | Distributed extension | Anything semantic |

The 20-year-survivable kernel is roughly:

```
~500 LOC of Rust (verify + chain + types)
+ wire format JSON Schema
+ ~5 Lean theorems
+ ~10 Kani harnesses
+ formal/INCOMPLETENESS.md (the boundary statement)
```

Everything else is scaffolding around it. Important scaffolding, but
scaffolding.

---

## What this analysis demands of the team

1. **Treat the wire format as the contract.** Adapters can die without consequence.
2. **Keep the trust root pluggable.** `AuthoritySource` exists for this — keep it.
3. **Never assume "Human" is the only trust root forever.** Phase 4 will demand alternatives.
4. **Resist market-flavored features in the kernel.** They go in `AuthoritySource` adapters.
5. **Publish the formal model.** Be cite-able when the next paradigm arrives.
6. **Document non-goals more aggressively than goals.** What we DON'T do is what makes us survive.

---

## What this rules out (today, regardless of scenario)

Adding any of these to the TCB is forbidden because every scenario above
makes them worse, not better:

| Forbidden in TCB | Why every death scenario disfavors it |
|-----------------|--------------------------------------|
| Framework-specific code | Scenario 1 |
| Probabilistic decisions | Scenario 2 |
| Model-aware logic | Scenarios 1+2 |
| Hardcoded "Human" trust root | Scenarios 4+5 |
| Permission/market entanglement | Scenario 5 |
| Heuristic semantics (coercion, ethics, etc) | Scenario 6 (compounding bad bets) |

(These are also enforced by `TCB_DISCIPLINE.md` Rule 2.)

---

## The honest summary

Of the six scenarios:

- **Scenario 1** (framework churn): defended; manageable
- **Scenario 2** (model "solves" it): not a real death
- **Scenario 3** (OS absorbs): absorption, not death; acceptable
- **Scenario 4** (no human root): real risk; defense exists but unfinished
- **Scenario 5** (paradigm shift): real risk; architecture is well-shaped to survive
- **Scenario 6** (capability is wrong): black swan; out of our hands

The project's job for the next 5 years is:
- Defend against 1, 2, 3 by discipline (in place)
- Prepare for 4 by keeping `AuthoritySource` and trust roots pluggable
- Prepare for 5 by NOT entangling permission with payment in the kernel
- Accept 6 as out-of-scope but stay honest enough to be cite-able prior art

If we do those four things, the kernel core has a reasonable chance of
20-year relevance — regardless of which specific scenario emerges.

---

*Updated: 2026-05-30. Re-review when any major architectural shift is
visible on the horizon. This document is constitutional — changes
require explicit re-analysis, not casual edits.*
