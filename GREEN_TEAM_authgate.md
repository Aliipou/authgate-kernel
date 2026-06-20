# Green Team: the strongest honest defense of AuthGate against its kill-tests

> Mandate: mount the best *honest* defense of AuthGate against `WHY_NOT_OPA.md`,
> `WHY_NOT_DLP.md`, `LABEL_PROPAGATION.md`, `STATUS.md` — and check for **premature closure**.
> Two claims are adjudicated separately. No manufactured defense: where the defense fails, it is
> conceded. Where the red-team declared a corpse prematurely, that is contested.

The defense is grounded in what the repo actually ships, not in aspiration:
`src/authgate/kernel/call_gate.py` (the unconditional per-call gate) and
`src/authgate/extensions/ifc.py` (`SecurityLattice.can_flow`, `NonInterferenceChecker.check_plan`
with cross-action label accumulation). These are the only load-bearing artifacts; the defense
stands or falls on them.

---

## Claim (a): "AuthGate solves an AUTHORIZATION problem OPA/Cedar/Zanzibar/ABAC inherently cannot."

### Best honest defense

I tried four angles to find an authorization scenario only AuthGate handles:

1. **Purpose at request time.** `context.purpose == granted_purpose` is one Rego/Cedar line.
   Not AuthGate-only. Conceded.
2. **Revocation / consent divergence.** Zanzibar deletes a tuple; consent-as-owner-relationship
   models the consent≠permission gap natively. Conceded.
3. **Delegation-chain attenuation + signatures.** Capability DAGs and Zanzibar both validate the
   chain. The *root-legitimacy* question (did the grantor have the real-world right?) is
   non-computable inside **any** access-control system — a shared gap AuthGate does not close.
   Conceded.
4. **The structural reframe** — "all four incumbents are point-in-time deciders; AuthGate reasons
   over a *plan/sequence*." This is the only angle with teeth, and it is **not an authorization
   claim**. A point-in-time decider asked the same (subject, action, resource, context) tuple
   returns the same verdict AuthGate's kernel does. The sequence reasoning that differs lives
   entirely in the **IFC extension** (`check_plan` accumulating read-labels across actions) — i.e.
   it is *flow* control, which belongs to claim (b), not authorization.

### Verdict on (a): **CONFIRMED (kill is robust)**

There is no real authorization scenario only AuthGate handles. Cedar is formally verified;
Zanzibar scales with native revocation; ABAC/Rego express any context predicate. AuthGate's kernel
is a competent capability authorizer but offers **no authorization capability the incumbents lack**.
The honest defense of (a) fails, and a failed defense confirms the red-team. AuthGate must **not**
be pitched as a better authorization engine. The red-team's authorization kill is correct and
robust.

---

## Claim (b): "AuthGate's purpose-bound information-flow control for agents solves something DLP + Data-Lineage + PBAC + IFC inherently cannot."

This is where the defense is real, and where I contest **premature closure**. The red-team
(`WHY_NOT_DLP.md`) itself reaches only the verdict "*candidate gap, threatened by 3 risks,
unproven, needs the label-creep experiment*." That is **not a kill**. The green-team task is to
confirm the gap is genuinely distinct and that coarse propagation can be useful despite label-creep
— and thereby show the "DLP-renamed" verdict has **not yet been earned**.

### Part 1 — the gap is structurally distinct (the "DLP-renamed" verdict is premature)

The "DLP with extra steps" dismissal collapses four different mechanisms into one. They differ on
**axes that are not cosmetic**:

| Incumbent | Where it acts | What it binds to | Block or observe |
|---|---|---|---|
| DLP | content at egress (wire/email/upload) | pattern/classifier match on *content* | block, post-hoc, at the perimeter |
| Data Lineage | warehouse / ETL, batch | column provenance | observe, design-time, after the fact |
| PBAC / Hippocratic DB | the *read* (query time) | declared purpose at access | block the read only — blind after |
| Classic IFC (JIF/FlowCaml) | language level / compile time | static program labels | block, but needs a *known program* |
| **AuthGate CallGate** | **every agent tool-call, runtime, in-loop** | **the capability/purpose the datum was read under** | **block at the step** |

The CallGate occupies a cell **no incumbent occupies**: the agent's per-action boundary, at
runtime, with the label bound to the *capability* (not the content, not the column, not a static
program variable). Concretely:

- **DLP is content-at-egress and capability-blind.** It sees "an SSN is leaving." It cannot see
  "this value was read under a *support* capability and is now flowing to a *marketing* sink."
  When an agent **launders PII through the LLM** ("summarize this customer record, then email the
  summary"), the SSN may be gone from the content but the *purpose violation survives the
  paraphrase*. A content classifier inspecting the summary finds nothing; a capability-taint that
  rode the provenance still blocks. That is a class of violation DLP **structurally cannot see** —
  it is not "DLP with extra steps," it is a different observable.
- **PBAC gates the read, then goes blind.** It cannot follow the datum across subsequent prompts
  and tool calls; the cross-call flow is exactly `check_plan`'s job.
- **Lineage is observe-after, not block-in-loop.** It tells you afterward; it does not deny the
  emitting call. Detect-and-remediate ≠ prevent.
- **Classic IFC needs a known program.** An agent plan assembled at runtime by an LLM is not a
  known program; `check_plan` runs the lattice check over the *runtime action sequence*, not a
  compiled one.

The binding — *label = the capability the value was read under* — and the location — *the CallGate,
which `call_gate.py` makes the unconditional sole entry point for every tool call* — are jointly a
position the incumbent stack does not cover. The "renamed DLP" verdict treats a different
{location × binding × timing} as cosmetic. **It is not cosmetic, and so that verdict is premature.**

### Part 2 — coarse (not sound) propagation can be USEFUL despite label-creep

The red-team's deepest risk (`LABEL_PROPAGATION.md` §A) is correct and I concede it fully: **sound,
fine-grained semantic propagation through an LLM is dead.** An LLM is not a transparent function;
"how much of the label remains" is undecidable in general. Do not pursue it. That concession is not
optional — it is the honest floor of this defense.

But the red-team **also already conceded** the rest: the coarse, conservative, tool-boundary
version (§B) is *alive* and *buildable on the existing pieces*. The remaining objection is
**label-creep**: conservative over-approximation taints everything, the gate blocks all egress, the
system becomes "sound but useless." This is a real failure mode — and `check_plan` exhibits it
literally: `read_labels_so_far` only grows, so once a SECRET label is read, every subsequent write
is checked against it forever.

The honest defense is **not** "label-creep won't happen." It is that label-creep is **bounded by
engineering already standard in conservative IFC**, and whether the residual is tolerable is an
*empirical* question, not a settled-negative one:

1. **Declassifiers** (the repo already names them as the mechanism). A declassifier resets the
   label on an explicit, audited boundary — the same escape hatch that makes real-world taint
   tracking (Perl taint mode, Android TaintDroid, every practical IFC system) usable rather than
   useless. The open question is *how small an auditable declassifier set suffices*, not whether
   the escape exists.
2. **Domain constraints bound the lattice.** Agent workloads are not arbitrary programs. A support
   agent reads under a handful of purposes and emits to a handful of sinks. The propagation graph
   is shallow and the lattice is small (`SecurityLattice.default` is 3 levels). Creep is worst in
   long, unconstrained pipelines — not the typical bounded agent loop.
3. **Asymmetric cost favors conservative blocking *in the right deployment*.** The red-team's risk
   #2 ("blocking false-positives is worse than detecting") is true **for low-stakes flows** and
   false **for high-stakes irreversible ones** (cross-tenant exfiltration, PII→training set). For
   the irreversible class, an over-block that an operator clears beats a detect-after-the-leak.
   Deployment scoping, not soundness, decides this.
4. **It over-approximates — which is the *safe* direction.** A conservative gate may annoy; it does
   not silently miss a flow. For a governance control that is the correct failure bias, and it is a
   genuine property DLP's classifier (which silently misses paraphrased leaks) does not have.

None of (1)–(4) *proves* the residual false-positive rate is tolerable. They establish that
**"degrades to DLP" is a hypothesis, not a demonstrated outcome** — and the red-team itself says so:
"Nobody yet knows which — and that, not philosophy, is the whole game." The only thing that converts
the hypothesis either way is the **label-creep measurement on real agent traces** that
`LABEL_PROPAGATION.md` Gate 2 specifies. Until that number exists, declaring (b) dead is exactly the
premature closure this review was asked to check for.

### The honest ceiling of the defense (so this is not a pitch)

- The defensible claim is a **recombination** of known techniques (capabilities: Dennis–Van Horn
  1966; IFC: Denning 1976) at a new boundary — engineering value, not new science. Conceded.
- The thread is **not empty**: DeepMind CaMeL, dual-LLM/planner-executor, agent taint-tracking are
  moving into exactly this space. So even a surviving (b) faces a *third* kill-test — "what does
  AuthGate add over CaMeL?" — whose honest answer is "a deployable runtime gate + capability DAG +
  audit," i.e. product/engineering, not a new idea. Conceded.
- The `check_plan` implementation is *plan-level coarse taint over labeled resources*; it is **not
  yet** wired to derive the label from the read-capability at the live CallGate, nor does it carry
  a declassifier API. The mechanism is demonstrated in miniature; the decisive experiment is
  unbuilt. Conceded.

### Verdict on (b): **UNDECIDED — genuinely open, not closed**

The gap is **structurally real and distinct** (Part 1): a {capability-binding × CallGate-location ×
in-loop-blocking} combination no incumbent occupies, catching at least one class — LLM-laundered
purpose violations — that content-DLP cannot see. The "DLP-renamed" verdict is therefore
**premature**. But the defense is **not an overturn**: the deepest risk (label-creep degrading
coarse taint toward heuristic tainting) is unresolved, and *cannot* be resolved by argument — only
by the empirical measurement on real agent traces. So (b) is neither a proven kill nor an overturned
one. It is a **live, undecided, measurable** question — a question, not a corpse. Confirming that
status — and that closing it now would be premature — is the green team's honest finding.

---

## Per-claim verdicts

- **(a) Authorization-only capability → CONFIRMED.** The defense fails honestly: no authorization
  scenario is AuthGate-only. The red-team's authorization kill is robust. Do not pitch AuthGate as
  an authorization engine.
- **(b) Capability-bound runtime IFC at the agent boundary → UNDECIDED.** The gap is structurally
  distinct from DLP/lineage/PBAC/IFC and the "DLP-renamed" verdict is premature; but the
  label-creep risk is unresolved and only the empirical Gate-2 experiment can decide product vs.
  DLP-renamed vs. close. Genuinely open — not closed.

*Green Team (defense), AuthGate kill-tests. Engineering: Ali Pourrahim. A failed defense confirms
the red-team; an UNDECIDED verdict means the question is genuinely open, not closed.*
