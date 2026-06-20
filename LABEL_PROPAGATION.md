# The one question that decides AuthGate: can purpose labels survive an LLM?

> Everything else is settled. FDK closed; lock-in frozen; AuthGate's authorization claim absorbed
> by OPA/Cedar/Zanzibar; its survivor (purpose-as-flow) narrowed by `WHY_NOT_DLP.md` to
> *capability-bound runtime IFC in the agent loop*. That survivor lives or dies on **one technical
> question**, and this file tries to kill it:
>
> **Can a purpose/capability label attached to data at read-time be carried — usefully and
> reliably — through an agent's execution (including LLM transformations) to the point of
> egress?** If no → AuthGate is DLP with extra steps, and it closes like FDK. If *partially* yes
> → it may be the first thing here genuinely worth building.

## Split the question, because the two halves have opposite answers

**A. The sound, fine-grained version — DEAD.** Track the label through the *meaning*: does this
generated token "depend on" the SSN? `SSN → summary → embedding → generated text`. An LLM is not a
transparent function; it paraphrases, infers, combines, and can leak a fact without copying a
token (or copy a token that carries no sensitive info). Information-flow tracking through an opaque
function is infeasible in general — classic IFC (Denning, JIF) *requires a known program*. There
is **no known general answer** to "how much of the label remains," and there is unlikely to be
one. **Do not pursue sound semantic propagation. It is the FDK mistake in a new costume — "if we
could track meaning, it'd be huge" — and we can't.**

**B. The coarse, conservative, tool-boundary version — ALIVE, but threatened.** Do *not* track
meaning. Track provenance at the **capability/tool granularity**: if any input to a tool-call (or
LLM step) was read under a purpose-P capability, the *output of that step* inherits label P, unless
an explicit **declassifier** ran. At egress, the CallGate checks purpose-compatibility (P-labeled
data may not flow to a sink declared for purpose Q) and **blocks**. This is *buildable* on the
existing pieces (capability DAG + IFC extension + CallGate), and it is **reliable in the
conservative sense** (it over-approximates; it won't silently miss a flow).

## The real crux is not soundness — it's label-creep (and it's measurable)

Conservative propagation has a famous failure mode: **everything becomes tainted.** After a few
agent steps, every value carries every purpose label, the gate blocks all egress, and the system
is unusable — "sound but useless." So the deciding question is **not** "is it sound?" (B isn't,
semantically) but:

> **Does coarse capability-taint catch real purpose-violations *without* over-tainting legitimate
> work into uselessness — given a practical set of declassifiers?**

That is an **empirical** question with a measurable answer: on real agent traces,
- **True-positive rate:** does it block the support-PII→marketing-email / inference-data→training
  / tenant-A→tenant-B leaks?
- **Label-creep / false-positive rate:** how often does it block a *legitimate* action because
  everything got tainted?

If TP is high and FP is tolerable (with a small, auditable declassifier set), AuthGate has a real
reason to exist. If label-creep dominates, **it degrades to heuristic tainting ≈ DLP, and it
closes.** Nobody yet knows which — and that, not philosophy, is the whole game.

## Honest competition note (this thread is NOT empty, and that's good *and* bad)

Capability + flow-control for LLM agents is exactly where frontier work is moving in 2024–2025:
**DeepMind's CaMeL** ("defeating prompt injection by design") separates control-flow from
data-flow for LLM agents with a capability-like model; there is active research on taint-tracking
and permission systems for agents, the "dual-LLM"/planner-executor split, and agent-sandboxing.
**Good:** this *validates the problem as real and current* (the opposite of FDK, which fought
settled philosophy). **Bad:** AuthGate is not first or alone, so even the survivor must answer a
third kill-test — *what does AuthGate add over CaMeL-style capability/flow approaches?* — likely
"a deployable runtime gate + capability DAG + audit," i.e. engineering/product, not a new idea.

## Probabilities (the user's, and the analysis supports them)

| Claim | Probability |
|---|---|
| AuthGate as a new security paradigm | < 10% |
| AuthGate as new fundamental research | 10–20% |
| AuthGate as an Agent-Governance product | 40–60% |
| AuthGate as a strong distributed-systems + security engineering showcase | 80%+ |

More survivable than FDK by far — because the problem is a **real, new, 2026 agent problem**, not a
centuries-old philosophical one.

## The sprint, now fully specified (two gates, the second needs a small prototype)

1. **Gate 1 (cheap, no code):** the three scenarios from `WHY_NOT_DLP.md` — do they survive
   risks #1–#2 (not catchable by output-DLP; not adequately handled by PBAC+logging)? If they
   collapse, stop here and close AuthGate.
2. **Gate 2 (the decider, needs a minimal prototype):** implement *coarse capability-taint at the
   CallGate* (label = the capability a value was read under; conservative propagation per tool-step;
   a few declassifiers) and run it on real/realistic agent traces. **Measure true-positive vs
   label-creep.** That single measurement decides whether AuthGate is a product or DLP-renamed.

Note the honesty: settling this *does* eventually require code — but a *small experiment-prototype
to measure label-creep*, not feature-building. Everything before that measurement is speculation,
including this document. The status remains: **the most promising of the three projects, and still
unproven — now reduced to one buildable, measurable experiment.**

*The decisive question, not a pitch. Engineering: Ali Pourrahim. Sound semantic propagation is
dead; coarse conservative propagation is alive iff label-creep is tolerable, which only a
measurement on real agent traces can show. "Partially yes" is the only outcome worth building on.*
