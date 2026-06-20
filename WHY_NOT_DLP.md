# Kill-test #2: does AuthGate's one survivor beat DLP + Lineage + PBAC + IFC?

> `WHY_NOT_OPA.md` killed AuthGate against the *authorization* incumbents (OPA/Cedar/Zanzibar)
> on everything except **one** thread: purpose-as-*flow* (data read for A, used for B), which
> point-in-time policy engines structurally can't see. But that thread lives in the
> **data-governance** space, which is *also* decades old. So the survivor must be re-killed here.
> The discipline (the one FDK kept fumbling): the question is **not** "could agent data-flow be
> important?" — it obviously could — it is **"what does AuthGate solve that the combination
> DLP + Data Classification + Data Lineage + Purpose-Based Access Control + IFC does not?"**
> If the answer is "nothing," the last survivor dies too.

## The data-governance incumbents, fairly, and their structural limit for *agents*

- **DLP / Data Loss Prevention** — detects/blocks sensitive *content* at egress points (email,
  upload, endpoint) via patterns/classifiers. *Limit:* content-at-egress, **not capability- or
  purpose-aware** — it sees "an SSN is leaving," not "this agent read it under a support
  capability and is now using it for marketing." Post-hoc, at the wire, not at the agent step.
- **Data Classification / labeling** (Purview, Macie) — tags sensitivity. *Limit:* labels, not
  runtime *enforcement* of where labeled data may flow during an agent's reasoning.
- **Data Lineage** (OpenLineage, Marquez, warehouse lineage) — tracks provenance through ETL/
  pipelines. *Limit:* **observability, batch/analytical, design-time** — it tells you afterward
  where a column came from; it does not *block* an agent action in the loop.
- **Purpose-Based Access Control / Hippocratic DBs** (GDPR purpose limitation) — binds access to a
  declared purpose **at query time**. *Limit:* it gates the *read*, like OPA-with-purpose; it does
  **not** follow the datum *after* the read, across prompts and tool calls.
- **Confidential Computing / TEEs** — protect data-in-use from the operator. *Limit:* isolation/
  encryption, **orthogonal** to purpose/flow semantics.
- **IFC (JIF/FlowCaml, research)** — the *correct mechanism*: labels + lattices + non-interference.
  *Limit:* mostly **language-level / research**, hard to deploy, and **not capability-aware** —
  classic IFC labels don't carry "obtained under capability C for purpose P."

Common structural fact: **all of these were built for humans and ETL pipelines, not for an
autonomous agent that makes many tool calls moving data through an LLM context.** That execution
surface — read via tool 1, reason in the prompt, emit via tool 2 to a different tenant/sink — is
where their assumptions don't fit.

## The candidate gap (stated narrowly, so it can be killed)

> **Capability-bound, runtime, per-tool-call information-flow enforcement *inside the agent loop*
> — the IFC label is tied to the *capability/purpose* under which the data was obtained, and the
> CallGate *blocks* (not just logs) any subsequent tool call that would move it to a sink
> inconsistent with that purpose.**

AuthGate is unusually positioned for exactly this, because it already has the three pieces *in one
runtime*: capability provenance (the DAG), the IFC extension (`NonInterferenceChecker`,
`SecurityLattice`), and the **CallGate** as the enforcement point at every tool invocation. The
existing stack has the pieces *in different products at different layers* (DLP at egress,
lineage in the warehouse, PBAC at the DB, IFC in a compiler) — none of them at the agent's
per-action boundary, and none of them carrying the *capability/purpose* label.

So the honest candidate answer to "why AuthGate vs the data-governance stack?": **it enforces
purpose as a flow property at the agent's tool boundary, with the label derived from the
capability the data was read under — a place and a binding the incumbents don't cover.**

## But hold the discipline — three ways this still dies

1. **"DLP with extra steps."** If, in practice, a content-classifier at each tool's egress (an
   "LLM-output DLP") catches the same violations without needing capabilities or IFC, the gap is
   cosmetic. Much agent-data-leak tooling is heading exactly there.
2. **PBAC + good logging is enough.** If purpose-at-read (PBAC) plus lineage/audit lets you
   *detect and remediate* misuse acceptably, the *runtime-blocking* IFC may be over-engineering
   nobody buys (blocking false-positives is worse than detecting).
3. **Label propagation through an LLM is unsound.** IFC needs to track the label as data flows —
   but once data enters an LLM's context and is transformed/summarized, *label propagation is
   undecidable in general*. If you can't soundly carry the label through the model, the whole
   mechanism degrades to heuristic tainting ≈ DLP. **This is the deepest technical risk**, and it
   may be fatal on its own.

## Probabilities (the user's, and the evidence supports them)

| Claim | Probability |
|---|---|
| AuthGate as a "new security paradigm" | low |
| AuthGate as a useful **Agent Governance** product | **notable** |
| AuthGate as a **complementary capability** on agentic-AI systems | **most likely** |

This is **more promising than FDK** for a non-philosophical reason: FDK chased a *philosophical*
question already tested for centuries; AuthGate chases a *practical 2026* question — *"what do
autonomous agents do with data after they're granted access?"* — that genuinely sharpens as agents
get stronger. The problem is real and current; the open question is solvability/differentiation,
not relevance.

## The sprint (still 2–4 weeks, still no new code) — but now against the right incumbents

Find **three real agent scenarios** where:
1. the read is properly authorized (OPA/Cedar/Zanzibar pass), **and**
2. a content-DLP at egress would *miss or false-positive* it, **and**
3. PBAC + lineage would only *detect after the fact*, **and**
4. capability-bound runtime IFC at the CallGate would *block it at the step*, **and**
5. the label can be **soundly carried** to that step (defeating risk #3).

Candidates: support-PII → marketing email; data consented for inference → training set;
tenant-A data → tenant-B tool; a "summarize then send" that launders PII through the model. For
each, the killing question is **risk #1/#2/#3 above**. If all three collapse into "ship an
output-DLP + audit log," **close AuthGate** and keep the body of work as a portfolio. If even one
holds — a real agent purpose-violation that *only* capability+IFC-in-the-loop catches, with sound
label propagation — then AuthGate has its single, real, defensible reason to exist, in **agent
data governance**, and that is worth building.

*Kill-test #2, not a pitch. Engineering: Ali Pourrahim. "Could matter" is not "does matter" — the
evidence required is the three scenarios above surviving risks #1–#3. Until then, the honest status
is: the most promising of the three projects, and still unproven.*
