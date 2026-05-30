# Project Positioning — What authgate IS, What it IS NOT

> "If you define authgate as 'a product for LangChain/OpenAI/CrewAI,' it dies
> when those frameworks change. If you define it as 'the authorization layer
> between decision and execution,' it becomes more important as agents get stronger."
> — Architect review, 2026-05-30

This document is the canonical answer. Every other document defers to this one
when there is a conflict about identity.

---

## What authgate IS

**The authorization layer between any decision and any IO.**

That's it. One sentence. That sentence must survive every architectural shift
in AI for the next 10 years.

The shape of the system is:

```
[Any decision-maker]
       ↓
       produces an Action (typed, signed, scoped)
       ↓
   ┌───────────────┐
   │   AuthGate    │   ← "Does this actor hold a valid capability proof for this resource?"
   └───────────────┘
       ↓
   Permit or Deny
       ↓
[Any IO target]
```

The decision-maker can be:
- An LLM agent (today)
- A planner-executor pair (likely soon)
- A goal-driven AGI subagent (later)
- A human typing a command
- A scheduled cron job
- Another machine in a federation

The IO target can be:
- A filesystem, database, API endpoint
- A network connection, a credential read
- A robot actuator
- Another agent's tool surface
- Anything that mutates real-world state

**The middle box is what authgate sells.** It does not care who made the decision.
It does not care what executes the IO. It cares whether the actor held a valid,
non-revoked, sufficiently-scoped capability proof at the moment of execution.

---

## What authgate IS NOT

| Not this | Why it matters |
|---------|---------------|
| A LangChain plugin | LangChain may not exist in 5 years |
| An OpenAI Agents SDK adapter | The SDK API will change |
| A CrewAI integration | Same risk |
| An MCP server | MCP is a protocol, not a substrate |
| A model-specific tool | Models change every quarter |
| A framework-specific feature | Frameworks are short-lived |

These are **conveniences**, not the product.

The actual product is the `CanonicalAction` wire format + the `verify()`
function. Everything else is glue.

---

## The contract is the wire format

The thing external systems must implement to use authgate is documented in:

| Schema | What it is |
|--------|-----------|
| `spec/canonical_action.schema.json` | The action you submit |
| `spec/gate_result.schema.json` | The decision you receive |
| `spec/audit_entry.schema.json` | The forensic record |

Any system that can produce a `CanonicalAction` JSON and consume a
`GateResult` JSON has integrated with authgate. **No framework dependency
exists at this layer.**

If LangChain disappears tomorrow, the wire format works. If OpenAI changes
their SDK, the wire format works. If a brand-new agent framework appears
in 2028, it integrates by producing the same JSON.

This is the contract that survives.

---

## Why the framing matters

Two ways to die:

### Death by framework binding
"AuthGate is the security layer for [framework X]."
→ When framework X dies or changes, authgate dies or breaks.

### Death by model binding
"AuthGate works with [model family Y]."
→ When models change architecture, authgate looks legacy.

One way to survive:

### Survival by abstraction at the right layer
"AuthGate verifies authority between any decision and any IO."
→ When frameworks change, the contract holds. When models change, the
   contract holds. When AGI arrives, the contract holds more strongly
   because the question "does this actor hold authority?" becomes more
   urgent, not less.

---

## The architect's question, re-stated

> "What does AuthGate actually protect against?"

Not GPT. Not Claude. Not LangChain.

It protects this:

```
Decision  →  Action  →  Real-world IO
```

Any architecture with that chain needs something like AuthGate at the arrow.
The chain exists today. The chain will exist in 5 years. The chain will exist
in 10 years.

What changes:
- WHO is at the decision step (model → agent → AGI subagent → swarm)
- WHAT is at the IO step (function call → API → robot → economic contract)

What stays:
- The arrow needs a gate
- The gate must answer: "Does this actor hold a valid capability proof?"
- The gate must answer it structurally, not probabilistically

That answer is what authgate sells. Forever.

---

## How positioning shapes daily decisions

| Question that comes up | Old (framework-bound) answer | New (Decision↔IO) answer |
|----------------------|------------------------------|--------------------------|
| Should we add LangChain v0.3 compatibility? | YES, immediately | YES — but as an adapter, not as project identity |
| Should we add support for [new framework Y]? | YES, urgently | Optional — `CanonicalAction` is the real contract |
| Should we tie our test suite to OpenAI SDK quirks? | Maybe | NO — test the contract, not the convenience |
| Should our README headline list adapters? | Yes, prominently | NO — lead with the wire format |
| Should we deprecate adapter A when framework A dies? | Yes | Yes, without any project-identity impact |
| Should we add a "model trust score" feature? | Possibly | NO — model-bound concept; out of scope |
| Should we add capability federation for distributed agents? | Maybe later | YES — but slowly, after Phase 1 lessons |

---

## The decade horizon

In 10 years, one of three things is true:

### A. authgate is the standard authority-proof format for agents
Every agent runtime, every framework, every cloud — they all produce
`CanonicalAction` (or its successor) and consume the verify decision.
The thing is invisible. Like TLS. Like seccomp. Like OAuth.

### B. authgate became part of a larger standard
A consortium picked something equivalent. The work is folded in. The
contributors are credited. The wire format influences the eventual standard.
Not a failure — an absorption.

### C. The capability primitive turned out to be wrong
A successor primitive (economic staking, reputation, consensus) replaced it.
The work was wrong but the rigor wasn't wasted. (See DEATH_SCENARIOS.md.)

Only outcome C is failure. A and B both succeed.

To make A or B more likely than C, the project must stay positioned as
"the authority layer," not as "the LangChain plugin."

---

## When in doubt

Ask: "Will this decision still be true if LangChain doesn't exist?"

- If yes → make the decision.
- If no → it's a framework-coupling decision. Put it in an adapter, not the core.

Ask: "Will this decision still be true if the dominant agent architecture
is one we haven't imagined yet?"

- If yes → make the decision.
- If no → it's architecture-coupling. Defer or isolate.

---

## What this positioning rules out

| Rejected work | Why |
|--------------|-----|
| Custom features for one framework's idiosyncrasy | Couples to short-lived API |
| "Model-aware" authorization heuristics | Couples to model behavior |
| Framework-specific test suites that block builds | Tests the convenience, not the contract |
| Marketing copy that leads with framework names | Trains users to think of us as a plugin |
| Roadmap items framed as "support framework X" | Hides the underlying capability |

What it permits (and encourages):

| Encouraged work | Why |
|----------------|-----|
| Better `CanonicalAction` JSON Schema docs | The contract |
| More test coverage of the wire format | The contract |
| Independent reviewers exercising the wire format | Validates the contract |
| Adapters for popular frameworks | Reduces friction (but never load-bearing) |
| Removing tight coupling that exists today | Long-term durability |

---

*Updated: 2026-05-30. This is the project's constitutional layer.
Any change to the identity stated here requires explicit re-positioning
discussion. Otherwise: defer to this file.*
