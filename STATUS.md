# AuthGate status — disposition (2026-06-20)

Same discipline applied to FDK, applied here: kill the idea first; keep only what survives. Three
kill-tests were run (`WHY_NOT_OPA.md`, `WHY_NOT_DLP.md`, `LABEL_PROPAGATION.md`). This is where
AuthGate honestly stands.

## What collapsed

- **Authorization.** OPA / Cedar (formally verified) / Zanzibar (ReBAC, native revocation) / ABAC
  already solve "is this actor allowed to do this?" AuthGate is **not** a better authorization
  engine, and should not be pitched as one. (`WHY_NOT_OPA.md`)
- **Revocation, relationship graphs, purpose-at-request-time** — all expressible in the incumbents.

## The one surviving thesis

> **Authorization ≠ Purpose Control.**
> OPA/Cedar/Zanzibar ask *"are you allowed?"* The question agents force is different:
> *"for what purpose was this data obtained, and is its current use consistent with that purpose?"*
> That is **information-flow / purpose governance for autonomous agents** — a real, new, 2026
> problem (validated by frontier work: DeepMind CaMeL, dual-LLM, agent taint-tracking), not a
> settled one. It is the only thread here that survived every kill-test.

**Reframed positioning (industrial, legible):** *Runtime purpose-bound data governance for AI
agents.* Not "a new authorization model" — an enforcement layer that binds data use to the
purpose it was obtained under, **independently of whether the model itself can be trusted to.**

**What the real-agent test (`REAL_AGENT_TEST.md`) changed.** The original pitch — *agents leak
PII, AuthGate stops it* — was **falsified on real agents**: capable aligned models self-defend
(0/8 SSN leaks; 5/5 refused under honest framing). But the same models leaked email+phone 2/3 of
the time when the cross-purpose move was **disguised as a formatting task** — a classic *policy-
robustness failure* (behavior depends on framing / prompt / model). So the legitimate question is
no longer *"can the model be trusted?"* but **"can enforcement be made independent of model
behavior?"** — which is exactly what a provenance-based, framing-blind gate provides. That is the
surviving, defensible thesis.

**The next kill-test is no longer technical — it is market.** The real risk is not DLP; it is
*"do companies feel this pain enough to pay, or is **Microsoft Purview + DLP + audit logs** good
enough for them?"* This must be killed or confirmed by customer evidence, not code: find teams
deploying autonomous agents on sensitive data who have *experienced* a framing-robustness leak and
do **not** consider their existing governance stack sufficient. If they don't exist (or Purview
suffices), AuthGate closes like FDK. If they do, there is a product.

## What it reduces to (one buildable, measurable experiment)

The thesis lives or dies on a single technical question (`LABEL_PROPAGATION.md`):

- **Sound, fine-grained label propagation through an LLM — DEAD** (an LLM is not a transparent
  function; this is the FDK mistake in new costume).
- **Coarse, conservative, capability-scoped taint at the CallGate — ALIVE**, but threatened by
  **label-creep** (over-taint → blocks everything → useless).

So the decider is **empirical, not philosophical**: *does coarse capability-taint catch real agent
purpose-violations without over-blocking legitimate work?* High true-positive + tolerable
label-creep → a real Agent-Governance product. Label-creep dominates → DLP with a new name → close.

## Disposition

- **AuthGate authorization** → archived as "absorbed by incumbents."
- **AuthGate + purpose/flow control** → the one open thread. **A 2–4 week sprint, no more:**
  Gate 1 (no code) — three real agent scenarios survive "not output-DLP-catchable" and "not
  PBAC+logging-enough"; Gate 2 (the decider, a *minimal* prototype) — coarse capability-taint on
  the CallGate, run on real agent traces, **measure true-positive vs label-creep.** That number
  decides product-vs-DLP-vs-close.
- If the sprint says no → archive it like FDK and keep the whole body as a **distributed-systems +
  security engineering portfolio** (its 80%+-probability value either way).

## The pattern worth remembering

Across this entire program, ideas **collapsed** wherever they reached toward freedom / consent /
legitimacy / philosophy, and **survived** wherever they reached toward runtime enforcement /
distributed systems / security / capability management / governance. That is the signal: the
advantage is **systems engineering**, not normative theory. Spend energy accordingly.

| Project | Status |
|---|---|
| FDK as a theory | **closed** |
| Lock-in Analytics | **frozen** (needs real migration data) |
| AuthGate authorization | **absorbed by OPA/Cedar/Zanzibar** |
| AuthGate + purpose/flow control | **the one live thread — one experiment from a verdict** |

*Engineering: Ali Pourrahim. Kept honest: "could matter" is not "does matter"; only the label-creep
measurement on real agent traces converts this thesis from plausible to proven — or closes it.*

---

## Addendum — 2026-08-20 (evidence only; disposition unchanged)

The kill-test disposition above stands. Additional artifacts landed for review:

- `ASSUMPTIONS.md` — explicit Ed25519 axiom / proved-vs-open table
- Bounded TLC run of AuthGateV3 — no error found (`formal/tlc_run.log`)
- `REVIEW_PACKET.md`, `CHATGPT_REVIEW_BRIEF.md` — packaging for external readers
- `FREEDOM_THEORY_POSITION.md`, `MCP_STANDARDIZATION.md` — positioning notes (do not alter the STATUS kill-tests)
