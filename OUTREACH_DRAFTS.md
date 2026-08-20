# Outreach drafts — researchers, OIDF/AuthZEN, endorsers

**Status:** drafts for human send. Do not auto-send. Fill `[brackets]` before use.  
**Updated:** 2026-08-20

---

## 1. Keijo Heljanko — generality / Zoom

**Subject:** AuthGate — answering your generality question + Zoom

Dear Keijo,

Thank you for the question about whether AuthGate’s results are only valid inside
its own scenarios. Short answer: the *security* claim we still defend is not the
ownership ontology; it is an executable conformance profile for agent tool-call
PEPs (AE-1…AE-10) under deny-dominant composition and non-amplification. That claim
is measured by a driver suite any second implementation can fail.

What we falsified (on purpose): “legitimacy derived from ownership/consent uniquely
discriminates vs Cedar/OPA/purpose baselines.” Details are in the attached
REVIEW_PACKET and ASSUMPTIONS table.

I would be glad to take the Zoom call you suggested. My availability in EEST:
`[windows]`. Packet: `[link to REVIEW_PACKET on GitHub]`.

Best regards,  
Ali Pourrahim

**Also note his pointers (to acknowledge in a follow-up):** Byron Cook / AWS,
Bedrock AgentCore guardrails, Dogwood temporal policy language — we treat these as
neighbouring industrial work, not rivals to reinvent.

---

## 2. Sophia Drossopoulou — authority/legitimacy (+ cc list)

**Subject:** Re: authority vs legitimacy — AuthGate/FDK + OOPSLA 2025 pointer

Dear Sophia,

Thank you for pressing on authority vs legitimacy. We now keep them as **co-equal
evaluators** under a lattice meet: legitimacy is veto-only and cannot grant; order
carries no semantics. The Theory of Freedom is retained as optional normative
lineage, not as the industrial claim (decision memo attached).

I am reading the OOPSLA 2025 paper you pointed to before a fuller technical reply;
this note is to confirm the architectural move and to invite critique of the
AE profile + ASSUMPTIONS table.

Copying James Noble, Susan Eisenbach, Julian (Kry10), and Mark Miller as you
suggested.

Best regards,  
Ali

**Attachment checklist:** REVIEW_PACKET, FREEDOM_THEORY_POSITION, CLAIM.md  
**Todo before send:** finish OOPSLA 2025 reading notes in `outreach/notes-oopsla2025.md`.

---

## 3. Ralf Jung — TCB / INCOMPLETENESS

**Subject:** AuthGate TCB framing — request for pushback on INCOMPLETENESS.md

Dear Ralf,

Following Andrew Appel’s thread, I would value your critique of our TCB boundary
write-up (`formal/INCOMPLETENESS.md`) and ASSUMPTIONS.md: Rust TCB vs Python
compatibility layer, Kani as bounded checking, and the explicit Ed25519 axiom
(unverified `cryptography` / non-HACL* runtime).

Specifically: where would a careful reader over-read our guarantees?

Best regards,  
Ali

---

## 4. Robbert Krebbers / Lennard Gächter — Iris / RefinedRust

**Subject:** RefinedRust maturity for an authority PEP — intro request

Dear Robbert,

Thank you for the Iris/RefinedRust pointer. Per your estimate (~1–1.5 years in an
experienced team), I am treating a RefinedRust port as PhD-scale, not a sprint.
With your permission I would contact Lennard Gächter for a candid maturity read,
and I am also surveying iris-lean as an alternative.

Packet: REVIEW_PACKET + ASSUMPTIONS (Ed25519 axiom explicit).

Best regards,  
Ali

---

## 5. Bryan Parno — Verus vs Kani wording

**Subject:** Correcting our Kani/Verus description

Dear Bryan,

Thank you for the correction. We now state Kani results as **bounded model
checking** and reserve “guarantees for arbitrary executions” for Verus-class
proofs we do not yet have. The wording is locked in ASSUMPTIONS.md. If you see
remaining overclaim in the REVIEW_PACKET, I would be grateful for a red pen.

Best regards,  
Ali

---

## 6. Hongjin Liang — observational refinement / rely-guarantee

**Subject:** Contextual refinement for multi-agent authority composition

Dear Hongjin,

Thank you for the pointers to observational/contextual refinement and
rely-guarantee / CSL (including Murray et al., CSF 2016). Our near-term formal
path is: pick one axiom (candidate: no use of undelegated authority), prove in
the model, then target contextual refinement for interfering agents. I would
welcome a sanity check on that order before we invest.

Best regards,  
Ali

---

## 7. Bruno Blanchet path — Squirrel team

**Subject:** Key reuse in delegation + audit — Squirrel after Tamarin?

Dear `[Baelde / Koutsos / Delaune]`,

Bruno Blanchet suggested Squirrel (not CryptoVerif) for our setting, with
symbolic-first order (Tamarin → computational). The open problem is key reuse
across a delegation chain that also feeds a tamper-evident audit log. ASSUMPTIONS
currently axiomatize Ed25519 EUF-CMA. Would you be open to a short design review
of the protocol sketch before we invest in models?

Best regards,  
Ali

---

## 8. OIDF participation agreement + AuthZEN list

### 8a. Resubmit OIDF contribution agreement

- Full legal name: `[Given + ALL family names]`
- Full postal address: `[street, city, postal code, country]`
- Prior form voided by Mike Leszcz — resubmit cleanly; keep PDF + send date log.

### 8b. AuthZEN mailing list post (after countersignature) — Atul’s invite

**Subject:** [AuthZEN] Agent tool-call PEP profile — attenuation + veto-only composition

Hello,

Following Atul’s invitation: we have an executable Authority Enforcement profile
(AE-1…AE-10) aimed at AI-agent tool calls — deny-dominant composition of an
authority verdict with untrusted constraint evaluators, macaroon-style attenuation,
action-content binding, one-time tokens, audit fidelity. We claim **no new security
principle**; the point is measurability for this setting.

We are standardizing the *wire* on MCP and looking to AuthZEN for authZ vocabulary
alignment — not proposing a competing RFC yet.

Links: `[REVIEW_PACKET]`, `[PROFILE]`, `[conformance suite]`.  
Happy to present on a WG call.

Ali Pourrahim

---

## 9. Target reviewer waves (private before public)

| Wave | People | Goal |
|---|---|---|
| 0 | Heljanko, Drossopoulou (+cc), Jung, Parno | Close open threads; fix overclaims |
| 1 | Krebbers → Gächter; Blanchet → Squirrel; Liang | Formal path realism |
| 2 | Watson (Capsicum/CHERI), Klein/Andronick (seL4), Miller | Capability novelty check with final packet |
| 3 | AuthZEN list + MCP adapter users | Industrial signal |
| 4 | Public (arXiv / broader) | Only after ASSUMPTIONS-stable packet |

EPFL-shaped evaluation: prefer reviewers who will try to **kill** the claim.

---

## 10. Publication track notes

- **TLC** on `authgate-kernel` AuthGateV3: prerequisite for second publication nomination.
- **cascade-conformal arXiv (cs.LG/stat.ML):** still needs endorser — follow up Kotte (Adobe/PASC) and Zhang/Amin/Perakis (MIT ORC).
- **10-week axiom-to-code engineering plan:** keep as separate schedule; do not block REVIEW_PACKET on it.
