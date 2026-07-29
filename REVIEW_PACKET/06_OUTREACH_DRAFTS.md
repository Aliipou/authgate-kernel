# Wave 1 outreach drafts

Written 2026-07-29. Every draft is short on purpose. A researcher decides whether to
reply in the first three lines, and a long email reads as someone who wants attention
rather than a specific answer.

## Rules used in all of them

1. **Name one thing of theirs**, accurately, and say why it makes them the right
   reader. No flattery.
2. **Ask for one specific thing to break.** "What do you think?" gets nothing.
3. **Disclose the two admitted Lean steps and the unreproduced table before they ask.**
   This is what makes it credible to send now rather than after the toolchain works:
   you are not claiming verification, you are handing them a checkable list.
4. **No attachments.** One link to the tagged commit.
5. Signature is the same everywhere, three lines, no title inflation.

## ⚠ Verify before sending

The paper titles, author names and venues below come from the research brief, not from
my own check. **Confirm each one against the actual PDF before sending**, and take the
email address from the paper itself. An email that misattributes someone's work is
worse than no email. Items to confirm: the EPFL capability-tracking paper and its
author list, the CaMeL authorship, the SAGA/NDSS paper, the ChainCaps workshop paper.

---

## 1. EPFL, capability tracking group

**To:** address from the paper PDF (Yichen Xu or Oliver Bračevac, not Odersky)
**Subject:** Runtime counterpart to your capability tracking, one invariant I would like broken

> Hello,
>
> Your work on tracking capabilities for agent safety enforces at the type level what
> I have been enforcing at runtime, and I think that makes you the right person to
> find the hole in mine.
>
> AuthGate is a capability kernel that gates tool execution on an Ed25519 delegation
> chain, with epoch-based revocation and a hash-chained audit log. Where your approach
> proves an agent cannot express a forbidden effect, mine assumes the agent can express
> anything and refuses to execute it. The interesting question is whether the runtime
> version buys anything your static version does not already give, or whether it is
> strictly weaker.
>
> The invariant I would most like you to attack is attenuation: rights decrease
> monotonically along a delegation chain, with no path that re-widens them. It is
> stated in TLA+ as `Attenuation` and there are Kani harnesses for the sequence case.
>
> Honest status: the Lean development admits one step pending code-to-spec
> correspondence, and I have not re-run the verification on a clean machine, so the
> status table lists everything as unreproduced. That table is the first thing in the
> packet.
>
> [LINK]
>
> Ali Pourrahim

---

## 2. Cambridge / CHERI orbit

**To:** a postdoc in the group, or Capabilities Limited
**Subject:** Does a software capability chain give the attenuation guarantees CHERI enforces in hardware?

> Hello,
>
> CHERI enforces attenuation and provenance in hardware. I have built the same
> discipline in software for AI agent tool calls, and I would like to know where that
> substitution fails.
>
> AuthGate validates an Ed25519 delegation chain before any tool executes: expiry,
> epoch, resource binding, monotonic attenuation. No hardware assumptions. The obvious
> objection is that a software chain can be bypassed by anything already inside the
> address space, which is exactly the class CHERI closes and I cannot.
>
> The specific question: is there an attenuation or revocation attack that hardware
> capabilities defeat and a signed-chain design cannot, even in principle? If the
> answer is yes and it is fundamental, I would rather learn it now and scope the claim
> accordingly.
>
> Status is stated plainly in the packet: ten TLA+ invariants declared, thirteen Kani
> harnesses written, none of it reproduced on a clean machine yet, one admitted Lean
> step on code-to-spec correspondence.
>
> [LINK]
>
> Ali Pourrahim

---

## 3. Kani, GitHub Discussions

**Post, not an email. Highest reply probability of anything in Wave 1.**

**Title:** Do these harnesses prove the invariant, or only a bounded check?

> I have thirteen Kani harnesses over a capability kernel and I want to know whether I
> am claiming more than they establish.
>
> Representative ones: `prop_permitted_implies_no_violations`,
> `prop_seq_accumulated_monotone`, `prop_delegation_denied_without_delegate_claim`.
>
> Two things I am unsure about. First, the unwind bounds: a delegation chain is
> unbounded in principle, so a proof at a fixed unwind says nothing about longer
> chains, and I would like to know the accepted way to state that limitation without
> overclaiming. Second, whether stubbing the signature verification turns these into
> proofs about a model rather than about the code.
>
> Harnesses and the spec are here: [LINK]

---

## 4. ETH, agent security

**Subject:** Does an authority layer reduce prompt injection to a blast-radius problem?

> Hello,
>
> Your work argues that architecture, not detection, is what contains prompt injection.
> I built an authority layer on that premise and I would like to know whether it
> actually holds.
>
> AuthGate refuses any tool call not backed by a signed capability for that exact
> resource. A successful injection can therefore make the agent try anything, and
> should still fail to execute anything outside the capability it already holds. My
> claim is that injection becomes a blast-radius question rather than a prevention
> question.
>
> The scenario I want you to break: an injected instruction that causes a legitimately
> held capability to be spent on an attacker-chosen action within its scope. I believe
> that one succeeds against my design, and I would like to know if it is the worst case
> or merely the first case.
>
> Verification status is unreproduced and stated as such in the packet.
>
> [LINK]
>
> Ali Pourrahim

---

## 5. Verus Zulip and TLA+ forum

**Subject:** Composing two independent gates as one theorem

> I have two enforcement layers, a legitimacy gate that can only deny and an authority
> gate that grants capability, and I want to state and check one property: no action
> executes unless both admit it.
>
> Right now they are separate TLA+ invariants, and the composition is an English
> sentence in a README rather than a theorem. Is `PermitSoundness` over the composed
> state machine the right formulation, or should the composition be stated as a
> refinement between two specs? And for the Rust side, is this a case where Verus buys
> something Kani cannot, given the property is about all execution paths rather than a
> bounded input space?
>
> Spec and config: [LINK]

---

## 6. SAGA authors, differentiation

**Subject:** Where AuthGate differs from SAGA's token model, and where it does not

> Hello,
>
> Your architecture uses cryptographic access-control tokens to govern agent-to-agent
> interaction. My kernel uses one-time capability tokens to govern agent-to-tool
> execution, which makes your work the nearest neighbour to mine and the first thing a
> reviewer will raise.
>
> My reading of the difference: SAGA governs which agents may interact, AuthGate
> governs whether a specific action may execute, with attenuation along a delegation
> chain and epoch revocation. If that reading is wrong, I would rather be corrected now
> than in review.
>
> The concrete ask: is there a case your token model handles that a per-action
> capability chain does not, and would you consider the composition of the two a
> meaningful contribution or a restatement?
>
> [LINK]
>
> Ali Pourrahim

---

## 7. Finland: Aalto Secure Systems, University of Helsinki, VTT

**Different ask. Not review, affiliation.** Send after at least one of 1 to 6 replies.

**Subject:** Capability kernel for agent execution, looking for a research home in Helsinki

> Hello,
>
> I finished a B.Eng. in Information Technology at Centria in March 2026 and I have
> spent the last year building a capability-security kernel for autonomous agents:
> Ed25519 delegation chains, epoch revocation, a hash-chained audit log, a TLA+ model
> with ten invariants and a Lean development with one admitted step.
>
> I am writing for two reasons. The first is a research question I cannot answer alone:
> whether authority and legitimacy are genuinely independent preconditions for
> execution, or whether the second reduces to policy over the first. The second is
> practical. I hold a UAS bachelor's, so a doctoral position is not open to me yet, and
> I am looking for the route in: a master's, a research assistant position, or a
> project that needs someone who writes both Rust and Lean.
>
> Would you be willing to tell me whether this question is worth pursuing, and if so
> where it belongs?
>
> [LINK]
>
> Ali Pourrahim

---

## 8. Anthropic

**Subject:** Capability kernel for tool execution, offering it as an adversarial target

> Hello,
>
> I built a capability-security kernel that sits between an agent's decision and its
> tool execution: no tool call runs without a signed, attenuated, revocable capability
> for that exact resource, and every decision lands in a hash-chained audit log. There
> are adapters for several agent frameworks, including yours.
>
> I am not pitching a product. I am asking whether the model survives contact with
> people who run agent tooling at scale. The specific claim to attack: a compromised
> agent, including one under a successful prompt injection, cannot execute an action
> outside the capabilities it already holds, and cannot re-widen rights through
> delegation.
>
> Everything is stated with its limits: ten TLA+ invariants declared and not yet
> model-checked on a clean machine, thirteen Kani harnesses whose unwind bounds are not
> yet published, one admitted Lean step on code-to-spec correspondence.
>
> If there is a better channel for this than a cold email, I would appreciate being
> pointed at it.
>
> [LINK]
>
> Ali Pourrahim

---

## 9. xAI

**Read this first.** A cold email to Elon Musk has, realistically, no chance of being
read, and sending one costs you the option of a serious approach later. The version
below goes to an engineer who works on agent infrastructure, found through their own
public writing. If you want the direct version anyway, send exactly this text to the
public address and treat it as a lottery ticket, not a plan.

**Subject:** Execution-time authority for tool-using agents, looking for someone to break it

> Hello,
>
> If you are running tool-using agents in production, the question that eventually
> arrives is what stops one from doing something irreversible. I built an answer and I
> would like it attacked.
>
> A capability kernel sits between decision and execution. Every tool call needs a
> signed capability for that exact resource, rights only ever narrow along a delegation
> chain, revocation is epoch-based, and the audit log is hash-chained so tampering is
> detectable after the fact.
>
> It is Rust, the trusted computing base is about 255 lines, and the formal claims are
> published with their gaps rather than without them.
>
> If it is useful, take it. If it is broken, I would rather hear that from you than
> find out later.
>
> [LINK]
>
> Ali Pourrahim

---

## 10. LinkedIn post

Post this **after** the repo is public and tagged, not before.

> I have spent the last year on a question that turns out to be harder than it sounds:
> what stops an AI agent from doing something irreversible?
>
> Not detecting bad intent. Not scoring outputs. Refusing execution.
>
> AuthGate is a capability-security kernel that sits between an agent's decision and
> its tool call. Every action needs a cryptographically signed capability for that
> exact resource. Rights only narrow when delegated, never widen. Revocation is
> epoch-based. Every decision lands in a hash-chained audit log, so tampering is
> detectable after the fact. The trusted computing base is about 255 lines of Rust with
> unsafe code forbidden.
>
> Today I published the review packet, and it opens with a table of what has NOT been
> verified: ten TLA+ invariants declared but not model-checked on a clean machine,
> thirteen Kani harnesses whose unwind bounds are not yet published, one admitted step
> in the Lean development where the model has not been shown to correspond to the code.
>
> That table is the point. Anyone can write "formally verified" in a README. What is
> useful is a list a stranger can check, one line at a time.
>
> If you work on capability security, formal methods, or agent infrastructure, I am
> looking for people to break it. Link in the comments.

**Why the negative framing works:** every other agent-security post claims more than it
can show. A post that leads with its own unverified list is the only one a researcher
will trust, and researchers are the audience you want.

---

## Sending order

| Day | Send | Why |
|---|---|---|
| 1 | 3 (Kani), 5 (Verus/TLA+) | Community channels, low risk, and their answers improve the packet before any researcher sees it |
| 3 | 1 (EPFL) | The nearest technical neighbour |
| 3 | 4 (ETH) | Independent of 1, so a silence on one is not a silence on both |
| 7 | 2 (Cambridge), 6 (SAGA) | After the first replies have improved the framing |
| 10 | 8 (Anthropic), 9 (xAI) | Industry, once the packet has survived at least one researcher |
| 14 | 7 (Finland) | Affiliation ask, strongest once someone external has engaged |
| — | 10 (LinkedIn) | Same day as the repo goes public |

One follow-up each, ten working days later, three lines. Then stop.
