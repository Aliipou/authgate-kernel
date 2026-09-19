# Community channels: where to post, and what to post

Researched 2026-07-29, every route verified against its own site.

**The strategic point:** cold-emailing professors has a low reply rate and a slow clock.
Open mailing lists, GitHub discussions and working groups have neither problem, and the
people in them are the same people. Everything below is a channel an outsider can post
to today without an introduction.

Order of effort, highest value first.

---

## 1. Cedar, and why it must be answered before anything else

**This is the most important finding in the research.** Cedar is an AWS authorization
engine written in **Rust**, with a **Lean** formal specification, machine-checked
proofs, verification-guided development and differential testing against the Lean
model. It is now a CNCF Sandbox project, so governance is vendor-neutral.

Read that again: someone has already done verification-guided development of an
authorization engine in Rust with Lean proofs, at scale, with a paper about the
methodology (*How We Built Cedar: A Verification-Guided Approach*, arXiv:2407.01688).

Every reviewer, every professor and every workshop referee will ask **"how is this
different from Cedar?"** There is currently no answer to that in this repository, and
that gap matters more than the unreproduced verification table.

The honest differentiation, as far as I can tell, is:

| | Cedar | AuthGate |
|---|---|---|
| Decides | whether a policy permits a request | whether a signed capability authorises this action |
| Trust model | policy evaluated by a trusted engine | capability chain cryptographically verified, no trusted evaluator |
| Delegation | policy-expressed | monotonic attenuation along a signed chain |
| Revocation | policy update | epoch-based, no revocation list |
| Audit | logging | hash-chained, tamper-evident |

That table is a hypothesis, not a result. Verifying it is the first task.

**Route in:** an issue or discussion on https://github.com/cedar-policy/cedar-spec

> **Title:** Does the Cedar model admit monotonic attenuation as a provable property?
>
> I have been building a capability kernel for AI agent tool execution: signed
> delegation chains, epoch revocation, a hash-chained audit log, TLA+ and Lean.
> Reading cedar-spec, the obvious question is whether I have rebuilt something you
> already prove.
>
> Specifically: can Cedar's model state and prove that rights decrease monotonically
> along a delegation path, with no path that re-widens them? In my model that is an
> invariant over the chain rather than a property of a policy set, and I cannot tell
> from the Lean spec whether the two are equivalent or genuinely different.
>
> If they are equivalent, I would rather learn it here than at a review.

The Automated Reasoning Group people who wrote the Lean spec are active in that repo.
This single question is worth more than five professor emails.

---

## 2. IETF WIMSE working group

Chartered on *"fine-grained, least privilege access control for workloads deployed
across multiple service platforms."* Active drafts include a workload proof token.
They liaise with OAuth, RATS, SCITT, CNCF/SPIFFE and the OpenID Foundation.

- List: https://www.ietf.org/mailman/listinfo/wimse
- Archive: https://mailarchive.ietf.org/arch/browse/wimse/
- Charter: https://datatracker.ietf.org/wg/wimse/about/

**Read the archive for a week before posting.** Then:

> **Subject:** Monotonic attenuation and epoch revocation in workload delegation chains
>
> I have an open-source implementation of delegation-chain authorisation that may be
> relevant to the workload credential drafts: Ed25519-signed chains where rights
> attenuate monotonically, revocation is epoch-based rather than list-based, and every
> decision lands in a hash-chained log. Roughly 255 lines of Rust in the trusted
> computing base, with a TLA+ model and Lean proofs.
>
> Two questions for the group:
>
> 1. Is attenuation monotonicity something the WIMSE architecture wants stated as a
>    protocol invariant, or is it deliberately left to implementations?
> 2. Epoch-based revocation avoids distributing revocation lists at the cost of a
>    bounded staleness window. Is that trade-off acceptable in the multi-system model
>    the charter describes?
>
> Implementation and the formal artifacts are public, including a status table of what
> has and has not been machine-checked.

---

## 3. IETF OAuth: the AI-agent delegation drafts

There are live individual drafts on precisely this problem:

- `draft-oauth-ai-agents-on-behalf-of-user`
- `draft-klrc-aiagent-auth` (deals with delegation chain splicing attacks)
- `draft-nelson-agent-delegation-receipts` (cryptographic delegation receipts)
- `draft-prakash-aip` (agent identity protocol)

**None of them has a monotonic-attenuation proof, epoch revocation, or a hash-chained
audit trail.** That is a precise, defensible gap to fill, and individual-draft authors
are usually glad of cryptographic review.

Route: oauth@ietf.org, replying on-thread to a specific draft. Author contact details
are published on each datatracker page. Do not construct addresses.

---

## 4. CrewAI discussion #3235: someone is asking for exactly this

https://github.com/crewAIInc/crewAI/discussions/3235 — "Auth and Permissions Delegation
Layer for CrewAI Agents". An open request for an `AuthProvider` interface in the
tool-execution path that checks agent capability before any tool call and returns a
structured denial.

This is the most concrete "we want this, please build it" evidence anywhere in the
research, and it costs one comment.

> I have an implementation of roughly this. AuthGate is a capability kernel that gates
> tool execution: every call must present a signed capability bound to that exact
> resource, rights attenuate when delegated and never widen, revocation is epoch-based,
> and denials are structured rather than exceptions. There is already a CrewAI adapter.
>
> Two design questions before I propose anything concrete: should the check sit in the
> tool-execution path or one layer up at the agent boundary, and would you want denial
> to be a return value or a raised error?
>
> Happy to open a PR against a specific interface shape if there is appetite for it.

---

## 5. OpenSSF AI/ML Security WG, SAFE-MCP SIG

SAFE-MCP is an ATT&CK-style catalogue of 80+ attack techniques against tool-using LLMs,
explicitly covering tool permission abuse. They catalogue the attacks and **lack a
concrete mitigation implementation**, which is what this kernel is.

- Repo: https://github.com/ossf/ai-ml-security
- List: openssf-wg-ai-ml-security@lists.openssf.org
- Slack: `#wg-ai-ml-security`, bi-weekly call on the OpenSSF public calendar

Join a call before posting. Offer the kernel as a mapped mitigation against named
SAFE-MCP techniques, which is a contribution they can actually merge.

---

## 6. Worth doing, lower priority

| Target | Why | Route |
|---|---|---|
| SPIFFE/SPIRE | Workload identity is the layer below delegation chains. Active 2026 work on SPIFFE identity for AI agents | CNCF Slack, monthly community meeting |
| Cătălin Hrițcu, MPI-SP | Best pure-academic match found: secure compilation, compartmentalisation, reference monitors, small verified TCBs | https://catalin-hritcu.github.io/group.html |
| Inria Prosecco / Aeneas | Aeneas verifies Rust in **Lean**. If your Lean proofs are meant to cover Rust code, this is the tooling | https://team.inria.fr/prosecco/ |
| MPI-SWS, RustBelt/Iris | The foundational soundness argument for a Rust TCB with `unsafe` boundaries | https://plv.mpi-sws.org/rustbelt/ |
| CISPA, Cas Cremers | Your delegation chain is a protocol, and protocols are what Tamarin proves | https://cispa.de/en/research/research-groups |
| Cloudflare Code Mode | Capability-style sandboxing without capability formalism. Real intellectual overlap | GitHub issues on `cloudflare/agents` |
| Cerbos, Permit.io | Both publish on MCP authorisation, both small and responsive | their community Slack/Discord |
| MCP SEP process | MCP is where tool calls actually happen. Now under Linux Foundation governance, so contributing is not vendor outreach | https://github.com/modelcontextprotocol/modelcontextprotocol |
| OpenID AIIM, Threat Modelling subgroup | Filed the OIDF response to NIST on agent security | requires signing a participation agreement first |

---

## 7. Checked and found nothing: do not spend time here

Oxford (security activity is legacy protocol verification; OXCAV is control-theoretic
safe AI, not capabilities), Imperial College, TU Delft (both cybersecurity and PL
groups), IMDEA Software, TU Munich, the Alan Turing Institute (policy and RL-based
cyber defence, not systems verification), Chainguard (supply chain, not runtime
enforcement), Browserbase, and the sandbox providers E2B, Modal and Daytona, which
compete on cold-start time rather than authorisation semantics.

Each of these was checked against its own research pages. Skipping them is a finding,
not an omission.

---

## 8. One framing rule

For academic and standards audiences, lead with the **255-line verified TCB and the
formal artifacts**, not with AI agents. The agent framing is what gets you filed under
hype by systems and verification people; the small verified kernel is what gets you
read. Invert it only for the industry channels.
