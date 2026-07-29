# Read this first

**For:** capability-security researchers, formal methods practitioners, agent
infrastructure engineers.
**Ask:** break one specific invariant. Not "what do you think".
**Time to a useful opinion:** two hours. This document is arranged to make that
possible.

## 1. The research claim, in one paragraph

Existing autonomous systems lack a formally verifiable decision boundary separating
action *proposal* from action *execution*. This project investigates whether
**authority** and **legitimacy** can be modelled as independent, composable predicates
whose conjunction is required before any action executes, and whether that separation
buys anything that a policy engine layered over an object-capability system does not
already provide.

That last clause is the honest part. If the answer is no, this is a well-engineered
restatement of known results and should be described as such. Deciding which it is, is
what this packet is asking you to help with.

## 2. What is actually built

| Layer | What it does | Where |
|---|---|---|
| **AuthGate** | Authority. Gates execution on an Ed25519 delegation chain: expiry, epoch revocation, resource binding, monotonic attenuation | `authgate-kernel/` |
| **FDK** | Legitimacy. A deny-only gate asking whether the action should happen at all, independent of who is asking | composition boundary, see `SEMANTICS.md` |
| **Audit** | Hash-chained log, tampering detectable after the fact | `authgate-kernel/src/` |

Trusted computing base is roughly 255 lines of Rust with `#![forbid(unsafe_code)]`.
Everything else is outside the TCB by construction.

## 3. Where to go, by what you care about

| You work on | Read | Then attack |
|---|---|---|
| Capability security | `PRIOR_ART.md` (568 lines, Lampson 1974 onward), `SEMANTICS.md` | `Attenuation`: can rights re-widen along any path? |
| Formal methods | `04_FORMAL_VERIFICATION_STATUS.md`, `formal/` | The two admitted Lean steps, and the unwind bounds |
| Agent security | `THREAT_MODEL.md`, `EXTERNAL_REVIEW_PACKAGE.md` | Injection that spends a legitimately held capability |
| Systems | `ARCHITECTURE.md`, `TCB.md`, `NON_GOALS.md` | Anything reachable that bypasses `CallGate` |

`EXTERNAL_REVIEW_PACKAGE.md` in the repo root predates this packet and remains the
fuller scoping document, including what is deliberately out of scope. This packet does
not replace it; it adds the verification status that was missing.

## 4. What is not claimed

Read this before deciding the project overstates itself, because most of the obvious
objections are already conceded in writing:

- **Covert channels are not addressed.** `PRIOR_ART.md` grounds this in Lampson's 1974
  confinement paper and states plainly that no deployed capability system has solved
  it. Not a gap unique to this kernel, and not fixed by it.
- **The verification is not reproduced.** See `04`. Ten TLA+ invariants are declared,
  thirteen Kani harnesses are written, and on 2026-07-29 none of them were re-run on a
  clean machine. Every cell in that table says so.
- **One Lean step is admitted pending code-to-spec correspondence.** The Lean model has
  not been shown to correspond to the Rust implementation. This is the weakest joint in
  the whole structure and it is stated here rather than left to be discovered.
- **Cryptographic properties are axioms** reducible to Ed25519 security. Standard, but
  say it out loud.
- Semantic intent, ethics and alignment are explicitly out of scope. The kernel does
  not parse text.

## 5. Known documentation defects

Being specific about our own mess, so you do not waste review time on it:

- **73 occurrences of "freedom-kernel" across 12+ markdown files.** The project was
  renamed to authgate-kernel and the rename is incomplete, including inside
  `PRIOR_ART.md` and `AXIOMATIC_FOUNDATION.md`. Same system, older name. This is
  cosmetic, but it will make you wonder whether you are reading about two projects.
- Kani unwind bounds and stubs are not published per harness, which makes the current
  Kani claims unfalsifiable as stated. Fixing this is the top priority.

## 6. The research programme, if you are reading this as a potential collaborator

The kernel is one component. The open questions that outlive it:

1. Can authority be given a formal calculus independent of any policy language?
2. Can legitimacy be defined so it does not collapse into policy over authority?
3. Is the conjunction composable, and provably so, across independently written gates?
4. Does the separation survive distribution and multiple issuers?
5. What is the runtime cost against OPA, Cedar, and a plain capability system?

Question 2 is the one the whole framing stands or falls on, and it is the one I most
want an outside opinion on. Question 5 is unanswered and needs a benchmark, not an
argument.

## 7. How to report a finding

Open an issue using the security-review-finding template: setup, steps, which invariant
you violated, and why the defence fails. Findings against a tagged commit are worth
more than findings against a moving `HEAD`; use the review tag.

Acknowledgement in the repository for anything that lands. If you would rather not be
named, say so and you will not be.
