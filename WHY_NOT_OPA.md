# Kill-test: does AuthGate solve anything OPA / Cedar / Zanzibar *inherently cannot*?

> Same discipline that closed the FDK theory file, turned on AuthGate. The question is **not**
> "is AuthGate good?" — it is *"why would the world need AuthGate when OPA, Cedar, and Zanzibar
> exist?"* If the honest answer is "it wouldn't," AuthGate gets FDK's fate. This runs the three
> scenarios that are AuthGate's best case and tries to **kill** each by showing an incumbent can
> already do it.

## The incumbents, stated fairly (so the kill is real)

- **OPA / Rego** — a general policy *language + evaluator*. Decides one request at a time from
  the input you give it. Anything expressible as a function of (subject, action, resource,
  context) is expressible in Rego.
- **AWS Cedar** — a *formally verified* authorization policy language (point-in-time
  `is principal P allowed action A on resource R in context C?`).
- **Google Zanzibar (SpiceDB / OpenFGA)** — relationship-based access control; global, consistent
  authorization from relationship tuples; **revocation is native** (delete a tuple).
- **ABAC / XACML** — attribute-based decisions with a PDP/PEP architecture and policy combining.

Common structural fact: **all four are point-in-time authorization deciders.** They answer "is
this single action permitted *now*?" They are *stateless about flow* — they do not, by design,
track what happens to data *after* an allowed read, across requests, over time.

## Scenario 1 — Purpose violation (read authorized; use outside the consented purpose)

**The decision-time version collapses.** "Allow read only for purpose = support" is just a
condition on context: trivially expressible in Rego/Cedar/ABAC (`context.purpose == granted_purpose`).
So *authorizing a request with a declared purpose* is **not** an AuthGate-only capability.

**The flow version is a real gap — but it's IFC, not magic.** The hard case is: data is read for
purpose A (legitimately), then *used* for purpose B (a marketing model, an export). That is a
property of **information flow across requests**, which point-in-time policy engines **inherently
cannot** see — they evaluate the read, not the downstream sink. Enforcing it requires
**information-flow control** (Denning lattices; non-interference), which OPA/Cedar/Zanzibar do
not provide. AuthGate *does* ship an IFC extension (`authgate.extensions`: `NonInterferenceChecker`,
`SecurityLattice`, `IFCViolation`). **So Scenario 1 is the one place AuthGate has a capability the
incumbents structurally lack.**

*Honest caveat:* IFC is a 1970s field, and AuthGate **bundles** a known technique rather than
inventing one. The defensible claim is therefore narrow: *"capability authority **plus**
information-flow/purpose control in one gate,"* not "a new kind of access control." **Verdict:
SURVIVES — narrowly, as IFC+capabilities.**

## Scenario 2 — Revoked consent (access still valid; owner revoked consent)

**Collapses.** Revocation is the thing Zanzibar is *built for*: remove the relationship tuple and
the next check denies, with consistency guarantees (zookies). OPA/Cedar deny on the next eval once
the consent fact leaves the data. The only subtlety — *consent* (the data owner's act) vs.
*permission* (an admin grant) can diverge — is modelled by making consent an **owner-controlled
relationship/attribute** that gates the grant. All three incumbents can express "access requires a
live owner-consent relationship." **Verdict: KILLED — no AuthGate-only capability.**

## Scenario 3 — Delegation provenance (chain valid; root/origin illegitimate)

**Shared-unsolvable — and AuthGate doesn't win it either.** Capability systems and Zanzibar
validate the *chain* (attenuation, signatures, tuples) but **assume the root is legitimate**.
Whether the original grantor had the *real-world right* to grant — the **provenance / ownership-
genesis** question — is not a computable fact inside any access-control system, AuthGate included.
AuthGate's capability DAG checks attenuation and signatures exactly like the others; it cannot
audit whether the root capability *should* have existed, because that needs a trustworthy
consent/ownership graph (the same input problem that sank the FDK product story). **Verdict:
KILLED as a differentiator — it's a real gap, but a *shared* one no one fills.**

## The verdict

| Scenario | Can OPA/Cedar/Zanzibar do it? | AuthGate distinctive? |
|---|---|---|
| 1. Purpose, at decision time | **Yes** (policy on context) | no |
| 1b. Purpose, as **flow over time** | **No** (they're point-in-time) | **YES — via IFC (a known technique it bundles)** |
| 2. Revoked consent | **Yes** (Zanzibar-native / consent-as-relationship) | no |
| 3. Delegation provenance / flawed origin | No — but **nobody** can (shared) | no |

**AuthGate survives the kill-test on exactly one narrow front, and survives it better than FDK
did (FDK had none):** the combination of **capability authority + information-flow/purpose
control**, which point-in-time policy engines (OPA/Cedar/Zanzibar/ABAC) structurally do not
provide. Everything else collapses to "write a policy" or to a problem no one solves.

So the honest one-line answer to *"why AuthGate when OPA/Cedar exist?"* is **not** "a better
authorization engine" (it isn't — Cedar is verified, Zanzibar scales). It is: *"for **usage /
flow / purpose control** layered on capabilities — a different question than authorization, which
the incumbents own."* And even that is a recombination of known techniques (capabilities:
Dennis–Van Horn 1966; IFC: Denning 1976), made usable — the same engineering-value, not
new-science, pattern as the lock-in tool.

## The sprint this implies (2–4 weeks, no new code)

Spend the whole budget on **Scenario 1b**, because it is the only surviving gap:

> **Find three real, current cases where an agent action is *authorized* but *should be blocked
> because of information flow / purpose*, and where OPA/Cedar/Zanzibar provably cannot enforce it
> while capabilities+IFC can.** Candidates: an LLM agent reads PII granted for support, then
> includes it in a marketing email; data consented for *inference* used for *training*; a tool
> granted read on one tenant's data emitting it to another's sink.

For each, the killing question: *can this be handled by "log it + a DLP rule + a database
purpose-column," or does it genuinely need capability-scoped non-interference?* If the three
collapse to DLP/logging, **close AuthGate like FDK**. If they hold — if there is a real class of
agent purpose-violations that only capability+IFC catches — there is a product, and it is in
**agent data governance**, not in "another authorization engine."

If, after that sprint, the answer is "no convincing need," the right move is the FDK move: archive
it, and use the whole body of work as a strong **backend / cloud / distributed-systems / product-
engineering** portfolio — which, realistically, is its highest-return use either way.

*Kill-test, not a pitch. Engineering: Ali Pourrahim. Verdicts are reconstructions of incumbent
capabilities, offered to be refuted — if OPA/Cedar/Zanzibar can do Scenario 1b too, AuthGate gets
FDK's fate.*
