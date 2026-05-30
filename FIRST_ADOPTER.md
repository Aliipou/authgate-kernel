# First Adopter — 30-minute integration

**For:** any team where SOMETHING decides and SOMETHING ELSE executes IO. Today
that's mostly LLM agents calling tools. Tomorrow it may be planners, AGI
subagents, or autonomous economic actors. The shape is the same.

This document is for **one company / one project / one team**. We do not need
a thousand users. We need the first one.

If you have:
- a decision-maker (LLM agent, planner, scheduled task, anything)
- that calls tools (functions, APIs, database operations, anything)
- that hit real-world state (filesystem, DB, network, credentials, anything)

— keep reading. The framework you use today is a convenience; the gate works
regardless of which framework dies next.

---

## What you have today (probably)

```
LLM decides → tool runs → IO happens
```

No authority proof. No audit trail. No structural boundary.

When something goes wrong (and it will), you cannot answer:
- *Which tool ran?*
- *Why did it run?*
- *Who said it could run?*
- *Can I prove the run was authorized?*

If your AI runs `os.system(...)` based on what an LLM said: you have a problem.

---

## What you get in 30 minutes

```
LLM decides → CallGate (checks authority proof) → tool runs OR denied → audit logged
```

Every tool call is gated. Every decision is logged. Every denial is structural
(the tool body never runs). The audit log is tamper-evident.

That's it. We're not selling you AGI safety. We're selling you the answer to
"who said this tool could run?"

---

## The 30-minute integration (working code)

### Step 1 — install (2 min)

```bash
pip install authgate
# or for development:
git clone https://github.com/Aliipou/authgate-kernel
cd authgate-kernel && pip install -e .
```

### Step 2 — wrap one tool (10 min)

Before:

```python
def read_customer_data(customer_id: str) -> dict:
    return db.query("SELECT * FROM customers WHERE id = ?", customer_id)

# Used directly by the agent:
result = read_customer_data(customer_id="123")
```

After:

```python
from authgate import (
    AgentType, Entity, Resource, ResourceType, RightsClaim,
    OwnershipRegistry, FreedomVerifier, Action, AuditLog, CallGate,
)

# One-time setup at startup
alice = Entity("alice@yourcompany.com", AgentType.HUMAN, identity_token=ALICE_SECRET)
bot   = Entity("support-bot",            AgentType.MACHINE, identity_token=BOT_SECRET)
customer_db = Resource("customer-db", ResourceType.DATABASE_TABLE, scope="/customers/")

registry = OwnershipRegistry()
registry.register_machine(bot, alice)
registry.add_claim(RightsClaim(alice, customer_db, can_read=True, can_delegate=True))
registry.delegate(RightsClaim(bot, customer_db, can_read=True), delegated_by=alice)

audit = AuditLog(path="/var/log/authgate.jsonl", max_entries=100_000)
gate  = CallGate(FreedomVerifier(registry, audit_log=audit))

gate.register("read_customer_data", read_customer_data)

# In the agent loop:
result = gate.execute(
    Action("read-cust", actor=bot, resources_read=[customer_db]),
    "read_customer_data",
    {"customer_id": "123"},
)

if result.permitted:
    print(result.output)
else:
    print(f"DENIED: {result.denied_reason}")
    # Audit log has the entry; nothing happened to the customer DB
```

That's the whole integration. Three new imports. One registry setup.
One `gate.execute()` call instead of a direct function call.

### Step 3 — run shadow mode for a week (15 min to set up)

In shadow mode, the gate logs decisions but never blocks. You compare what
would have been denied against what your current system did.

```python
gate = CallGate(
    FreedomVerifier(registry, audit_log=audit),
    shadow_mode=True,  # log decisions, never deny
)
```

(Shadow mode is the kind of small adoption-friendly feature that DOES belong in
the project — see FEATURE_FREEZE.md "ALLOWED with justification". If shadow mode
isn't implemented in your version, run `gate.execute()` then **ignore the result**
and always execute the tool. Track decisions out-of-band for the first week.)

After one week, you'll have an audit log showing:
- How many tool calls happened
- How many would have been denied
- Whether any denials look like real attacks
- Whether any false-denials need policy adjustment

### Step 4 — promote to primary (after 30 days)

When the shadow-mode log shows:
- Zero false denials of legitimate operations
- At least one true denial that would have prevented something bad
- Audit chain integrity intact across the period

Flip `shadow_mode=False`. The gate is now structural.

---

## What you need to bring

| Need | What it is |
|------|-----------|
| At least one agent | LangChain, OpenAI Agents SDK, Anthropic, CrewAI, MCP — any |
| At least one tool | A function the agent calls that touches real state |
| At least one resource | A database, file, API endpoint, credential, model weight, anything sensitive |
| At least one human owner | The person responsible for the resource |
| 30 minutes of integration time | Initial wire-up |
| 30 days of shadow mode | To gain confidence |

What you do NOT need:
- New infrastructure
- A Kubernetes cluster
- A Rust toolchain (Python works; Rust is for the formal guarantees later)
- An understanding of capability theory
- A philosophy degree

---

## What we ask in return

In exchange for the integration:

1. **Tell us what broke.** Honest postmortem of friction points.
2. **Tell us what we got wrong.** API confusion, missing features, false security claims.
3. **Tell us what you'd need next.** The first adopter's wishlist drives the post-freeze roadmap.
4. **One quote.** A sentence we can put on the README. Anonymized if you want.

That's it. No fees. No support contract. No marketing pressure.

You get a working capability gate. We get the validation that infrastructure
needs in order to become infrastructure.

---

## What you should NOT use this for (yet)

- Anything where a false denial costs > $10,000
- Anything where a single bypass costs > $100,000
- Anything in a regulated environment requiring SOC2/HIPAA compliance
  (the project doesn't have those audits — see DEPLOYMENT_READINESS.md)
- Anything that requires distributed multi-org trust (Phase 4 work, not yet done)

For those: wait for v2.0 with external review completed.

---

## What we'll do for you

| Within 24 hours of you telling us "we're trying it" |
|------|
| Reply with a setup-help offer |
| Make ourselves available for a 30-minute Q&A |
| Triage any bug you find as P0 |
| Close any finding before public release |

You are not a beta tester for us. You are the bottleneck for the entire project.
The first real deployment is worth more than the next 1000 GitHub stars.

---

## Contact

Open an issue: https://github.com/Aliipou/authgate-kernel/issues
Subject line: `[FIRST-ADOPTER] <your-context>`

Or email if you want to keep it private: see SECURITY.md.

---

*If you adopt this, you become the reference. The project gets credible
because of you. Thank you.*
