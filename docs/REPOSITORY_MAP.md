# Repository map

Sluicegate is one product plus a set of experimental satellites. Start with the core; ignore the rest until you need them.

| Repository | Role | Status | Start here if |
|---|---|---|---|
| [`sluicegate`](https://github.com/Aliipou/sluicegate) (this repo, formerly `authgate-kernel`) | The core: capability wire format, `verify` function, Rust TCB, Python mirror, WASM/seccomp enforcement | Primary | You want to gate agent tool calls |
| [`decision-os-min`](https://github.com/Aliipou/decision-os-min) | Host/execution plane: signed action-bound decisions, one-time tokens, locked-agent sandbox profile and probes | Experimental | You want the process-isolation layer and escape probes |
| [`authgate-gate`](https://github.com/Aliipou/authgate-gate) | Agent tool-call gate that layers capability → purpose-binding → runtime/drift checks (ALLOW / DENY / TRANSFORM) with a tamper-evident audit record. Still carries the former AuthGate name | Experimental | You want purpose-binding and behavioural-drift checks on top of capabilities |
| [`freedom-theory`](https://github.com/Aliipou/freedom-theory) | The philosophical constitution (A1–A7). Not part of the TCB | Reference | You want the "why", not the "how" |
| [`decision-runtime`](https://github.com/Aliipou/decision-runtime), [`audit-ledger`](https://github.com/Aliipou/audit-ledger), `plugin-*`, `adapter-*` | Satellites around the decision plane; none holds authority | Experimental | You are extending the decision plane |

## How they fit

```
agent (locked container, no ambient authority)
   └─ Intent (JSON lines over stdin/stdout)
        └─ host (decision-os-min): mediation, replay refusal, one-time token spend
             └─ Sluicegate verify: signed capability → Permit | Deny
                  └─ effect adapter (only reached on Permit), audit before effect
```

## What is and is not claimed

See [NON_GOALS.md](../NON_GOALS.md), [THREAT_MODEL.md](../THREAT_MODEL.md) and [ASSUMPTIONS.md](../ASSUMPTIONS.md). In particular: the sandbox is a partial mitigation with documented residuals, not a proof of isolation, and the tests and red-team runs were written by the author — independent attempts to break it are welcome (see [SECURITY.md](../SECURITY.md)).
