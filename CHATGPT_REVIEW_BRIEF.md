# ChatGPT / external review brief — AuthGate (2026-08-20)

Paste this whole file into ChatGPT (or another reviewer) and ask for a hostile
review. Prefer: “Attack the claims; do not flatter; name what to archive.”

---

## Who / what

**AuthGate** (`github.com/Aliipou/authgate-kernel`) is a capability-security
kernel between any decision-maker and IO: verify a signed, non-revoked,
attenuated capability chain — else deny and audit. Companion reference PEP with
co-equal veto-only evaluators lives in sibling `decision-os-min`.

Canonical pipeline: identity → FDK legitimacy (DENY-only) → AuthGate authority →
PEP execute + audit.

## Claims that are still live

1. **Non-amplification under composition** (decision-os-min): untrusted
   evaluators are veto-only; `compose(a,k…) ⊑ a`. Measured by AE-1…AE-10
   conformance (10/10 PASS on one implementation).
2. **Attenuation (AE-4/AE-5)** via macaroon-*lite* caveats (HMAC, intersect
   allowlists) — not a full Macaroon/Biscuit stack.
3. **Action-content binding + one-time tokens + hash-chained audit.**
4. **TLA+ AuthGateV3**: TLC completed with no error on bounded model
   (`Len(audit_log)≤1`, safety-only). Log in `formal/tlc_run.log`.
5. **Rust TCB tests**: 293 lib tests pass (local, ASCII `CARGO_TARGET_DIR`).
6. **Python reference** (AUTHGATE_BACKEND=python): core + redteam sample
   green (69 tests in focused run).

## Claims that are dead or demoted (do not re-inflate)

- “Better authorization than Cedar/OPA/Zanzibar” — **absorbed**; see
  `WHY_NOT_OPA.md`, `STATUS.md`.
- “Ownership/consent ontology uniquely discriminates” — **falsified**; see
  workspace `REVIEW_REQUEST_2026-08-10.md` §4.
- Theory of Freedom as product differentiator — **optional lineage only**;
  `FREEDOM_THEORY_POSITION.md`.

## Honesty table (must cite)

`ASSUMPTIONS.md`: Ed25519 EUF-CMA is an **axiom** (runtime =
`cryptography` / unverified — not HACL*/Fiat). Kani = **bounded**. Verus /
Squirrel / Iris = **not started**. Profile is **one implementation**, not a
multi-party standard.

## Infra-ready surface (decision-os-min companion)

Docker compose, persistent signing key (`DECISION_OS_KEY_FILE`), `/readyz`,
evaluator timeout (threaded → also blocks in-process key theft), MCP mediator
in `plugin-mcp`.

## Open gaps (honest)

- In-process Python evaluators can still steal `_key` if timeout is None
  (documented `test_break_inprocess_evaluator_steals_signing_key`).
- TLC larger bound (`Len≤3`) + weak fairness not yet overnight-green.
- No second independent PEP measured against AE profile.
- Portfolio / OIDF / researcher emails are human-send (drafts in
  `OUTREACH_DRAFTS.md`).

## Ask the reviewer

1. Is the remaining wedge real once Macaroons + MCP + Cedar are granted?
2. Does ASSUMPTIONS under-claim or over-claim?
3. Should AuthGate archive the purpose-governance thesis or keep the AE
   conformance + PEP wedge?
4. Rank next spend: HACL* Ed25519 vs Tamarin/Squirrel vs second implementation.

## Reproduce

```bash
# AuthGate Python
cd freedom-kernel-work  # or clone Aliipou/authgate-kernel
AUTHGATE_BACKEND=python pip install -e ".[dev,signing]"
pytest tests/test_call_gate.py tests/test_core.py tests/test_delegation_abuse.py -q

# AuthGate Rust (Windows: avoid non-ASCII paths)
export CARGO_TARGET_DIR=/tmp/ag-target   # or D:\ag-target
cd authgate-kernel && cargo test --lib

# TLC
cd formal && java -XX:+UseParallelGC -jar tla2tools.jar -workers 4 MC_AuthGateV3

# Companion conformance
cd contracts-spec && python -m conformance.suite   # 10 pass
```

## Primary packet files in this repo

- `REVIEW_PACKET.md`
- `ASSUMPTIONS.md`
- `FREEDOM_THEORY_POSITION.md`
- `MCP_STANDARDIZATION.md`
- `formal/COVERAGE.md`, `formal/tlc_run.log`
