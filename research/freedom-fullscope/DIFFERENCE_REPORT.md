# How different could AuthGate become?

**Branch:** `research/freedom-fullscope`  
**Question:** If we keep the Freedom Formal extras (skill A1–A5 as structural solutions) in front of the capability gate, how different is the product from today’s AuthGate?

---

## Short answer

| Layer | Today (`main`) | With fullscope extras |
|---|---|---|
| Core question | “Does this actor hold a valid capability?” | That **plus** “Does this act violate sealed freedom axioms?” |
| Deny reasons | Cap/expiry/epoch/attenuation/ownership | + audit endgame, rival constitution, compulsory guide, liability shift, exit lock, Is/Ought gap |
| Product identity | Capability security for agents | **Agent legitimacy OS** (normative + capability) |
| Adoption surface | Security / infra buyers | + governance, rights, compliance-philosophy buyers — and new rejection risk |
| Overlap with OPA/Cedar | High on pure authz | Lower: extras are not what OPA ships |
| Merge to `main`? | — | Only if market evidence says these denies are load-bearing |

Capability AuthGate stays a **narrow gate**. Fullscope becomes a **two-stage stack**: legitimacy (Freedom Formal) → authority (AuthGate). Same IO, different politics and deny surface.

---

## What stays the same

- Rust TCB invariants (binding, identity, expiry, epoch, resource, attenuation) — untouched on this branch.
- Wire format / CallGate still answers capability questions.
- Extras are DENY-only: they never grant authority AuthGate refused.
- Framework adapters can stay conveniences.

---

## What becomes different (concrete)

### 1. Decision pipeline

```text
TODAY:     Action → CallGate(capability) → Permit|Deny → IO

FULLSCOPE: Action → FreedomFormal(A1–A5) → Deny? stop
                              ↓ ALLOW
                         CallGate(capability) → Permit|Deny → IO
```

An action can be **cryptographically authorized and still blocked**. That is the entire delta.

### 2. New deny classes (AuthGate alone misses these)

From the scenario catalog (`unique_need_scenarios`):

| ID | Scenario | Extra axiom | Why capability gate misses it |
|---|---|---|---|
| S1 | Wipe audit before known review deadline | A2 | Log delete may be in-cap |
| S2 | Load rival “safety constitution” | A3 | Caps don’t seal a normative digest |
| S3 | Force all calls through one guide oracle | A3 | Routing can be authorized |
| S4 | Bill human for bot error / socialize loss | A4 | Charge tool may be in-cap |
| S5 | Disable exit / revoke path after onboard | A5 | Settings write may be in-cap |
| S6 | Act under Is/Ought gap with no guide | A5 | Caps don’t require a guide channel |
| S8 | Sensitive act with audit unbound | A2 | Audit-as-policy ≠ Ma'ad-style mandatory Ans |

**Overlap (not a unique win):** S7 ownerless machine — AuthGate A4 already covers this.

### 3. Product / market shape

| Dimension | How it changes |
|---|---|
| **Pitch** | From “TLS for agent tools” toward “constitutional runtime for agents” |
| **Competitors** | Less Cedar/OPA; more governance / policy / “agent constitution” vendors — and DLP still overlaps some audit cases |
| **Trust story** | Stronger narrative coherence with Theory of Freedom; weaker “boring infra” story |
| **False-positive risk** | Higher: `known_audit_deadline`, `is_ought_gap`, `socializes_loss` need careful wiring or they block normal ops |
| **TCB size** | If promoted into TCB → larger attack surface + proof burden; if kept research/Python → honest but bypassable (same as today’s non-TCB layers) |
| **License / politics** | Sealed constitution + religious lineage in the deny path hardens some enterprise deals, softens others |

### 4. How *large* is the behavioral delta?

Empirically on this branch’s catalog:

- **7 / 8** scenarios = capability would PERMIT, Freedom Formal DENY → extras change the outcome.
- **1 / 8** = already denied by AuthGate-style ownership → no unique delta.

So for the **attack classes we enumerated**, the system becomes **qualitatively different** on endgame audit, constitution sealing, compulsory guidance, liability, and exit — not merely a rename of existing flags.

It does **not** become different on: classic ReBAC, cloud IAM, or “is principal P allowed action A on resource R?” — Cedar/Zanzibar still own that.

### 5. Three futures (honest)

1. **Quarantine (recommended default)**  
   Keep on `research/freedom-fullscope`. AuthGate `main` stays capability-first. Difference = optional legitimacy sidecar for experiments.

2. **Productize as sidecar**  
   Ship `FreedomFormalEvaluator` as DENY-only pre-gate (Python/API), never in Rust TCB. Difference = new API + deny reasons; security claims stay with CallGate.

3. **Absorb into TCB**  
   Maximum difference: every tool call carries constitution digest, audit-bound, exit bits in the binding hash. Maximum cost: proofs, red team, and a new threat model. Only justified if S1–S6 show up in real customer traces.

---

## Verdict on “how different”

- **Runtime behavior:** meaningfully different on **legitimacy-shaped** abuses (audit endgame, rival constitution, lock-in, liability shift) — not on generic authorization.
- **Architecture:** two-stage vs one-stage.
- **Identity:** capability kernel → constitutional agent runtime if marketed that way.
- **Worth merging:** only after real scenarios (not our synthetic catalog) show buyers need those denies more than they fear false positives.

This report is the success criterion of the branch: we can *see* the delta. Next evidence must be external traces, not more axioms.
