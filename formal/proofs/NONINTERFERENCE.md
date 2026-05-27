# Noninterference Research

**Phase:** 5 (6–12 months)
**Status:** Research problem definition — not yet implemented.

---

## Problem

The kernel enforces *authority* (who can act on what). It does not enforce
*information flow* (whether reading resource A and writing resource B causes
a security violation even if both are individually permitted).

Noninterference is the property: "an agent with high-security access cannot
influence the observations of an agent with low-security access."

---

## Current State

The IFC extension (`extensions/ifc.py`) implements Bell-LaPadula labels:
- Resources carry `ifc_label` (e.g. "SECRET", "PUBLIC")
- `NonInterferenceChecker` verifies that a plan does not route information from
  HIGH labels to LOW labels

This is an *extension* — not in the TCB. The Lean 4 theorem `taint_monotone` proves
that IFC taint only grows across a plan, never shrinks.

---

## Open Research Questions

1. **Completeness of Bell-LaPadula for agent systems:** Does Bell-LaPadula capture
   all covert flows in a multi-agent execution context? (Known answer: No — timing
   and probabilistic channels are not covered.)

2. **Declassification semantics:** How should the kernel handle intentional downflow
   (e.g., a sanitized report derived from SECRET data)? Currently unsupported.

3. **Multi-agent IFC:** When agent A (TAINT=SECRET) delegates to agent B, does B
   inherit the taint? Current model: yes (conservative). Is this sound?

4. **Compositionality:** If subsystem S1 satisfies noninterference and S2 satisfies
   noninterference, does S1 ∘ S2 satisfy noninterference? (Known: generally no — the
   composition problem is open for practical systems.)

---

## Relevance to "Capability Laundering"

Capability laundering (ATK-002) is a specific form of interference: an agent uses
two legitimately-authorized agents to route information in a way that bypasses
the capability boundary. IFC addresses this at the label level, but only if labels
are assigned correctly and completely.

This is the most promising niche research direction in the roadmap.

---

## Next Steps

1. Survey literature on IFC for distributed/multi-agent systems (cite: Volpano-Smith 1996, Zdancewic 2002)
2. Define the attacker model for capability laundering under IFC
3. Prove or disprove: Bell-LaPadula + attenuation = no capability laundering
