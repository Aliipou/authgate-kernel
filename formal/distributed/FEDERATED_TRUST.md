# Federated Trust Roots — Design

**Phase:** 4 (6–12 months)
**Status:** Design stub — not yet implemented.

---

## Problem

The current model requires a single human principal as the trust root. In federated
deployments (multiple organizations, multiple ownership domains), there is no single
root of trust — each organization has its own principal hierarchy.

---

## Model

```
Org A root principal  ←──┐
Org B root principal  ←──┼── Federation agreement (signed cross-domain grant)
Org C root principal  ←──┘
```

Cross-organization delegations require:
1. Explicit `CrossDomainGrant` signed by both organizations' root principals
2. Scoped to specific capabilities and resources
3. Revocable by either organization's root

---

## Open Questions

- How are cross-domain grants represented in the wire format?
- What happens when Org A revokes a cross-domain grant Org B already exercised?
- How are trust domains mapped to organizational boundaries?
