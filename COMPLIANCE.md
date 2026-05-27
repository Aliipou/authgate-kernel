# Compliance Story

**Phase:** 7 (Enterprise Reality)
**Status:** Initial draft — not yet production-validated.

---

## Auditability

Every verification decision is:
- Timestamped (Unix milliseconds)
- Cryptographically signed (ed25519)
- Hash-chained to the previous entry (SHA-256 chain since v2)
- Written to an append-only JSONL log

This provides:
- **Non-repudiation:** A signed PERMITTED result proves the kernel authorized the action.
- **Tamper detection:** `AuditLog.verify_chain()` detects any modification or deletion.
- **Replay detection:** Each entry contains a random nonce; re-submission of a prior result is detectable.

---

## Healthcare / HIPAA Considerations

For healthcare deployments involving PHI (Protected Health Information):

| Requirement | authgate-kernel behavior |
|---|---|
| Access control (§164.312(a)) | Enforced via typed capability claims per resource |
| Audit controls (§164.312(b)) | Append-only signed audit log per decision |
| Integrity (§164.312(c)) | Hash-chained log; ed25519 signatures |
| Transmission security (§164.312(e)) | Out of scope — kernel gate only; network layer is caller's responsibility |

**Gap:** The kernel gates actions against typed claims. Whether the claims correctly
represent HIPAA access rules is the deploying organization's responsibility.
The kernel enforces whatever is registered — it does not validate regulatory correctness.

---

## Regulated AI (EU AI Act, NIST AI RMF)

| Framework requirement | authgate-kernel support |
|---|---|
| Traceability of AI decisions | Audit log with per-decision signed records |
| Human oversight mechanisms | Sovereignty flags structurally enforce human corrigibility |
| Access control to AI systems | Capability claims gate agent tool access |
| Documentation of capabilities | `THREAT_MODEL.md`, `SEMANTICS.md`, `INCOMPLETENESS.md` |

---

## Deployment Recommendation for Regulated Environments

1. Use `AuditLog(path="/var/log/kernel.jsonl")` with daily rotation
2. Call `AuditLog.verify_chain()` on each log rotation to detect tampering
3. Use a KMS-backed ed25519 key (not the in-memory default) for production
4. Set `expires_at` on all claims — perpetual claims are a compliance risk
5. Run `expire_stale()` on a scheduled interval
