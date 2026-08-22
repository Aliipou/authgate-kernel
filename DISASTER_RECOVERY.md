# Disaster Recovery

Procedures for **root key compromise**, **audit log loss**, and **registry corruption**.
Pair with [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) and [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md).

---

## Severity matrix

| Event | RTO target | RPO target | Primary action |
|-------|------------|------------|----------------|
| Root key compromised | 1 hour | 0 (assume all proofs forged) | Emergency rotation + epoch bump |
| Admin token leaked | 15 min | N/A | Rotate token; audit registry mutations |
| Audit log lost/corrupt | 4 hours | Last durable backup | Restore from PVC/SIEM; treat gap as untrusted |
| Registry Secret tampered | 30 min | Last known-good Secret version | Roll back Secret; restart pods |
| Verifier pod compromised | 30 min | N/A | Kill pod; redeploy from pinned image digest |

---

## 1. Root key compromise

**Assume:** attacker can forge capability proofs until epoch cutover.

### Immediate (0–15 min)

```python
# Emergency epoch bump — invalidates ALL caps below new_epoch
registry.set_min_epoch(new_epoch=current_epoch + 1_000_000)
registry.revoke_all("*")  # if API supports wildcard; else enumerate holders
```

```bash
# Kill all agent pods — stop exfiltration while rotating
kubectl -n agent-runtime delete pods -l app=ai-agent
```

### Rotation (15–60 min)

1. Generate new root keypair in Vault/HSM (never on compromised host).
2. Create emergency rotation cert (`overlap_window_seconds=0`):

```python
from authgate.key_rotation import rotate
cert = rotate(old_sk, new_sk, new_epoch=target_epoch, overlap_window_seconds=0)
cert.to_wire()  # distribute to all verifiers
```

3. Update Secrets Manager / Vault with new signing key.
4. Redeploy all verifier sidecars with new Secret + `min_epoch`.
5. Re-issue claims from human principals only (no machine self-mint).

### Verification

```bash
authgate-cli key verify-cert rotation-emergency.json
authgate-cli audit verify /var/log/authgate/audit.jsonl
pytest tests/test_adversarial_redteam.py -q
```

---

## 2. Audit log loss or tampering

### Detect

```bash
authgate-cli audit verify audit.jsonl
# CHAIN BROKEN → stop trusting decisions after last good entry
```

### Recover

1. **PVC backup:** restore latest snapshot to `AUTHGATE_AUDIT_PATH`.
2. **SIEM copy:** re-import JSONL from Fluent Bit / CloudWatch archive.
3. **No backup:** document gap in incident ticket; decisions during gap window are **unattested**.

### Preserve evidence

```bash
cp audit.jsonl audit-incident-$(date +%Y%m%d).jsonl
sha256sum audit-incident-*.jsonl >> incident-manifest.txt
```

---

## 3. Registry corruption

### Detect

- Unexpected PERMITTED for unknown resources
- Machine registered without human owner (A4 violation — should never PERMIT)

### Recover

```bash
# Roll back K8s Secret to previous version
kubectl -n agent-runtime rollout undo secret/agent-registry-config
kubectl -n agent-runtime rollout restart deployment/ai-agent-with-verifier
```

Maintain **versioned registry JSON** in git (encrypted) or Vault KV v2 with version history.

---

## 4. Backup requirements

| Asset | Method | Frequency |
|-------|--------|-----------|
| Audit JSONL | PVC snapshot or SIEM | Continuous ship + daily snapshot |
| Registry JSON | Vault KV versioning / git | On every admin mutation |
| Rotation certs | Immutable object store | On every rotation |
| Container image | Pin digest in deployment | On every release |

---

## 5. Post-incident

1. File GitHub security advisory if TCB affected ([SECURITY.md](SECURITY.md)).
2. Update [FINDINGS.md](FINDINGS.md) if new attack class discovered.
3. Add adversarial scenario to `attack_harness/` before closing ticket.
4. Re-score [DEPLOYMENT_READINESS.md](DEPLOYMENT_READINESS.md) F4 when postmortem complete.

---

## Drill schedule (recommended)

| Drill | Frequency |
|-------|-----------|
| `authgate-cli audit verify` on production log | Weekly |
| Emergency key rotation in staging | Quarterly |
| Restore audit from backup | Quarterly |
| Tabletop: admin token leak | Annually |
