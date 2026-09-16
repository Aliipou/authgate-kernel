# Key Management — Production Integration Guide

AuthGate does **not** embed a KMS. Trust roots and signing keys are **operator-supplied**.
This guide shows how to wire industry-standard key stores to the verifier sidecar.

---

## Keys in scope

| Key | Purpose | Rotation |
|-----|---------|----------|
| **Root Ed25519** | Signs capability proofs | [key_rotation.py](src/authgate/key_rotation.py) + epoch bump |
| **Admin token** | Registry mutation (`AUTHGATE_ADMIN_TOKEN`) | Rotate via secret operator; restart pod |
| **Verifier signing key** | Signs audit/verification attestations | Same as root or separate; mount read-only |

---

## HashiCorp Vault

### Static secret (development → staging)

```bash
vault kv put secret/authgate/admin token="$(openssl rand -hex 32)"
vault kv put secret/authgate/signing @signing.key
```

**External Secrets Operator** (`ExternalSecret`):

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: authgate-admin
  namespace: agent-runtime
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: authgate-admin
  data:
    - secretKey: token
      remoteRef:
        key: secret/authgate/admin
        property: token
```

Mount into the sidecar as today (`sidecar-deployment.yaml`).

### Dynamic credentials (production pattern)

1. Vault PKI or Transit engine holds the root; agents never see long-lived root keys.
2. CronJob or admission webhook calls Vault to mint **short-lived claims** (24h TTL).
3. On compromise: `vault write -f transit/keys/authgate-root/rotate` + bump `min_epoch` on all verifiers.

---

## AWS Secrets Manager + KMS

```bash
aws secretsmanager create-secret \
  --name prod/authgate/admin-token \
  --secret-string "$(openssl rand -hex 32)"

aws secretsmanager create-secret \
  --name prod/authgate/signing-key \
  --secret-binary fileb://signing.key
```

**IRSA** (EKS): attach a Role to `agent-runtime-sa` with `secretsmanager:GetSecretValue` scoped to `prod/authgate/*`.

Optional: envelope-encrypt the signing key with **AWS KMS** CMK before storing in Secrets Manager; decrypt in an init container, mount tmpfs only.

---

## Azure Key Vault

```bash
az keyvault secret set --vault-name $VAULT --name authgate-admin-token --value "$(openssl rand -hex 32)"
az keyvault certificate create --vault-name $VAULT --name authgate-signing \
  --policy "$(cat ed25519-policy.json)"
```

Use **Secrets Store CSI driver** with `SecretProviderClass` pointing at Key Vault; mount as files under `/etc/authgate-kernel/`.

---

## Rotation procedure (all platforms)

1. Generate new keypair **outside** the running pod (HSM, Vault Transit, or offline ceremony).
2. Issue `RotationCertificate` via `authgate.key_rotation` (see [DEPLOYMENT.md](DEPLOYMENT.md)).
3. Distribute cert to all verifiers; set overlap window (recommended: 3600s; emergency: 0).
4. Bump `min_epoch` to invalidate old capability cohort.
5. Re-sign outstanding claims or wait for natural expiry.
6. Verify: `authgate-cli key verify-cert rotation.json`

---

## Anti-patterns

| Do not | Why |
|--------|-----|
| Commit keys to git | Immediate permanent compromise |
| Share admin token with agents | Registry mutation = full authority rewrite |
| Use default K8s Secret without encryption at rest | Cluster backup = key leak |
| Rotate signing key without epoch bump | Old proofs remain valid indefinitely |

---

## Checklist before production

- [ ] Root key generated in HSM or Vault Transit (not on laptop)
- [ ] Admin token ≥ 256 bits entropy, stored in secret operator
- [ ] Pod mounts keys read-only; `automountServiceAccountToken: false` unless required
- [ ] Rotation runbook tested in staging ([DISASTER_RECOVERY.md](DISASTER_RECOVERY.md))
- [ ] `AUTHGATE_BACKEND=rust` when formal guarantees required
