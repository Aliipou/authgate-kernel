# Migration Guide — Registry & Schema Versions

AuthGate wire schemas use `schema_version` in JSON envelopes. This guide covers
registry format upgrades and proof re-issuance after kernel version bumps.

---

## Version map

| Kernel | Registry format | Wire schema | Notes |
|--------|-----------------|-------------|-------|
| 0.1.x | Legacy flat claims | pre-v1 | Unsupported |
| 1.0.x | `agents` + `machine_owners` + `claims` | 1.0.0 | Current |

---

## CLI migration

```bash
# Dry-run: show diff only
authgate-cli migrate registry --from reg-v0.json --to reg-v1.json --dry-run

# Write migrated registry
authgate-cli migrate registry --from reg-v0.json --to reg-v1.json

# Validate output against wire schemas
authgate-cli validate --schema canonical_action action.json
```

---

## v0 → v1 registry transform

The migrator handles:

| v0 field | v1 field |
|----------|----------|
| `entities[]` with `type` | `agents[]` with `kind` (`HUMAN` / `MACHINE`) |
| `ownership[]` | `machine_owners[]` |
| `rights[]` | `claims[]` with explicit `can_read` / `can_write` / `can_delegate` |
| Missing `identity_token` | Preserved; add tokens before production (C-1 mitigation) |

Example:

```bash
authgate-cli migrate registry \
  --from examples/legacy/registry-v0.example.json \
  --to /etc/authgate/registry.json
```

---

## Proof re-issuance after root rotation

Capabilities signed under `old_root` are invalid after epoch cutover. Migration steps:

1. Export active holders: `authgate-cli audit stats audit.jsonl` + registry dump.
2. Human principals re-delegate via `/delegate` (attenuated) or offline signing tool.
3. Bump `min_epoch` on verifiers **after** new proofs are distributed.
4. Run shadow validation: old proofs must DENY, new proofs must PERMIT on test actions.

---

## Zero-downtime sidecar upgrade

1. Deploy new sidecar image to **canary** pod (1 replica).
2. Shadow-compare: agent calls old + new `/verify`; alert on divergence.
3. Rolling update remaining replicas.
4. Roll back if `authgate-cli audit verify` fails on canary log.

---

## Breaking change policy

- **PATCH:** bug fixes, no schema change
- **MINOR:** additive JSON fields only; old clients still validate
- **MAJOR:** breaking wire change → migration tool update required + CHANGELOG `[Breaking]`

See [CHANGELOG.md](CHANGELOG.md) and [FEATURE_FREEZE.md](FEATURE_FREEZE.md).
