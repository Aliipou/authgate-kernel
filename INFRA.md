# Infra readiness — AuthGate Verifier API

## What “infra-ready” means here

**Infra-ready = zero open items in [Engineering gaps](README.md#engineering-gaps).**  
All listed gaps must be closed, scoped to a documented non-goal, or moved to [Explicit limitations](README.md#explicit-limitations). Claims like “deployable sidecar” apply only when that table has no open rows and required CI workflows are green on `main`.

A **deployable reference verifier sidecar/service**, not a full enterprise gateway.
Shipped on **`main`** when the above holds; CI runs Docker `/readyz` smoke on every push.

| Included | Deliberately at the ingress (not here) |
|---|---|
| Docker image + compose | TLS termination |
| Persistent audit volume (`AUTHGATE_AUDIT_PATH`) | Multi-region audit notary |
| Admin token for registry mutation (`AUTHGATE_ADMIN_TOKEN`) | Caller mTLS / OAuth for `/verify` |
| `/healthz`, `/readyz`, Prometheus `/metrics` | WAF / rate limits |
| Attenuating `/delegate` (no MACHINE self-mint via `/claim`) | Policy editor UI |
| Kubernetes sidecar example (`examples/kubernetes/`) | Horizontal spent-store shard |

## Quick start

```bash
cp .env.example .env   # set AUTHGATE_ADMIN_TOKEN
docker compose up --build -d
curl -s localhost:8000/readyz
curl -s -X POST localhost:8000/verify -H 'content-type: application/json' \
  -d '{"action_id":"probe","actor":{"name":"ghost","kind":"MACHINE"},"bypasses_verifier":true}'
```

## Env

| Var | Role |
|---|---|
| `AUTHGATE_ADMIN_TOKEN` | Required. Bearer for `X-AuthGate-Admin` on `/machine`, `/claim`, `/delegate`, `/conflict/resolve` |
| `AUTHGATE_AUDIT_PATH` | Hash-chained JSONL audit path |
| `AUTHGATE_BACKEND` | `python` (default in image) or Rust when installed |
| `PORT` / `HOST` | Bind address for `authgate-server` |

## Gate boundary (must hold)

1. **No unauthenticated registry mutation** — without admin token → 401; without token configured → mutators 503, `/readyz` 503.
2. **MACHINE cannot self-mint via `/claim`** — use `/delegate` from the registered human owner with attenuation.
3. **Same-name HUMAN/MACHINE registration** requires distinct `identity_token` values (blocks fictional self-ownership).

## Red-team regression

```bash
AUTHGATE_BACKEND=python pytest tests/test_api_redteam_boundary.py tests/test_adversarial_redteam.py redteam/ -q
```

## Honest limits

- `/verify` is intentionally open to the pod network (sidecar model). Lock it down with NetworkPolicy + mTLS at the mesh.
- Python backend is identity-degraded vs Rust TCB (`health_check()` reports C-1/C-2). Prefer Rust kernel in production.
