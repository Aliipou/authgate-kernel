# Deployment Guide

**Phase:** 7 (Enterprise Reality)
**Status:** Initial draft.

---

## Quick Start

```bash
pip install authgate                        # pure Python, no build toolchain
pip install maturin && cd authgate-kernel && pip install .   # with Rust kernel
```

```python
from authgate.kernel.verifier import FreedomVerifier
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.audit import AuditLog

log = AuditLog(path="/var/log/kernel.jsonl")
registry = OwnershipRegistry()
# ... register machines, add claims ...
verifier = FreedomVerifier(registry, audit_log=log)
```

---

## Deployment Topologies

### Sidecar (recommended)

Run the verifier as an isolated sidecar process alongside each agent:

```
Agent Process ──── gRPC/IPC ───► Verifier Sidecar
                                      │
                                 OwnershipRegistry
                                      │
                                  AuditLog (file)
```

Benefits: process isolation, minimal attack surface, OS-level boundary.

### In-Process

Embed the verifier directly in the agent process:

```python
verifier = FreedomVerifier(registry.freeze())
```

Benefits: zero latency, simpler deployment.
Risk: a memory-safety bug in orchestration code is in the same process as the gate.

### Distributed (future)

Multi-node with consensus-backed revocation. See `formal/distributed/`.

---

## Security Hardening Checklist

- [ ] Use `registry.freeze()` before passing to verifier — eliminates TOCTOU
- [ ] Set `expires_at` on all machine claims — no perpetual claims
- [ ] Use `AuditLog(path=...)` — not in-memory only
- [ ] Call `AuditLog.verify_chain()` on log rotation
- [ ] Use KMS-backed ed25519 key for production (not in-memory default)
- [ ] Run verifier with seccomp/AppArmor profile (no network, minimal filesystem)
- [ ] Pin dependency versions — check `cargo audit` in CI

---

## Latency Budget

| Operation | Target | Typical (Rust) |
|---|---|---|
| `verify()` — permit path | < 5 µs | ~2 µs |
| `verify()` — blocked (flag) | < 1 µs | ~0.3 µs |
| Registry, 10k claims (indexed) | < 10 µs | ~3 µs (O(1) lookup) |
| Cascading revocation, 100 agents | < 1 ms | ~600 µs |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FREEDOM_KERNEL_MAX_DEPTH` | 16 | Maximum delegation chain depth |
| `FREEDOM_KERNEL_REPLAY_WINDOW` | 30 | Signature replay window in seconds |
| `FREEDOM_KERNEL_AUDIT_PATH` | None | Path to audit log file |
