# Incident Response Guide

**Phase:** 7 (Enterprise Reality)
**Status:** Initial draft.

---

## Detecting a Potential Bypass

Signs that the kernel may have been bypassed or is misconfigured:

1. **Agent performed an action without a corresponding PERMITTED audit entry**
   → Agent is not routed through the verifier. Fix: wire all tool calls through verify().

2. **audit_log.verify_chain() returns False**
   → Audit log was tampered with or entries were deleted.
   → Preserve the log, treat all decisions since the last verified entry as untrustworthy.

3. **Machine acted on a resource it has no claim for**
   → Either the action was not verified, or the registry was modified post-freeze.
   → Audit registry mutation calls.

---

## Immediate Response: Revoke a Compromised Agent

```python
# Immediate revocation of a single agent
registry.revoke_all("CompromisedBot")

# Cascading revocation: revoke CompromisedBot and all agents it delegated to
count = registry.revoke_cascading("CompromisedBot")
print(f"Revoked {count} claims across delegation subtree")
```

---

## Forensics: Audit Log Analysis

```python
log = AuditLog(path="/var/log/kernel.jsonl")
# Load from file (re-read for forensics):
import json
entries = [json.loads(line) for line in open("/var/log/kernel.jsonl")]

# Find all PERMITTED actions by a specific actor
suspect_permits = [e for e in entries if e["permitted"] and "SuspectBot" in e["action_id"]]

# Verify chain integrity
if not log.verify_chain():
    print("ALERT: Audit log tampered — escalate to security team")
```

---

## Escalation Criteria

| Event | Severity | Action |
|---|---|---|
| `verify_chain()` fails | Critical | Preserve logs, revoke all affected agents, escalate |
| PERMITTED with no prior claim | Critical | Agent bypassed gate — investigate orchestration layer |
| Unexpected BLOCKED volume spike | High | May indicate attack probing; review violations |
| Machine claimed sovereignty flag | High | Review action source; check for prompt injection |
