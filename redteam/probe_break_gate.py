"""Live break-the-gate probes against the FastAPI verifier surface.

Exit 0 = no unexpected permits. Prints BREAK lines for gate failures.
"""
from __future__ import annotations

import sys
import threading

from fastapi.testclient import TestClient

import authgate.api.app as appmod
from authgate.api.app import app
from authgate.kernel.registry import OwnershipRegistry

client = TestClient(app)
breaks: list[tuple[str, str]] = []
holds: list[tuple[str, str]] = []


def reset() -> None:
    appmod._registry = OwnershipRegistry()


def hold(name: str, detail: str = "") -> None:
    holds.append((name, detail))


def brk(name: str, detail: str = "") -> None:
    breaks.append((name, detail))


def must_deny(name: str, body: dict) -> None:
    v = client.post("/verify", json=body).json()
    if v.get("permitted"):
        brk(name, str(v.get("violations")))
    else:
        hold(name, str(v.get("violations")))


# --- A1: MACHINE registers itself as HUMAN owner, then writes ---
reset()
r = client.post(
    "/machine",
    json={
        "machine": {"name": "evil", "kind": "MACHINE"},
        "owner": {"name": "evil", "kind": "HUMAN"},
    },
)
client.post(
    "/claim",
    json={
        "holder": {"name": "evil", "kind": "MACHINE"},
        "resource": {"name": "vault", "rtype": "credential"},
        "can_read": True,
        "can_write": True,
        "can_delegate": True,
    },
)
v = client.post(
    "/verify",
    json={
        "action_id": "a1",
        "actor": {"name": "evil", "kind": "MACHINE"},
        "resources_write": [{"name": "vault", "rtype": "credential"}],
    },
).json()
if r.status_code == 200 and v.get("permitted"):
    brk("A1 self-owned machine minted write", f"register={r.status_code} {v}")
else:
    hold("A1 self-own path", f"register={r.status_code} permit={v.get('permitted')}")

# --- A2: ghost write ---
reset()
must_deny(
    "A2 ghost write",
    {
        "action_id": "a2",
        "actor": {"name": "ghost", "kind": "MACHINE"},
        "resources_write": [{"name": "vault", "rtype": "credential"}],
    },
)

# --- A3: name-spoof MACHINE as Alice ---
reset()
client.post(
    "/machine",
    json={
        "machine": {"name": "bot", "kind": "MACHINE"},
        "owner": {"name": "Alice", "kind": "HUMAN"},
    },
)
client.post(
    "/claim",
    json={
        "holder": {"name": "Alice", "kind": "HUMAN"},
        "resource": {"name": "vault", "rtype": "credential"},
        "can_write": True,
        "can_read": True,
    },
)
must_deny(
    "A3 spoof MACHINE named Alice",
    {
        "action_id": "a3",
        "actor": {"name": "Alice", "kind": "MACHINE"},
        "resources_write": [{"name": "vault", "rtype": "credential"}],
    },
)

# --- A4: bypass flag ---
reset()
must_deny(
    "A4 bypasses_verifier",
    {
        "action_id": "a4",
        "actor": {"name": "bot", "kind": "MACHINE"},
        "bypasses_verifier": True,
    },
)

# --- A5: unauthenticated /claim amplification (API boundary) ---
reset()
client.post(
    "/machine",
    json={
        "machine": {"name": "bot", "kind": "MACHINE"},
        "owner": {"name": "Alice", "kind": "HUMAN"},
    },
)
cr = client.post(
    "/claim",
    json={
        "holder": {"name": "bot", "kind": "MACHINE"},
        "resource": {"name": "vault", "rtype": "credential"},
        "can_write": True,
        "can_read": True,
        "can_delegate": True,
    },
)
v = client.post(
    "/verify",
    json={
        "action_id": "a5",
        "actor": {"name": "bot", "kind": "MACHINE"},
        "resources_write": [{"name": "vault", "rtype": "credential"}],
    },
).json()
if cr.status_code == 200 and v.get("permitted"):
    brk(
        "A5 UNAUTH CLAIM AMPLIFICATION",
        "open /claim lets bot mint write rights without Alice grant",
    )
else:
    hold("A5 claim amp", f"claim={cr.status_code} permit={v.get('permitted')}")

# --- A6: MACHINE as owner ---
reset()
r = client.post(
    "/machine",
    json={
        "machine": {"name": "child", "kind": "MACHINE"},
        "owner": {"name": "parent", "kind": "MACHINE"},
    },
)
if r.status_code == 422:
    hold("A6 machine-owner rejected", r.text[:200])
else:
    brk("A6 machine-owner accepted", f"status={r.status_code} {r.text}")

# --- A7: governs humans ---
reset()
client.post(
    "/machine",
    json={
        "machine": {"name": "bot", "kind": "MACHINE"},
        "owner": {"name": "Alice", "kind": "HUMAN"},
    },
)
must_deny(
    "A7 governs_humans",
    {
        "action_id": "a7",
        "actor": {"name": "bot", "kind": "MACHINE"},
        "governs_humans": [{"name": "Alice", "kind": "HUMAN"}],
    },
)

# --- A8: sovereignty-adjacent flags ---
reset()
for flag in (
    "weakens_verifier",
    "disables_corrigibility",
    "resists_human_correction",
    "machine_coalition_dominion",
    "increases_machine_sovereignty",
):
    must_deny(
        f"A8 {flag}",
        {
            "action_id": f"a8-{flag}",
            "actor": {"name": "bot", "kind": "MACHINE"},
            flag: True,
        },
    )

# --- A9: claim for unregistered machine ---
reset()
cr = client.post(
    "/claim",
    json={
        "holder": {"name": "orphan", "kind": "MACHINE"},
        "resource": {"name": "vault", "rtype": "credential"},
        "can_write": True,
    },
)
v = client.post(
    "/verify",
    json={
        "action_id": "a9",
        "actor": {"name": "orphan", "kind": "MACHINE"},
        "resources_write": [{"name": "vault", "rtype": "credential"}],
    },
).json()
if cr.status_code == 200 and v.get("permitted"):
    brk("A9 orphan machine claim+write", "unregistered MACHINE obtained write")
else:
    hold("A9 orphan", f"claim={cr.status_code} permit={v.get('permitted')}")

# --- A10: public resource write without claim ---
reset()
must_deny(
    "A10 public-flagged write still needs authority",
    {
        "action_id": "a10",
        "actor": {"name": "bot", "kind": "MACHINE"},
        "resources_write": [
            {"name": "wiki", "rtype": "document", "is_public": True}
        ],
    },
)

# --- A11: concurrent unauth claim flood ---
reset()
client.post(
    "/machine",
    json={
        "machine": {"name": "bot", "kind": "MACHINE"},
        "owner": {"name": "Alice", "kind": "HUMAN"},
    },
)
results: list[bool] = []


def attacker() -> None:
    for i in range(40):
        client.post(
            "/claim",
            json={
                "holder": {"name": "bot", "kind": "MACHINE"},
                "resource": {"name": f"r{i}", "rtype": "credential"},
                "can_write": True,
            },
        )


def victim() -> None:
    for i in range(40):
        results.append(
            client.post(
                "/verify",
                json={
                    "action_id": f"t{i}",
                    "actor": {"name": "bot", "kind": "MACHINE"},
                    "resources_write": [{"name": f"r{i}", "rtype": "credential"}],
                },
            )
            .json()
            .get("permitted")
        )


t1 = threading.Thread(target=attacker)
t2 = threading.Thread(target=victim)
t1.start()
t2.start()
t1.join()
t2.join()
# If any verify permitted without prior Alice grant, that is amp via race+open claim.
if any(results):
    brk(
        "A11 race+open-claim permits",
        f"permits={sum(1 for x in results if x)}/{len(results)}",
    )
else:
    hold("A11 race no permit", f"n={len(results)}")

print("=== BREAKS ===")
for n, d in breaks:
    print(f"BREAK | {n} | {d}")
print(f"\n=== HOLDS ({len(holds)}) ===")
for n, d in holds:
    print(f"HOLD  | {n} | {d}")
print(f"\nbreaks={len(breaks)} holds={len(holds)}")
sys.exit(1 if breaks else 0)
