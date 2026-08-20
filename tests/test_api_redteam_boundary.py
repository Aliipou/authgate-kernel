"""
Red-team regression: API boundary attacks that previously broke the gate.

These encode the 2026-08-20 probe findings:
  A1 — fictional same-name HUMAN owner + self-minted write
  A5 — unauthenticated / open MACHINE /claim amplification
  A11 — race + open claim permits
"""
from __future__ import annotations

import os
import threading

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("AUTHGATE_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault(
    "AUTHGATE_AUDIT_PATH",
    os.path.join(os.environ.get("TEMP", "/tmp"), "authgate-redteam-audit.jsonl"),
)

import authgate.api.app as appmod
from authgate.api.app import app
from authgate.kernel.registry import OwnershipRegistry

ADMIN = {"X-AuthGate-Admin": os.environ["AUTHGATE_ADMIN_TOKEN"]}
client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset():
    appmod._registry = OwnershipRegistry()
    yield


def test_a1_fictional_self_ownership_refused():
    r = client.post(
        "/machine",
        headers=ADMIN,
        json={
            "machine": {"name": "evil", "kind": "MACHINE"},
            "owner": {"name": "evil", "kind": "HUMAN"},
        },
    )
    assert r.status_code == 422
    assert "same-name" in r.json()["detail"].lower() or "identity_token" in r.json()["detail"]


def test_a1_same_name_ok_with_distinct_tokens():
    r = client.post(
        "/machine",
        headers=ADMIN,
        json={
            "machine": {"name": "evil", "kind": "MACHINE", "identity_token": "m-tok"},
            "owner": {"name": "evil", "kind": "HUMAN", "identity_token": "h-tok"},
        },
    )
    assert r.status_code == 200


def test_a5_unauth_claim_rejected():
    r = client.post(
        "/claim",
        json={
            "holder": {"name": "bot", "kind": "MACHINE"},
            "resource": {"name": "vault", "rtype": "credential"},
            "can_write": True,
        },
    )
    assert r.status_code == 401


def test_a5_machine_claim_path_blocked_even_with_admin():
    client.post(
        "/machine",
        headers=ADMIN,
        json={
            "machine": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
            "owner": {"name": "Alice", "kind": "HUMAN", "identity_token": "a"},
        },
    )
    r = client.post(
        "/claim",
        headers=ADMIN,
        json={
            "holder": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
            "resource": {"name": "vault", "rtype": "credential"},
            "can_write": True,
            "can_read": True,
            "can_delegate": True,
        },
    )
    assert r.status_code == 422
    v = client.post(
        "/verify",
        json={
            "action_id": "a5",
            "actor": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
            "resources_write": [{"name": "vault", "rtype": "credential"}],
        },
    ).json()
    assert v["permitted"] is False


def test_a5_delegate_without_owner_grant_forbidden():
    client.post(
        "/machine",
        headers=ADMIN,
        json={
            "machine": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
            "owner": {"name": "Alice", "kind": "HUMAN", "identity_token": "a"},
        },
    )
    # Alice has no claim — attenuation must fail
    r = client.post(
        "/delegate",
        headers=ADMIN,
        json={
            "holder": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
            "resource": {"name": "vault", "rtype": "credential"},
            "can_write": True,
        },
    )
    assert r.status_code == 403


def test_a11_race_cannot_amplify_without_delegate():
    client.post(
        "/machine",
        headers=ADMIN,
        json={
            "machine": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
            "owner": {"name": "Alice", "kind": "HUMAN", "identity_token": "a"},
        },
    )
    results: list[bool] = []

    def attacker() -> None:
        for i in range(30):
            client.post(
                "/claim",
                headers=ADMIN,
                json={
                    "holder": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
                    "resource": {"name": f"r{i}", "rtype": "credential"},
                    "can_write": True,
                },
            )

    def victim() -> None:
        for i in range(30):
            results.append(
                client.post(
                    "/verify",
                    json={
                        "action_id": f"t{i}",
                        "actor": {"name": "bot", "kind": "MACHINE", "identity_token": "b"},
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
    assert not any(results), f"unexpected permits: {sum(1 for x in results if x)}/{len(results)}"
