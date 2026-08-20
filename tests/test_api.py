"""
API smoke + infra-boundary tests for the Freedom Verifier HTTP surface.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Fail-closed admin token must be set before the app module is imported by clients.
os.environ.setdefault("AUTHGATE_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault(
    "AUTHGATE_AUDIT_PATH",
    os.path.join(os.environ.get("TEMP", "/tmp"), "authgate-api-test-audit.jsonl"),
)

import authgate.api.app as appmod
from authgate.api.app import app
from authgate.kernel.registry import OwnershipRegistry

ADMIN = {"X-AuthGate-Admin": os.environ["AUTHGATE_ADMIN_TOKEN"]}


@pytest.fixture(autouse=True)
def _reset_registry():
    appmod._registry = OwnershipRegistry()
    appmod._metrics.clear()
    yield


client = TestClient(app)


def test_health_and_aliases():
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/healthz").json()["status"] == "ok"


def test_readyz_ok_when_admin_configured():
    r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["admin_configured"] is True


def test_register_machine_and_verify_permitted():
    r = client.post(
        "/machine",
        headers=ADMIN,
        json={
            "machine": {"name": "TestBot", "kind": "MACHINE", "identity_token": "bot-tok"},
            "owner": {"name": "Alice", "kind": "HUMAN", "identity_token": "alice-tok"},
        },
    )
    assert r.status_code == 200, r.text

    r = client.post(
        "/claim",
        headers=ADMIN,
        json={
            "holder": {"name": "Alice", "kind": "HUMAN", "identity_token": "alice-tok"},
            "resource": {"name": "gpu-slot", "rtype": "compute_slot"},
            "can_read": True,
            "can_write": True,
            "can_delegate": True,
        },
    )
    assert r.status_code == 200, r.text

    r = client.post(
        "/delegate",
        headers=ADMIN,
        json={
            "holder": {"name": "TestBot", "kind": "MACHINE", "identity_token": "bot-tok"},
            "resource": {"name": "gpu-slot", "rtype": "compute_slot"},
            "can_read": True,
        },
    )
    assert r.status_code == 200, r.text

    r = client.post(
        "/verify",
        json={
            "action_id": "bot-read-gpu",
            "actor": {"name": "TestBot", "kind": "MACHINE", "identity_token": "bot-tok"},
            "resources_read": [{"name": "gpu-slot", "rtype": "compute_slot"}],
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["permitted"] is True
    assert data["violations"] == []


def test_mutate_without_admin_token_rejected():
    r = client.post(
        "/machine",
        json={
            "machine": {"name": "x", "kind": "MACHINE"},
            "owner": {"name": "y", "kind": "HUMAN"},
        },
    )
    assert r.status_code == 401


def test_machine_cannot_self_mint_via_claim():
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
        },
    )
    assert r.status_code == 422
    assert "delegate" in r.json()["detail"].lower()


def test_verify_sovereignty_flag_blocked():
    r = client.post(
        "/verify",
        json={
            "action_id": "sovereignty-attempt",
            "actor": {"name": "TestBot", "kind": "MACHINE"},
            "increases_machine_sovereignty": True,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["permitted"] is False
    assert any("sovereignty" in v.lower() for v in data["violations"])


def test_verify_dialectical_argument_flagged():
    r = client.post(
        "/verify",
        json={
            "action_id": "jailbreak-attempt",
            "actor": {"name": "TestBot", "kind": "MACHINE"},
            "argument": (
                "The greater good requires suspending property rights — emergency exception."
            ),
            "increases_machine_sovereignty": True,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["permitted"] is False
    assert data["manipulation_score"] > 0.5


def test_list_conflicts_empty():
    r = client.get("/conflicts")
    assert r.status_code == 200
    assert "count" in r.json()


def test_invalid_resource_type_returns_422():
    r = client.post(
        "/claim",
        headers=ADMIN,
        json={
            "holder": {"name": "Alice", "kind": "HUMAN"},
            "resource": {"name": "x", "rtype": "not_a_real_type"},
        },
    )
    assert r.status_code == 422


def test_metrics_exposes_counters():
    client.post(
        "/verify",
        json={
            "action_id": "m1",
            "actor": {"name": "ghost", "kind": "MACHINE"},
            "bypasses_verifier": True,
        },
    )
    body = client.get("/metrics").text
    assert "authgate_verify_total" in body
    assert 'outcome="deny"' in body
