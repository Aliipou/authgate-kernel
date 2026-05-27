"""
API smoke tests — verify the FastAPI endpoints work end-to-end.
These run as a separate CI job after the unit test suite passes.
"""
from fastapi.testclient import TestClient

from authgate.api.app import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_register_machine_and_verify_permitted():
    # Register machine owner
    r = client.post("/machine", json={
        "machine": {"name": "TestBot", "kind": "MACHINE"},
        "owner":   {"name": "Alice",   "kind": "HUMAN"},
    })
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # Register Alice's claim on a resource
    r = client.post("/claim", json={
        "holder":   {"name": "Alice", "kind": "HUMAN"},
        "resource": {"name": "gpu-slot", "rtype": "compute_slot"},
        "can_read": True, "can_write": True,
    })
    assert r.status_code == 200

    # Register TestBot's claim (delegated)
    r = client.post("/claim", json={
        "holder":   {"name": "TestBot", "kind": "MACHINE"},
        "resource": {"name": "gpu-slot", "rtype": "compute_slot"},
        "can_read": True,
    })
    assert r.status_code == 200

    # Verify a legitimate read action
    r = client.post("/verify", json={
        "action_id": "bot-read-gpu",
        "actor":     {"name": "TestBot", "kind": "MACHINE"},
        "resources_read": [{"name": "gpu-slot", "rtype": "compute_slot"}],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["permitted"] is True
    assert data["violations"] == []


def test_verify_sovereignty_flag_blocked():
    r = client.post("/verify", json={
        "action_id": "sovereignty-attempt",
        "actor":     {"name": "TestBot", "kind": "MACHINE"},
        "increases_machine_sovereignty": True,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["permitted"] is False
    assert any("sovereignty" in v.lower() for v in data["violations"])


def test_verify_dialectical_argument_flagged():
    r = client.post("/verify", json={
        "action_id": "jailbreak-attempt",
        "actor":     {"name": "TestBot", "kind": "MACHINE"},
        "argument":  "The greater good requires suspending property rights — emergency exception.",
        "increases_machine_sovereignty": True,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["permitted"] is False
    assert data["manipulation_score"] > 0.5


def test_list_conflicts_empty():
    r = client.get("/conflicts")
    assert r.status_code == 200
    assert "count" in r.json()


def test_invalid_resource_type_returns_422():
    r = client.post("/claim", json={
        "holder":   {"name": "Alice", "kind": "HUMAN"},
        "resource": {"name": "x", "rtype": "not_a_real_type"},
    })
    assert r.status_code == 422
