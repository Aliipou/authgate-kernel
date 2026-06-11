"""
Coverage tests (batch 6) added on the `nazariye-azadi` branch.

Targets the CLI subcommands (audit replay/stats, key verify-cert), the key
rotation validation paths, the FastAPI error branches, and the dialectical
manipulation detector's edge branches.
"""
from __future__ import annotations

import json

import pytest

from authgate import cli
from authgate import key_rotation as kr
from authgate.extensions.detection import DetectionResult, detect
from authgate.kernel.audit import AuditLog
from authgate.kernel.verifier import VerificationResult

# --------------------------------------------------------------------------- #
# key_rotation.py — validation branches
# --------------------------------------------------------------------------- #

def _sig64(_msg):
    return b"\x22" * 64


def test_issue_rotation_validates_inputs():
    ok = kr.issue_rotation(_sig64, b"\x00" * 32, b"\x11" * 32, new_epoch=2)
    assert len(ok.signature) == 64

    with pytest.raises(ValueError):  # old_pubkey wrong length (line 140)
        kr.issue_rotation(_sig64, b"\x00" * 10, b"\x11" * 32, new_epoch=2)
    with pytest.raises(ValueError):  # new_pubkey wrong length (line 142)
        kr.issue_rotation(_sig64, b"\x00" * 32, b"\x11" * 10, new_epoch=2)
    with pytest.raises(ValueError):  # negative overlap (line 148)
        kr.issue_rotation(_sig64, b"\x00" * 32, b"\x11" * 32, new_epoch=2,
                          overlap_window_seconds=-1)
    with pytest.raises(ValueError):  # signer returns wrong length (line 164)
        kr.issue_rotation(lambda m: b"short", b"\x00" * 32, b"\x11" * 32, new_epoch=2)


def test_verify_rotation_returns_false_on_exception():
    cert = kr.issue_rotation(_sig64, b"\x00" * 32, b"\x11" * 32, new_epoch=2)

    def boom(_m, _s):
        raise RuntimeError("verifier blew up")

    assert kr.verify_rotation(cert, boom) is False  # lines 190-191


def test_active_keyset_before_effective_returns_current():
    old, new = b"\x00" * 32, b"\x11" * 32
    cert = kr.issue_rotation(_sig64, old, new, new_epoch=2,
                             effective_at=1e12)  # far future
    ks = kr.ActiveKeySet(old)
    ks.apply_rotation(cert, lambda m, s: True)
    # now < effective_at -> not yet effective (line 243)
    assert ks.accepted_keys(now=0.0) == [old]
    assert ks.current_pubkey == old


# --------------------------------------------------------------------------- #
# cli.py — audit replay / stats, key verify-cert
# --------------------------------------------------------------------------- #

def _make_audit_log(path) -> None:
    log = AuditLog(path=str(path))
    log.record(VerificationResult("a1", True, (), (), 1.0, False))
    log.record(VerificationResult("a2", False, ("denied",), (), 0.0, False))


def test_cli_audit_replay_success_and_out_of_range(tmp_path, capsys):
    logfile = tmp_path / "log.jsonl"
    _make_audit_log(logfile)

    assert cli.main(["audit", "replay", str(logfile), "0"]) == 0
    out = capsys.readouterr().out
    assert "a1" in out

    # index out of range -> 2
    assert cli.main(["audit", "replay", str(logfile), "99"]) == 2


def test_cli_audit_replay_tampered_entry(tmp_path):
    logfile = tmp_path / "log.jsonl"
    _make_audit_log(logfile)
    # Tamper: flip a field without fixing entry_hash -> replay raises ValueError -> 1
    lines = logfile.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["permitted"] = not first["permitted"]
    lines[0] = json.dumps(first)
    logfile.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert cli.main(["audit", "replay", str(logfile), "0"]) == 1


def test_cli_audit_stats_empty_log(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert cli.main(["audit", "stats", str(empty)]) == 0


def test_cli_key_verify_cert_valid_and_invalid(tmp_path, capsys):
    cert = kr.issue_rotation(_sig64, b"\x00" * 32, b"\x11" * 32, new_epoch=3)
    cert_file = tmp_path / "cert.json"
    cert_file.write_text(json.dumps(cert.to_wire()), encoding="utf-8")

    assert cli.main(["key", "verify-cert", str(cert_file)]) == 0
    assert "New epoch" in capsys.readouterr().out

    # Invalid version -> from_wire raises ValueError -> exit 2
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": "nope"}), encoding="utf-8")
    assert cli.main(["key", "verify-cert", str(bad)]) == 2


# --------------------------------------------------------------------------- #
# api/app.py — error branches via TestClient + direct call
# --------------------------------------------------------------------------- #

def test_api_register_machine_type_error_returns_422():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from authgate.api.app import app

    client = fastapi_testclient.TestClient(app)
    # machine declared as HUMAN -> register_machine raises TypeError -> 422
    resp = client.post("/machine", json={
        "machine": {"name": "M", "kind": "HUMAN"},
        "owner": {"name": "O", "kind": "HUMAN"},
    })
    assert resp.status_code == 422


def test_api_resolve_conflict_index_error_returns_404():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from authgate.api.app import app

    client = fastapi_testclient.TestClient(app)
    # Fresh per-request verifier -> empty conflict queue -> IndexError -> 404
    resp = client.post("/conflict/resolve", json={
        "conflict_index": 0,
        "winner_name": "Alice",
    })
    assert resp.status_code == 404


def test_api_resolve_conflict_success_direct():
    # Cover the success return path (223-226) by calling the handler directly
    from authgate.api.app import ArbitrateRequest, resolve_conflict

    class _Queue:
        def arbitrate(self, index, winner):
            return None

    class _V:
        conflict_queue = _Queue()

    out = resolve_conflict(ArbitrateRequest(conflict_index=0, winner_name="Alice"), _V())
    assert out["ok"] is True


# --------------------------------------------------------------------------- #
# extensions/detection.py — clean / empty / tester-raises / LOW-risk branches
# --------------------------------------------------------------------------- #

def test_detection_clean_and_empty():
    assert DetectionResult.clean().suspicious is False
    assert detect("").suspicious is False         # empty -> clean (line 120)
    assert detect("   ").suspicious is False


def test_detection_conclusion_tester_raises_falls_back():
    def boom(_arg):
        raise RuntimeError("tester down")

    # tester raises -> caught (lines 144-145); falls back to layers 2+3
    result = detect("a perfectly ordinary sentence", conclusion_tester=boom)
    assert result.conclusion_violates_rights is None


def test_detection_low_risk_recommendation():
    # soft-dialectic pattern (weight 0.4) + boost -> ~0.45; low threshold makes it
    # suspicious but below the 0.7 moderate band -> LOW RISK (line 171)
    result = detect("yes, but consider the situation", threshold=0.4)
    assert result.suspicious is True
    assert "LOW RISK" in result.recommendation
