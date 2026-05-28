"""
CLI integration tests — authgate-cli verify / audit / key commands.

Tests use temp files and subprocess-free invocation (call main() directly)
so they run without the package being installed as a console_script.

Run: pytest tests/test_cli.py -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure src/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authgate.cli import build_parser, cmd_audit_stats, cmd_audit_verify, cmd_verify


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

REGISTRY_DATA = {
    "agents": [
        {"id": "alice", "kind": "HUMAN"},
        {"id": "bot",   "kind": "MACHINE"},
    ],
    "machine_owners": [
        {"machine": "bot", "owner": "alice"},
    ],
    "resources": [
        {"id": "sales", "type": "DATASET", "scope": "/data/sales/"},
    ],
    "claims": [
        {"holder": "bot", "resource": "sales", "can_read": True},
    ],
}

ACTION_PERMIT = {
    "action_id": "test-read",
    "actor": "bot",
    "resources_read": ["sales"],
}

ACTION_DENY = {
    "action_id": "test-sovereignty",
    "actor": "bot",
    "resources_read": ["sales"],
    "increases_machine_sovereignty": True,
}

ACTION_UNOWNED = {
    "action_id": "test-unowned",
    "actor": "orphan",  # not registered
    "resources_read": ["sales"],
}


def _write_json(obj: dict, suffix: str = ".json") -> str:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    json.dump(obj, f)
    f.close()
    return f.name


@pytest.fixture()
def reg_file():
    path = _write_json(REGISTRY_DATA)
    yield path
    os.unlink(path)


@pytest.fixture()
def permit_action_file():
    path = _write_json(ACTION_PERMIT)
    yield path
    os.unlink(path)


@pytest.fixture()
def deny_action_file():
    path = _write_json(ACTION_DENY)
    yield path
    os.unlink(path)


@pytest.fixture()
def unowned_action_file():
    path = _write_json(ACTION_UNOWNED)
    yield path
    os.unlink(path)


def _parse(argv: list[str]):
    parser = build_parser()
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# cmd_verify
# ---------------------------------------------------------------------------

class TestCmdVerify:
    def test_permit_returns_0(self, reg_file, permit_action_file):
        args = _parse(["verify", "--registry", reg_file, "--action", permit_action_file])
        assert args.func(args) == 0

    def test_deny_returns_1(self, reg_file, deny_action_file):
        args = _parse(["verify", "--registry", reg_file, "--action", deny_action_file])
        assert args.func(args) == 1

    def test_unowned_actor_denied(self, reg_file, unowned_action_file):
        args = _parse(["verify", "--registry", reg_file, "--action", unowned_action_file])
        assert args.func(args) == 1

    def test_json_output_parseable(self, reg_file, permit_action_file, capsys):
        args = _parse([
            "verify", "--registry", reg_file, "--action", permit_action_file, "--json"
        ])
        args.func(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["permitted"] is True
        assert "violations" in data
        assert "confidence" in data

    def test_audit_log_written(self, reg_file, permit_action_file):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            args = _parse([
                "verify", "--registry", reg_file,
                "--action", permit_action_file,
                "--audit", audit_path,
            ])
            args.func(args)
            with open(audit_path, encoding="utf-8") as f:
                lines = f.readlines()
            assert len(lines) == 1
            entry = json.loads(lines[0])
            assert entry["permitted"] is True
        finally:
            os.unlink(audit_path)

    def test_missing_registry_file_exits_2(self, permit_action_file):
        args = _parse(["verify", "--registry", "/nonexistent/reg.json",
                       "--action", permit_action_file])
        with pytest.raises(SystemExit) as exc:
            args.func(args)
        assert exc.value.code == 2

    def test_invalid_registry_json_exits_2(self, permit_action_file):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write("not json")
            bad_path = f.name
        try:
            args = _parse(["verify", "--registry", bad_path, "--action", permit_action_file])
            with pytest.raises(SystemExit) as exc:
                args.func(args)
            assert exc.value.code == 2
        finally:
            os.unlink(bad_path)


# ---------------------------------------------------------------------------
# cmd_audit_verify / cmd_audit_stats
# ---------------------------------------------------------------------------

class TestCmdAuditVerify:
    def _make_log(self, n: int = 5) -> str:
        from authgate.kernel.audit import AuditLog
        from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
        from authgate.kernel.registry import OwnershipRegistry
        from authgate.kernel.verifier import Action, FreedomVerifier

        human = Entity("owner", AgentType.HUMAN)
        bot = Entity("bot", AgentType.MACHINE)
        res = Resource("r", ResourceType.DATASET, scope="/data/")
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        reg.add_claim(RightsClaim(bot, res, can_read=True))

        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False
        ) as f:
            path = f.name

        log = AuditLog(path=path)
        v = FreedomVerifier(reg.freeze(), audit_log=log)
        for i in range(n):
            v.verify(Action(f"e{i}", actor=bot, resources_read=[res]))
        return path

    def test_valid_chain_returns_0(self):
        path = self._make_log(5)
        try:
            args = _parse(["audit", "verify", path])
            assert args.func(args) == 0
        finally:
            os.unlink(path)

    def test_tampered_chain_returns_1(self):
        from authgate.kernel.audit import AuditLog

        path = self._make_log(5)
        try:
            log, _ = AuditLog.load_and_verify(path)
            with log._lock:
                log._records[2]["permitted"] = not log._records[2]["permitted"]
            # Write tampered records back to file
            with open(path, "w", encoding="utf-8") as f:
                import json as _json
                for r in log._records:
                    f.write(_json.dumps(r) + "\n")
            args = _parse(["audit", "verify", path])
            assert args.func(args) == 1
        finally:
            os.unlink(path)

    def test_stats_outputs_counts(self, capsys):
        path = self._make_log(3)
        try:
            args = _parse(["audit", "stats", path])
            args.func(args)
            out = capsys.readouterr().out
            assert "entries" in out
            assert "permitted" in out
            assert "chain" in out
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Parser structure
# ---------------------------------------------------------------------------

class TestParserStructure:
    def test_verify_requires_registry_and_action(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["verify"])

    def test_audit_subcommands_present(self):
        args = _parse(["audit", "verify", "some.jsonl"])
        assert args.audit_command == "verify"

    def test_json_flag_default_false(self, reg_file, permit_action_file):
        args = _parse(["verify", "--registry", reg_file, "--action", permit_action_file])
        assert args.json is False
