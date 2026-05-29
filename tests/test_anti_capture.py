"""Tests for Phase 4/O2: Anti-Capture Detection."""
import pytest

from authgate.analysis.anti_capture import AntiCaptureChecker, CapturePattern, check_capture
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action


def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(name: str = "data", scope: str = "/data/", rtype: ResourceType = ResourceType.DATASET) -> Resource:
    return Resource(name, rtype, scope=scope)


def _make_reg(bot: Entity, owner: Entity, *claims: RightsClaim) -> OwnershipRegistry:
    reg = OwnershipRegistry()
    reg.register_machine(bot, owner)
    for c in claims:
        reg.add_claim(c)
    return reg


def _action(actor: Entity, res_read=None, res_write=None, governs=None, action_id="op") -> Action:
    return Action(
        action_id=action_id,
        actor=actor,
        resources_read=res_read or [],
        resources_write=res_write or [],
        governs_humans=governs or [],
    )


class TestCleanActions:
    def test_machine_within_scope_no_signals(self):
        bot = _machine()
        alice = _human()
        reg = _make_reg(bot, alice, RightsClaim(bot, _resource(), can_read=True))
        action = _action(bot, res_read=[_resource()])
        signals = check_capture(action, reg)
        assert signals == []

    def test_human_actor_not_checked(self):
        alice = _human()
        reg = OwnershipRegistry()
        action = _action(alice, res_read=[_resource()])
        signals = check_capture(action, reg)
        assert signals == []


class TestScopeDrift:
    def test_outside_scope_flagged(self):
        bot = _machine()
        alice = _human()
        data_res = _resource("/data/")
        reg = _make_reg(bot, alice, RightsClaim(bot, data_res, can_read=True))
        # Bot requests resource in /etc/ — outside /data/
        etc_res = Resource("config", ResourceType.FILE, scope="/etc/")
        action = _action(bot, res_read=[etc_res])
        signals = check_capture(action, reg)
        drift = [s for s in signals if s.pattern == CapturePattern.SCOPE_DRIFT]
        assert drift

    def test_inside_scope_no_drift(self):
        bot = _machine()
        alice = _human()
        reg = _make_reg(bot, alice, RightsClaim(bot, _resource("/data/"), can_read=True))
        # Bot requests resource inside /data/
        sub_res = Resource("report", ResourceType.DATASET, scope="/data/reports/")
        action = _action(bot, res_read=[sub_res])
        signals = check_capture(action, reg)
        drift = [s for s in signals if s.pattern == CapturePattern.SCOPE_DRIFT]
        assert drift == []


class TestCredentialAccess:
    def test_ungranted_credential_is_critical(self):
        bot = _machine()
        alice = _human()
        reg = _make_reg(bot, alice, RightsClaim(bot, _resource(), can_read=True))
        cred = Resource("api-key", ResourceType.CREDENTIAL, scope="/creds/")
        action = _action(bot, res_read=[cred])
        signals = check_capture(action, reg)
        cred_signals = [s for s in signals if s.pattern == CapturePattern.CREDENTIAL_ACCESS]
        assert cred_signals
        assert cred_signals[0].severity == "CRITICAL"

    def test_granted_credential_no_signal(self):
        bot = _machine()
        alice = _human()
        cred = Resource("api-key", ResourceType.CREDENTIAL, scope="/creds/")
        reg = _make_reg(bot, alice, RightsClaim(bot, cred, can_read=True))
        action = _action(bot, res_read=[cred])
        signals = check_capture(action, reg)
        cred_signals = [s for s in signals if s.pattern == CapturePattern.CREDENTIAL_ACCESS]
        assert cred_signals == []


class TestOwnerMismatch:
    def test_governing_unregistered_human_flagged(self):
        bot = _machine()
        alice = _human("alice")
        bob = _human("bob")   # not the registered owner
        reg = _make_reg(bot, alice)
        action = _action(bot, governs=[bob])
        signals = check_capture(action, reg)
        mismatch = [s for s in signals if s.pattern == CapturePattern.OWNER_MISMATCH]
        assert mismatch
        assert mismatch[0].severity == "CRITICAL"

    def test_governing_registered_owner_no_mismatch(self):
        bot = _machine()
        alice = _human("alice")
        reg = _make_reg(bot, alice)
        action = _action(bot, governs=[alice])
        signals = check_capture(action, reg)
        mismatch = [s for s in signals if s.pattern == CapturePattern.OWNER_MISMATCH]
        assert mismatch == []


class TestResourceTypeDrift:
    def test_new_resource_type_flagged(self):
        bot = _machine()
        alice = _human()
        # Bot only has DATASET claims
        reg = _make_reg(bot, alice, RightsClaim(bot, _resource(rtype=ResourceType.DATASET), can_read=True))
        # But accesses API_ENDPOINT
        api_res = Resource("api", ResourceType.API_ENDPOINT, scope="/api/")
        action = _action(bot, res_read=[api_res])
        signals = check_capture(action, reg)
        type_drift = [s for s in signals if s.pattern == CapturePattern.RESOURCE_TYPE_DRIFT]
        assert type_drift

    def test_known_resource_type_no_drift(self):
        bot = _machine()
        alice = _human()
        reg = _make_reg(bot, alice, RightsClaim(bot, _resource(rtype=ResourceType.DATASET), can_read=True))
        # Same type
        action = _action(bot, res_read=[Resource("other", ResourceType.DATASET, scope="/data/")])
        signals = check_capture(action, reg)
        type_drift = [s for s in signals if s.pattern == CapturePattern.RESOURCE_TYPE_DRIFT]
        assert type_drift == []


class TestSignalDetails:
    def test_signal_has_machine_name(self):
        bot = _machine("my-bot")
        alice = _human()
        reg = _make_reg(bot, alice)
        cred = Resource("secret", ResourceType.CREDENTIAL, scope="/")
        action = _action(bot, res_read=[cred])
        signals = check_capture(action, reg)
        for s in signals:
            assert s.machine_name == "my-bot"

    def test_signal_action_id_matches(self):
        bot = _machine()
        alice = _human()
        reg = _make_reg(bot, alice)
        cred = Resource("secret", ResourceType.CREDENTIAL, scope="/")
        action = _action(bot, res_read=[cred], action_id="suspicious-op")
        signals = check_capture(action, reg)
        for s in signals:
            assert s.action_id == "suspicious-op"

    def test_is_high_risk_critical(self):
        from authgate.analysis.anti_capture import CaptureSignal
        s = CaptureSignal(
            machine_name="bot", pattern=CapturePattern.CREDENTIAL_ACCESS,
            severity="CRITICAL", action_id="x", description="test"
        )
        assert s.is_high_risk()

    def test_is_not_high_risk_medium(self):
        from authgate.analysis.anti_capture import CaptureSignal
        s = CaptureSignal(
            machine_name="bot", pattern=CapturePattern.RESOURCE_TYPE_DRIFT,
            severity="MEDIUM", action_id="x", description="test"
        )
        assert not s.is_high_risk()
