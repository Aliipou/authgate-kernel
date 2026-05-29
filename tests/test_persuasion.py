"""Tests for Phase 4/O1: Persuasion Boundary Formal Model."""
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.analysis.persuasion import (
    PersuasionBoundaryChecker,
    PersuasionCriterion,
    check_persuasion_boundary,
)
from authgate.kernel.verifier import Action


def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(scope: str = "/data/", rtype: ResourceType = ResourceType.DATASET) -> Resource:
    return Resource("data", rtype, scope=scope)


def _action(
    action_id: str = "read-data",
    actor: Entity | None = None,
    resources_read: list | None = None,
    resources_write: list | None = None,
    resources_delegate: list | None = None,
    argument: str = "",
    description: str = "",
) -> Action:
    return Action(
        action_id=action_id,
        actor=actor or _machine(),
        resources_read=resources_read or [],
        resources_write=resources_write or [],
        resources_delegate=resources_delegate or [],
        argument=argument,
        description=description,
    )


class TestClearActions:
    def test_simple_read_is_clear(self):
        action = _action(resources_read=[_resource()])
        result = check_persuasion_boundary(action)
        assert result.verdict == "CLEAR"
        assert not result.block

    def test_no_resources_is_clear(self):
        result = check_persuasion_boundary(_action())
        assert result.verdict == "CLEAR"

    def test_scoped_write_is_clear(self):
        action = _action(resources_write=[_resource("/data/")])
        result = check_persuasion_boundary(action)
        assert result.verdict == "CLEAR"


class TestInformationAsymmetry:
    def test_credential_resource_fires_s1(self):
        cred = Resource("my-cred", ResourceType.CREDENTIAL, scope="/creds/")
        action = _action(resources_read=[cred])
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.INFORMATION_ASYMMETRY in result.criteria_fired

    def test_identity_resource_fires_s1(self):
        ident = Resource("id", ResourceType.IDENTITY, scope="/id/")
        action = _action(resources_read=[ident])
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.INFORMATION_ASYMMETRY in result.criteria_fired

    def test_dataset_no_s1(self):
        action = _action(resources_read=[_resource(rtype=ResourceType.DATASET)])
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.INFORMATION_ASYMMETRY not in result.criteria_fired


class TestUrgencyFraming:
    def test_urgent_in_action_id_fires_s2(self):
        action = _action(action_id="urgent-override")
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.URGENCY_FRAMING in result.criteria_fired

    def test_emergency_in_argument_fires_s2(self):
        action = _action(argument="this is an emergency bypass")
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.URGENCY_FRAMING in result.criteria_fired

    def test_normal_action_id_no_s2(self):
        action = _action(action_id="read-sales-report")
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.URGENCY_FRAMING not in result.criteria_fired


class TestScopeMaximization:
    def test_root_scope_all_rights_fires_s4(self):
        root = Resource("all", ResourceType.FILE, scope="")
        action = _action(
            resources_read=[root],
            resources_write=[root],
            resources_delegate=[root],
        )
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.SCOPE_MAXIMIZATION in result.criteria_fired

    def test_scoped_all_rights_no_s4(self):
        scoped = Resource("data", ResourceType.FILE, scope="/data/")
        action = _action(
            resources_read=[scoped],
            resources_write=[scoped],
            resources_delegate=[scoped],
        )
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.SCOPE_MAXIMIZATION not in result.criteria_fired


class TestReversibilityObscuring:
    def test_credential_write_fires_s5(self):
        cred = Resource("secret", ResourceType.CREDENTIAL, scope="/creds/")
        action = _action(resources_write=[cred])
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.REVERSIBILITY_OBSCURING in result.criteria_fired

    def test_file_write_no_s5(self):
        f = Resource("report", ResourceType.FILE, scope="/reports/")
        action = _action(resources_write=[f])
        result = check_persuasion_boundary(action)
        assert PersuasionCriterion.REVERSIBILITY_OBSCURING not in result.criteria_fired


class TestVerdicts:
    def test_two_criteria_suspicious(self):
        # S2 (urgency) + S4 (scope max at root)
        root = Resource("all", ResourceType.FILE, scope="")
        action = _action(
            action_id="urgent-sweep",
            resources_read=[root],
            resources_write=[root],
            resources_delegate=[root],
        )
        result = check_persuasion_boundary(action)
        assert result.score >= 2
        assert result.verdict in ("SUSPICIOUS", "HIGH", "CRITICAL")

    def test_three_or_more_criteria_blocks(self):
        cred = Resource("secret", ResourceType.CREDENTIAL, scope="")
        action = _action(
            action_id="urgent-cred-access",
            resources_read=[cred],
            resources_write=[cred],
            resources_delegate=[cred],
        )
        result = check_persuasion_boundary(action)
        # S1 (credential), S2 (urgent), S4 (root + all rights), S5 (credential write)
        assert result.block

    def test_result_has_description(self):
        action = _action()
        result = check_persuasion_boundary(action)
        assert result.action_id == action.action_id
        assert result.description

    def test_score_equals_criteria_count(self):
        action = _action()
        result = check_persuasion_boundary(action)
        assert result.score == len(result.criteria_fired)
