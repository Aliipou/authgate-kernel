"""
Policy DSL parser tests — coverage for policy_dsl.py.

Covers: parse(), to_policy(), compile(); error paths (PolicyDSLSyntaxError);
comments, blank lines, wildcards, conditions, multi-statement policies,
and end-to-end DSL → Policy → evaluate() flows.
"""
from __future__ import annotations

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType
from authgate.kernel.policy_dsl import (
    PolicyDSL,
    PolicyDSLSyntaxError,
    PolicyStatement,
    compile as compile_policy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entity(name: str, kind: AgentType = AgentType.MACHINE) -> Entity:
    return Entity(name, kind)


def _resource(scope: str = "/data") -> Resource:
    return Resource("r", ResourceType.FILE, scope=scope)


# ---------------------------------------------------------------------------
# parse() — basic well-formed inputs
# ---------------------------------------------------------------------------

class TestParseBasic:
    def test_single_allow_read(self):
        stmts = PolicyDSL.parse("""
            ALLOW alice
              READ /data/reports/*
        """)
        assert len(stmts) == 1
        s = stmts[0]
        assert s.effect == "ALLOW"
        assert s.subject == "alice"
        assert "READ" in s.operations
        assert s.resource_scope == "/data/reports/*"

    def test_single_deny_write(self):
        stmts = PolicyDSL.parse("""
            DENY *
              WRITE /restricted/*
        """)
        assert len(stmts) == 1
        s = stmts[0]
        assert s.effect == "DENY"
        assert s.subject == "*"
        assert "WRITE" in s.operations

    def test_multiple_statements(self):
        stmts = PolicyDSL.parse("""
            ALLOW agent:AnalystBot
              READ /data/*

            DENY *
              WRITE /restricted/*
        """)
        assert len(stmts) == 2
        assert stmts[0].effect == "ALLOW"
        assert stmts[1].effect == "DENY"

    def test_multiple_operations_in_one_statement(self):
        stmts = PolicyDSL.parse("""
            ALLOW alice
              READ /data/*
              WRITE /outputs/*
        """)
        assert len(stmts) == 1
        assert "READ" in stmts[0].operations
        assert "WRITE" in stmts[0].operations

    def test_wildcard_operation_star_scope(self):
        stmts = PolicyDSL.parse("""
            ALLOW human:Alice
              READ *
              WRITE *
              DELEGATE *
        """)
        assert len(stmts) == 1
        assert stmts[0].resource_scope == "*"


# ---------------------------------------------------------------------------
# parse() — comment and whitespace handling
# ---------------------------------------------------------------------------

class TestParseCommentsAndBlanks:
    def test_full_line_comment_ignored(self):
        stmts = PolicyDSL.parse("""
            # This is a comment
            ALLOW alice
              READ /data/*
        """)
        assert len(stmts) == 1

    def test_inline_comment_stripped(self):
        stmts = PolicyDSL.parse("""
            ALLOW alice  # grant alice access
              READ /data/*  # read-only for now
        """)
        assert len(stmts) == 1
        assert stmts[0].subject == "alice"
        assert "/data/*" in stmts[0].resource_scope

    def test_blank_lines_between_statements(self):
        stmts = PolicyDSL.parse("""
            ALLOW alice
              READ /data/*


            DENY bob
              WRITE /restricted/*

        """)
        assert len(stmts) == 2

    def test_only_comments_and_blanks_returns_empty(self):
        stmts = PolicyDSL.parse("""
            # just a comment
            # and another
        """)
        assert stmts == []

    def test_empty_text_returns_empty(self):
        assert PolicyDSL.parse("") == []


# ---------------------------------------------------------------------------
# parse() — subject patterns
# ---------------------------------------------------------------------------

class TestParseSubjectPatterns:
    def test_agent_prefix(self):
        stmts = PolicyDSL.parse("ALLOW agent:AnalystBot\n  READ *")
        assert stmts[0].subject == "agent:AnalystBot"

    def test_human_prefix(self):
        stmts = PolicyDSL.parse("ALLOW human:Alice\n  READ *")
        assert stmts[0].subject == "human:Alice"

    def test_wildcard_subject(self):
        stmts = PolicyDSL.parse("DENY *\n  WRITE /restricted/*")
        assert stmts[0].subject == "*"

    def test_plain_name_subject(self):
        stmts = PolicyDSL.parse("ALLOW ResearchBot\n  READ /data/*")
        assert stmts[0].subject == "ResearchBot"


# ---------------------------------------------------------------------------
# parse() — conditions
# ---------------------------------------------------------------------------

class TestParseConditions:
    def test_unless_condition(self):
        stmts = PolicyDSL.parse("""
            ALLOW ResearchBot
              READ dataset/alice/*
              UNLESS delegated_by Alice
        """)
        assert stmts[0].conditions.get("UNLESS") == "delegated_by Alice"

    def test_max_delegation_depth(self):
        stmts = PolicyDSL.parse("""
            ALLOW agent:AnalystBot
              READ /data/reports/*
              MAX_DELEGATION_DEPTH 2
        """)
        assert stmts[0].conditions.get("MAX_DELEGATION_DEPTH") == "2"

    def test_expires_condition(self):
        stmts = PolicyDSL.parse("""
            ALLOW alice
              READ /data/*
              EXPIRES 3600
        """)
        assert stmts[0].conditions.get("EXPIRES") == "3600"

    def test_trust_domain_condition(self):
        stmts = PolicyDSL.parse("""
            ALLOW human:Alice
              READ *
              TRUST_DOMAIN internal
        """)
        assert stmts[0].conditions.get("TRUST_DOMAIN") == "internal"

    def test_multiple_conditions_on_one_statement(self):
        stmts = PolicyDSL.parse("""
            ALLOW agent:AnalystBot
              READ /data/reports/*
              MAX_DELEGATION_DEPTH 2
              EXPIRES 3600
              TRUST_DOMAIN internal
        """)
        c = stmts[0].conditions
        assert c["MAX_DELEGATION_DEPTH"] == "2"
        assert c["EXPIRES"] == "3600"
        assert c["TRUST_DOMAIN"] == "internal"


# ---------------------------------------------------------------------------
# parse() — error paths (PolicyDSLSyntaxError)
# ---------------------------------------------------------------------------

class TestParseSyntaxErrors:
    def test_indented_line_without_header(self):
        with pytest.raises(PolicyDSLSyntaxError) as exc:
            PolicyDSL.parse("  READ /data/*")
        assert exc.value.line_number == 1

    def test_allow_without_subject(self):
        with pytest.raises(PolicyDSLSyntaxError) as exc:
            PolicyDSL.parse("ALLOW\n  READ /data/*")
        assert "subject" in exc.value.message.lower() or "ALLOW" in exc.value.message

    def test_deny_without_subject(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("DENY\n  READ /data/*")

    def test_unknown_effect_keyword(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("GRANT alice\n  READ /data/*")

    def test_statement_with_no_operations(self):
        with pytest.raises(PolicyDSLSyntaxError) as exc:
            PolicyDSL.parse("ALLOW alice\nDENY bob\n  READ /data/*")
        assert "operations" in exc.value.message.lower() or "no operations" in exc.value.message

    def test_max_delegation_depth_missing_value(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("ALLOW alice\n  READ /data/*\n  MAX_DELEGATION_DEPTH")

    def test_max_delegation_depth_non_integer(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("ALLOW alice\n  READ /data/*\n  MAX_DELEGATION_DEPTH two")

    def test_expires_missing_value(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("ALLOW alice\n  READ /data/*\n  EXPIRES")

    def test_expires_non_integer(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("ALLOW alice\n  READ /data/*\n  EXPIRES 1h")

    def test_unless_missing_argument(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("ALLOW alice\n  READ /data/*\n  UNLESS")

    def test_trust_domain_missing_argument(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("ALLOW alice\n  READ /data/*\n  TRUST_DOMAIN")

    def test_error_has_line_number(self):
        text = "ALLOW alice\n  READ /data/*\n  MAX_DELEGATION_DEPTH bad"
        with pytest.raises(PolicyDSLSyntaxError) as exc:
            PolicyDSL.parse(text)
        assert exc.value.line_number == 3

    def test_invalid_subject_chars(self):
        with pytest.raises(PolicyDSLSyntaxError):
            PolicyDSL.parse("ALLOW alice bob charlie\n  READ *")


# ---------------------------------------------------------------------------
# to_policy() — IR compilation
# ---------------------------------------------------------------------------

class TestToPolicy:
    def test_allow_becomes_permit_rule(self):
        stmts = PolicyDSL.parse("ALLOW alice\n  READ /data/*")
        policy = PolicyDSL.to_policy(stmts, name="p")
        assert policy.rules[0].effect == "permit"

    def test_deny_becomes_deny_rule(self):
        stmts = PolicyDSL.parse("DENY *\n  WRITE /restricted/*")
        policy = PolicyDSL.to_policy(stmts, name="p")
        assert policy.rules[0].effect == "deny"

    def test_wildcard_subject_becomes_empty_pattern(self):
        stmts = PolicyDSL.parse("ALLOW *\n  READ *")
        policy = PolicyDSL.to_policy(stmts, name="p")
        assert policy.rules[0].actor_pattern == ""

    def test_named_subject_becomes_actor_pattern(self):
        stmts = PolicyDSL.parse("ALLOW alice\n  READ *")
        policy = PolicyDSL.to_policy(stmts, name="p")
        assert policy.rules[0].actor_pattern == "alice"

    def test_wildcard_scope_becomes_empty_scope(self):
        stmts = PolicyDSL.parse("ALLOW alice\n  READ *")
        policy = PolicyDSL.to_policy(stmts, name="p")
        assert policy.rules[0].resource_scope == ""

    def test_operations_lowercased(self):
        stmts = PolicyDSL.parse("ALLOW alice\n  READ *\n  WRITE *")
        policy = PolicyDSL.to_policy(stmts, name="p")
        assert "read" in policy.rules[0].operations
        assert "write" in policy.rules[0].operations

    def test_priority_ordering_first_statement_highest(self):
        stmts = PolicyDSL.parse("""
            ALLOW alice
              READ *
            DENY *
              WRITE *
        """)
        policy = PolicyDSL.to_policy(stmts, name="p")
        priorities = [r.priority for r in policy.rules]
        assert priorities[0] > priorities[1]

    def test_policy_name_set(self):
        stmts = PolicyDSL.parse("ALLOW alice\n  READ *")
        policy = PolicyDSL.to_policy(stmts, name="my-policy")
        assert policy.name == "my-policy"

    def test_empty_statements_produces_empty_policy(self):
        policy = PolicyDSL.to_policy([], name="empty")
        assert policy.rules == []


# ---------------------------------------------------------------------------
# compile() convenience function
# ---------------------------------------------------------------------------

class TestCompile:
    def test_compile_returns_policy(self):
        policy = compile_policy("ALLOW alice\n  READ /data/*", name="p")
        assert policy.name == "p"
        assert len(policy.rules) == 1

    def test_compile_raises_on_syntax_error(self):
        with pytest.raises(PolicyDSLSyntaxError):
            compile_policy("GRANT alice\n  READ *", name="p")

    def test_compile_multiline_docstring_style(self):
        policy = compile_policy("""
            ALLOW agent:AnalystBot
              READ /data/reports/*
              WRITE /outputs/analysis/*
              MAX_DELEGATION_DEPTH 2
              EXPIRES 3600
        """, name="analyst")
        assert policy.rules[0].effect == "permit"
        assert "read" in policy.rules[0].operations
        assert "write" in policy.rules[0].operations


# ---------------------------------------------------------------------------
# End-to-end: DSL → Policy → evaluate()
# ---------------------------------------------------------------------------

class TestEndToEnd:
    # Note: resource_scope uses prefix semantics via scope_contains(), not glob.
    # "READ /data" matches resources whose scope starts with "/data".
    # "READ *" (or no scope) compiles to empty scope = any resource.

    def test_allow_policy_permits_matching_actor(self):
        policy = compile_policy("""
            ALLOW alice
              READ /data
        """, name="e2e")
        actor = _entity("alice")
        res = _resource("/data/reports/q1.csv")
        ev = policy.evaluate(actor, res, "read")
        assert ev.effect == "permit"

    def test_deny_policy_blocks_matching_operation(self):
        policy = compile_policy("""
            DENY *
              WRITE /restricted
        """, name="e2e")
        actor = _entity("bot")
        res = _resource("/restricted/secret.txt")
        ev = policy.evaluate(actor, res, "write")
        assert ev.effect == "deny"

    def test_default_deny_blocks_unmatched(self):
        policy = compile_policy("""
            ALLOW alice
              READ /data
        """, name="e2e")
        actor = _entity("bob")
        res = _resource("/data/reports/q1.csv")
        ev = policy.evaluate(actor, res, "read")
        assert ev.effect == "deny"

    def test_allow_all_wildcard(self):
        # "*" resource scope compiles to empty string → matches any resource
        policy = compile_policy("""
            ALLOW *
              READ *
              WRITE *
        """, name="e2e")
        actor = _entity("anyone")
        res = _resource("/anything/path")
        assert policy.evaluate(actor, res, "read").effect == "permit"
        assert policy.evaluate(actor, res, "write").effect == "permit"

    def test_priority_allow_beats_deny(self):
        policy = compile_policy("""
            ALLOW alice
              READ /data
            DENY *
              READ *
        """, name="e2e")
        alice = _entity("alice")
        bob = _entity("bob")
        res = _resource("/data/x")
        assert policy.evaluate(alice, res, "read").effect == "permit"
        assert policy.evaluate(bob, res, "read").effect == "deny"

    def test_agent_prefix_subject_pattern(self):
        policy = compile_policy("""
            ALLOW agent:AnalystBot
              READ /data
        """, name="e2e")
        analyst = _entity("agent:AnalystBot")
        other = _entity("other-bot")
        res = _resource("/data/x")
        assert policy.evaluate(analyst, res, "read").effect == "permit"
        assert policy.evaluate(other, res, "read").effect == "deny"

    def test_scope_prefix_semantics(self):
        # Documents: resource_scope="/data" matches /data/sub but not /other.
        # Uses explicit ALLOW * catch-all so the default_effect="deny" doesn't shadow.
        policy = compile_policy("""
            DENY *
              WRITE /data
            ALLOW *
              WRITE /other
        """, name="e2e")
        actor = _entity("bot")
        # /data/secret starts with /data/ → deny rule fires
        assert policy.evaluate(actor, _resource("/data/secret"), "write").effect == "deny"
        # /other/file starts with /other/ → allow rule fires
        assert policy.evaluate(actor, _resource("/other/file"), "write").effect == "permit"
        # exact match /data → deny
        assert policy.evaluate(actor, _resource("/data"), "write").effect == "deny"
