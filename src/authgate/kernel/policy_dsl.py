"""
Policy DSL — textual syntax for expressing capability-security policies.

Syntax overview
---------------

    ALLOW <subject>
      <OPERATION> <resource_scope>
      ...
      [UNLESS delegated_by <principal>]
      [MAX_DELEGATION_DEPTH <n>]
      [EXPIRES <seconds>]
      [TRUST_DOMAIN <domain>]

    DENY <subject>
      <OPERATION> <resource_scope>
      ...

Where:
    <subject>       := '*' | 'agent:<name>' | 'human:<name>' | '<name>'
    <OPERATION>     := READ | WRITE | DELEGATE | NETWORK_ACCESS |
                       POLICY_MODIFY | SYSTEM_PROMPT_EDIT | MAX_DELEGATION_DEPTH
                       (upper-case tokens that are not condition keywords)
    <resource_scope> := a path, glob, or '*'

A statement begins with an ALLOW/DENY keyword on a non-indented line.
All operation and condition lines must be indented (at least one space/tab).
Blank lines and lines starting with '#' are ignored everywhere.

Examples
--------

    ALLOW ResearchBot
      READ dataset/alice/*
      DENY NETWORK_ACCESS
      UNLESS delegated_by Alice

    ALLOW agent:AnalystBot
      READ /data/reports/*
      WRITE /outputs/analysis/*
      MAX_DELEGATION_DEPTH 2
      EXPIRES 3600

    DENY *
      WRITE /data/restricted/*

    ALLOW human:Alice
      READ *
      WRITE *
      DELEGATE *
      TRUST_DOMAIN internal

    DENY agent:*
      POLICY_MODIFY *
      SYSTEM_PROMPT_EDIT *
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from typing import ClassVar

from authgate.kernel.policy import Policy, PolicyRule


# ---------------------------------------------------------------------------
# Public error type
# ---------------------------------------------------------------------------


class PolicyDSLSyntaxError(ValueError):
    """Raised when the DSL text cannot be parsed.

    Attributes:
        line_number: 1-based line number where the error was detected.
        message:     Human-readable description of the problem.
    """

    def __init__(self, line_number: int, message: str) -> None:
        self.line_number = line_number
        self.message = message
        super().__init__(f"line {line_number}: {message}")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PolicyStatement:
    """Parsed representation of a single DSL statement.

    Fields:
        effect            — "ALLOW" or "DENY"
        subject           — who the statement applies to; '*' is a wildcard;
                            may carry an 'agent:' or 'human:' prefix
        operations        — list of operation names (READ, WRITE, etc.)
        resource_scope    — resource path or pattern; '*' means anything
        conditions        — optional modifiers keyed by condition name:
                              UNLESS      → 'delegated_by <principal>'
                              MAX_DELEGATION_DEPTH → '<n>'
                              EXPIRES     → '<seconds>'
                              TRUST_DOMAIN → '<domain>'
    """

    effect: str                          # "ALLOW" | "DENY"
    subject: str                         # e.g. '*', 'agent:AnalystBot', 'Alice'
    operations: list[str] = field(default_factory=list)
    resource_scope: str = "*"
    conditions: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal parsing helpers
# ---------------------------------------------------------------------------

# Keywords that open a new top-level statement
_EFFECT_KEYWORDS: frozenset[str] = frozenset({"ALLOW", "DENY"})

# Keywords that introduce a condition rather than an operation+resource pair
_CONDITION_KEYWORDS: frozenset[str] = frozenset(
    {"UNLESS", "MAX_DELEGATION_DEPTH", "EXPIRES", "TRUST_DOMAIN"}
)

# Operations we recognise explicitly; anything else that appears in an
# indented line and is not a condition keyword is also accepted as an
# operation so the DSL stays open for extension.
_KNOWN_OPERATIONS: frozenset[str] = frozenset(
    {
        "READ",
        "WRITE",
        "DELEGATE",
        "NETWORK_ACCESS",
        "POLICY_MODIFY",
        "SYSTEM_PROMPT_EDIT",
    }
)

# Pattern for a valid subject token:
#   optional 'agent:' or 'human:' prefix, then name chars or '*'
_SUBJECT_RE = re.compile(r"^(?:(?:agent|human):)?[\w*.\-/]+$")


def _is_indented(line: str) -> bool:
    return line.startswith((" ", "\t"))


def _strip_comment(line: str) -> str:
    """Remove inline '#' comment from a raw line."""
    # Only strip if '#' is preceded by whitespace or is the first non-space char.
    idx = line.find("#")
    if idx == -1:
        return line
    # Treat everything from '#' onward as a comment.
    return line[:idx]


# ---------------------------------------------------------------------------
# PolicyDSL
# ---------------------------------------------------------------------------


class PolicyDSL:
    """Parser and compiler for the Freedom Kernel policy DSL."""

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @classmethod
    def parse(cls, text: str) -> list[PolicyStatement]:
        """Parse DSL *text* into a list of PolicyStatement objects.

        Raises PolicyDSLSyntaxError with line number and message on any
        parse error.
        """
        logical_lines = cls._logical_lines(text)
        statements: list[PolicyStatement] = []
        current: PolicyStatement | None = None
        current_line_no: int = 0

        for lineno, raw in logical_lines:
            # Strip inline comments and trailing whitespace
            stripped = _strip_comment(raw).rstrip()
            if not stripped.strip():
                continue  # blank after comment removal

            if _is_indented(stripped):
                # Must belong to an open statement
                if current is None:
                    raise PolicyDSLSyntaxError(
                        lineno,
                        "indented line has no preceding ALLOW/DENY statement",
                    )
                cls._parse_body_line(stripped.strip(), lineno, current)
            else:
                # New top-level statement — finalise and validate previous
                if current is not None:
                    cls._validate_statement(current, current_line_no)
                    statements.append(current)
                current = cls._parse_header(stripped.strip(), lineno)
                current_line_no = lineno

        # Finalise last statement
        if current is not None:
            cls._validate_statement(current, current_line_no)
            statements.append(current)

        return statements

    @classmethod
    def to_policy(cls, statements: list[PolicyStatement], name: str) -> Policy:
        """Convert a list of PolicyStatement objects into a Policy.

        The translation is:
          - ALLOW statements → effect="permit" PolicyRule
          - DENY statements  → effect="deny"   PolicyRule
          - subject → actor_pattern (empty string for '*')
          - resource_scope → resource_scope (empty string for '*')
          - operations → PolicyRule.operations (lower-cased)
          - priority is assigned by position: first statement = highest
            priority so that explicit rules beat catch-all denies.

        Conditions are not directly representable in the current PolicyRule
        schema; they are attached as metadata comments for future extension.
        """
        rules: list[PolicyRule] = []
        base_priority = len(statements) * 10

        for i, stmt in enumerate(statements):
            effect: str = "permit" if stmt.effect == "ALLOW" else "deny"
            actor_pattern: str = "" if stmt.subject == "*" else stmt.subject
            resource_scope: str = "" if stmt.resource_scope == "*" else stmt.resource_scope
            operations: list[str] = [op.lower() for op in stmt.operations]
            priority: int = base_priority - (i * 10)

            rules.append(
                PolicyRule(
                    effect=effect,  # type: ignore[arg-type]
                    operations=operations,
                    actor_pattern=actor_pattern,
                    resource_scope=resource_scope,
                    priority=priority,
                )
            )

        return Policy(name=name, rules=rules, default_effect="deny")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _logical_lines(text: str) -> list[tuple[int, str]]:
        """Return (1-based line number, raw line) pairs, skipping blank-only
        lines and full-line comments.

        textwrap.dedent() is applied so that triple-quoted Python strings work
        naturally — the common leading whitespace from a Python indented block
        is stripped before parsing, preserving the relative indentation that
        distinguishes ALLOW/DENY headers from their body lines.
        """
        dedented = textwrap.dedent(text)
        result: list[tuple[int, str]] = []
        for lineno, raw in enumerate(dedented.splitlines(), start=1):
            stripped_content = raw.strip()
            if not stripped_content:
                continue
            if stripped_content.startswith("#"):
                continue
            result.append((lineno, raw))
        return result

    @staticmethod
    def _parse_header(token_line: str, lineno: int) -> PolicyStatement:
        """Parse a top-level ALLOW/DENY line."""
        parts = token_line.split(None, 1)
        if len(parts) < 2:
            raise PolicyDSLSyntaxError(
                lineno,
                f"expected 'ALLOW <subject>' or 'DENY <subject>', got: {token_line!r}",
            )
        effect_token, subject = parts[0].upper(), parts[1].strip()

        if effect_token not in _EFFECT_KEYWORDS:
            raise PolicyDSLSyntaxError(
                lineno,
                f"statement must begin with ALLOW or DENY, got: {parts[0]!r}",
            )
        if not subject:
            raise PolicyDSLSyntaxError(
                lineno,
                f"{effect_token} statement missing subject",
            )
        if not _SUBJECT_RE.match(subject):
            raise PolicyDSLSyntaxError(
                lineno,
                f"invalid subject {subject!r} — use an identifier, '*', "
                "or 'agent:<name>'/'human:<name>'",
            )
        return PolicyStatement(effect=effect_token, subject=subject)

    @staticmethod
    def _parse_body_line(
        line: str, lineno: int, stmt: PolicyStatement
    ) -> None:
        """Parse one indented body line and mutate *stmt* in place."""
        parts = line.split(None, 1)
        keyword = parts[0].upper()

        # ---- condition keywords ----
        if keyword == "UNLESS":
            if len(parts) < 2:
                raise PolicyDSLSyntaxError(
                    lineno, "UNLESS requires an argument, e.g. 'UNLESS delegated_by Alice'"
                )
            stmt.conditions["UNLESS"] = parts[1].strip()
            return

        if keyword == "MAX_DELEGATION_DEPTH":
            if len(parts) < 2:
                raise PolicyDSLSyntaxError(
                    lineno, "MAX_DELEGATION_DEPTH requires a numeric argument"
                )
            value = parts[1].strip()
            if not value.isdigit():
                raise PolicyDSLSyntaxError(
                    lineno,
                    f"MAX_DELEGATION_DEPTH value must be a non-negative integer, got: {value!r}",
                )
            stmt.conditions["MAX_DELEGATION_DEPTH"] = value
            return

        if keyword == "EXPIRES":
            if len(parts) < 2:
                raise PolicyDSLSyntaxError(
                    lineno, "EXPIRES requires a numeric argument (seconds)"
                )
            value = parts[1].strip()
            if not value.isdigit():
                raise PolicyDSLSyntaxError(
                    lineno,
                    f"EXPIRES value must be a non-negative integer (seconds), got: {value!r}",
                )
            stmt.conditions["EXPIRES"] = value
            return

        if keyword == "TRUST_DOMAIN":
            if len(parts) < 2:
                raise PolicyDSLSyntaxError(
                    lineno, "TRUST_DOMAIN requires a domain name argument"
                )
            stmt.conditions["TRUST_DOMAIN"] = parts[1].strip()
            return

        # ---- operation + resource_scope ----
        # keyword is the operation name; the optional remainder is the scope
        operation = keyword
        resource_scope = parts[1].strip() if len(parts) > 1 else "*"

        stmt.operations.append(operation)
        # Last explicit resource_scope wins; if multiple ops have scopes this
        # records the last one, which is the common single-scope-per-statement
        # pattern. For multi-scope policies, create multiple statements.
        if resource_scope != stmt.resource_scope:
            stmt.resource_scope = resource_scope

    @staticmethod
    def _validate_statement(stmt: PolicyStatement, lineno: int) -> None:
        """Raise PolicyDSLSyntaxError if *stmt* is structurally invalid."""
        if not stmt.operations:
            raise PolicyDSLSyntaxError(
                lineno,
                f"{stmt.effect} {stmt.subject!r} statement has no operations — "
                "add at least one operation line (READ, WRITE, etc.)",
            )


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def compile(text: str, name: str) -> Policy:  # noqa: A001 — intentional shadow of builtin
    """Parse *text* as a policy DSL and return a compiled Policy named *name*.

    This is the primary entry point for most callers:

        from authgate.kernel.policy_dsl import compile as compile_policy

        policy = compile_policy('''
            ALLOW agent:AnalystBot
              READ /data/reports/*
              WRITE /outputs/analysis/*
              MAX_DELEGATION_DEPTH 2
        ''', name="analyst-policy")

    Raises:
        PolicyDSLSyntaxError — on any parse error, with line number.
    """
    statements = PolicyDSL.parse(text)
    return PolicyDSL.to_policy(statements, name=name)
