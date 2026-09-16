"""
Semantic consent veto — closes the "informed / voluntary / competent /
not-deceived" gap left open by ``kernel/consent.py``.

``ConsentCapability`` (and ``ConsentAnnotation``) enforce what is structural
and checkable without understanding: expiry, operation-scope, context-binding,
and that the grantor is human. That is everything a boolean check can honestly
verify. The theory's full predicate is wider —

    valid_consent(H, A) :- informed, voluntary, specific, revocable,
                           competent, not coerced, not deceived

— and four of those seven conjuncts (informed, voluntary, competent,
not-deceived) require judging the *meaning* of a request, not its shape. A
kernel cannot honestly claim to check them with a boolean, so PHILOSOPHY/
correctly reports this as a stated, partial gap rather than faking coverage.

This module does not close the gap by writing a semantic check into the TCB
— TCB_DISCIPLINE Rule 2 forbids that, correctly: "informed", "voluntary",
"competent" and "deceived" are exactly the banned semantic vocabulary. It
closes the gap the only honest way available: an OPTIONAL, untrusted judge,
composed the same way compass.py/synthesis.py/resolver.py already compose
guidance and justice outside the gate — never granting authority, only able
to veto, fail-closed on every error path, and contributing no evidence that
could be mistaken for a kernel-verified fact.

This is the same architecture as ``decision_os_min.semantic.semantic_veto``
(see the sibling decision-os-min project) and reuses its defenses line for
line, adapted to ``ConsentCapability``:

1. The judge sees a canonical JSON view of selected consent fields, never the
   live ``ConsentCapability`` object or kernel internals.
2. No truncation — an oversized view is DENIED, not cut (a cut view lets an
   attacker's deception hide past the boundary).
3. No lossy serialization — a non-JSON-safe view is DENIED, not stringified.
4. Strict output parsing, compared by base ``str`` so a subclass can't spoof
   a verdict.
5. Judge-supplied text is sanitized before it can reach a signed record: one
   line, no control/bidi characters, bounded length.
6. Every failure path — bad view, judge exception, timeout, malformed or
   unknown output — is DENY. ``on_uncertain="abstain"`` does not change that;
   an attacker who can break the judge must not thereby grant consent.

Non-claims
----------
A "consistent" verdict is not proof the human was actually informed,
voluntary, competent, and undeceived — it means an untrusted judge did not
find a problem, which is weaker than a mechanical guarantee and is reported
as such. This module contributes no `legitimacy_digest` or axiom evidence and
must never be mistaken for the mechanically-checked (Kani/Lean4/TLA+) parts
of the kernel. See ``docs/CONSENT_SEMANTICS.md`` for the full non-claims list
and how this changes row 8 of PHILOSOPHY/COVERAGE_MATRIX.md.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

INFORMED_VOLUNTARY_COMPETENT = "informed_voluntary_competent"
DECEPTIVE_OR_COERCIVE = "deceptive_or_coercive"
UNCERTAIN = "uncertain"
JUDGMENTS = frozenset({INFORMED_VOLUNTARY_COMPETENT, DECEPTIVE_OR_COERCIVE, UNCERTAIN})
_CANONICAL_JUDGMENT = {j: j for j in JUDGMENTS}

# What the judge is shown. Deliberately excludes the human grantor's identity
# (`grantor`) for the same reason decision-os-min's semantic_veto excludes
# `actor`: identity is an authority question this judge has no business
# reasoning about. `request_text` is the plain-language ask the human actually
# saw, if the caller has it — without it the judge can only assess shape, not
# whether the human was told the truth, so callers SHOULD supply it.
DEFAULT_FIELDS: tuple[str, ...] = (
    "grantee_kind",
    "resource_type",
    "operations",
    "scope",
    "request_text",
    "disclosed_purpose",
    "actual_purpose",
)
DEFAULT_MAX_VIEW_CHARS = 8000
MAX_REASON_CHARS = 280
MAX_NAME_CHARS = 48

OnUncertain = Literal["deny", "abstain"]

# Same character class decision-os-min strips: C0/C1 controls, DEL, Unicode
# line/paragraph separators, bidi embeddings/overrides/isolates, zero-width
# characters, and the BOM — anything that could forge or disguise a log line.
_UNSAFE_CHARS = re.compile(
    "[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]"
)
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class ConsentJudgment:
    """A judge's answer. ``judgment`` must be one of ``JUDGMENTS``."""

    judgment: str
    reason: str = ""


@runtime_checkable
class ConsentJudge(Protocol):
    """Anything with a ``name`` and a ``judge(view) -> judgment`` method.

    Untrusted: may raise, hang, or return garbage. Every one of those is DENY.
    """

    name: str

    def judge(self, view: str) -> ConsentJudgment | dict[str, Any]: ...


def clean_text(text: object, limit: int = MAX_REASON_CHARS) -> str:
    """Make judge-supplied text safe to log: one line, no control/direction
    characters, bounded length."""
    raw = str.__str__(text) if isinstance(text, str) else ""
    flat = _WHITESPACE.sub(" ", _UNSAFE_CHARS.sub(" ", raw)).strip()
    if len(flat) > limit:
        flat = flat[: max(limit - 1, 0)].rstrip() + "…"
    return flat


def build_view(fields_dict: dict[str, Any], fields: Iterable[str] = DEFAULT_FIELDS) -> str:
    """Canonical JSON of the selected fields. Raises ``TypeError``/``ValueError``
    if the content is not plain JSON (never falls back to a ``repr``)."""
    selected = {f: fields_dict[f] for f in fields if f in fields_dict}
    return json.dumps(
        selected, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )


def _parse(raw: object) -> tuple[str | None, str]:
    judgment: object
    reason: object
    if isinstance(raw, ConsentJudgment):
        judgment, reason = raw.judgment, raw.reason
    elif isinstance(raw, dict):
        judgment, reason = raw.get("judgment"), raw.get("reason", "")
    else:
        return None, f"malformed judge output of type {type(raw).__name__}"
    if not isinstance(judgment, str):
        return None, "judge output has no string judgment"
    canonical = _CANONICAL_JUDGMENT.get(str.__str__(judgment))
    if canonical is None:
        return None, f"unknown judgment {clean_text(judgment, 40)!r}"
    return canonical, clean_text(reason)


@dataclass(frozen=True)
class ConsentVetoResult:
    """ALLOW/DENY only — never authority, never evidence. See module docstring."""

    permitted: bool
    reason: str


def semantic_consent_veto(
    judge: ConsentJudge,
    *,
    fields: Iterable[str] = DEFAULT_FIELDS,
    max_view_chars: int = DEFAULT_MAX_VIEW_CHARS,
    on_uncertain: OnUncertain = "deny",
) -> Callable[[dict[str, Any]], ConsentVetoResult]:
    """Adapt a consent judge into a **veto-only, fail-closed** check.

    Call the returned function with a plain dict built from a
    ``ConsentCapability`` plus request context (see ``view_from_capability``
    below for the standard shape). It never mutates or grants; it can only
    turn a structurally-valid consent into a DENY.

    ``on_uncertain="abstain"`` lets an explicit "uncertain" verdict pass
    (structural checks still apply), for callers where refusing every
    ambiguous case is operationally unacceptable. Every other failure mode —
    judge error, timeout, malformed output, oversized or non-JSON view —
    stays DENY regardless, so an attacker who can break the judge cannot
    thereby manufacture consent.
    """
    fields = tuple(fields)
    if not fields:
        raise ValueError("semantic_consent_veto needs at least one field to show the judge")
    if not isinstance(max_view_chars, int) or max_view_chars < 1:
        raise ValueError("max_view_chars must be a positive int")
    if on_uncertain not in ("deny", "abstain"):
        raise ValueError("on_uncertain must be 'deny' or 'abstain'")
    name = clean_text(getattr(judge, "name", ""), MAX_NAME_CHARS) or type(judge).__name__
    label = f"consent-veto[{name}]"

    def deny(why: str) -> ConsentVetoResult:
        return ConsentVetoResult(permitted=False, reason=f"{label}: {why}")

    def check(consent_view: dict[str, Any]) -> ConsentVetoResult:
        try:
            view = build_view(consent_view, fields)
        except (TypeError, ValueError) as exc:
            return deny(
                f"consent context is not plain JSON, refusing to judge (fail-closed): "
                f"{type(exc).__name__}"
            )
        if len(view) > max_view_chars:
            return deny(
                f"view is {len(view)} chars, limit {max_view_chars}; "
                f"a truncated request is not judged (fail-closed)"
            )
        try:
            raw = judge.judge(view)
        except Exception as exc:
            return deny(f"judge error (fail-closed): {type(exc).__name__}: {clean_text(exc, 120)}")
        except BaseException as exc:
            if isinstance(exc, GeneratorExit):
                raise
            return deny(f"judge BaseException (fail-closed): {type(exc).__name__}")

        judgment, reason = _parse(raw)
        if judgment is None:
            return deny(f"{reason} (fail-closed)")
        if judgment == DECEPTIVE_OR_COERCIVE:
            return deny(f"deceptive_or_coercive: {reason}" if reason else "deceptive_or_coercive")
        if judgment == UNCERTAIN:
            if on_uncertain == "abstain":
                return ConsentVetoResult(permitted=True, reason=f"{label}: abstained (uncertain)")
            return deny(f"uncertain: {reason}" if reason else "uncertain")
        return ConsentVetoResult(permitted=True, reason=f"{label}: informed_voluntary_competent")

    return check


def view_from_capability(
    cap: Any,
    *,
    request_text: str = "",
    disclosed_purpose: str = "",
    actual_purpose: str = "",
) -> dict[str, Any]:
    """Standard view builder for a ``kernel.consent.ConsentCapability``.

    Callers who have the plain-language request the human actually saw
    should pass ``request_text`` — without it the judge can only assess the
    shape of the grant, not whether the human was told the truth about what
    it would be used for. ``disclosed_purpose``/``actual_purpose`` let a
    caller hand the judge a known disclosed-vs-real mismatch directly, for
    systems that already track that separately from free text.
    """
    return {
        "grantee_kind": getattr(cap.grantee, "kind", None) and cap.grantee.kind.name,
        "resource_type": getattr(cap.resource, "rtype", None) and cap.resource.rtype.value,
        "operations": sorted(cap.operations),
        "scope": cap.scope.value if hasattr(cap.scope, "value") else str(cap.scope),
        "request_text": request_text,
        "disclosed_purpose": disclosed_purpose,
        "actual_purpose": actual_purpose,
    }


class DisclosureMatchJudge:
    """Deterministic reference judge, so the contract is concrete and tested
    without a live model. A model-backed judge is a drop-in replacement —
    same shape as ``decision_os_min``'s ``examples/semantic_llm_judge.py``.

    Flags a request as deceptive when a disclosed purpose is given and an
    actual purpose is given and they don't match; uncertain when either is
    missing (nothing to compare); otherwise informed/voluntary/competent.
    """

    name = "disclosure-match"

    def judge(self, view: str) -> ConsentJudgment:
        data = json.loads(view)
        disclosed = (data.get("disclosed_purpose") or "").strip()
        actual = (data.get("actual_purpose") or "").strip()
        if not disclosed or not actual:
            return ConsentJudgment(UNCERTAIN, "no disclosed/actual purpose pair to compare")
        if disclosed != actual:
            return ConsentJudgment(
                DECEPTIVE_OR_COERCIVE,
                f"disclosed purpose {disclosed!r} does not match actual purpose {actual!r}",
            )
        return ConsentJudgment(INFORMED_VOLUNTARY_COMPETENT, "")
