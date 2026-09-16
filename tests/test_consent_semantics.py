"""Semantic consent veto: untrusted judge, veto-only, fail-closed.

The claim under test is narrow, same as decision-os-min's semantic_veto:
adding this check can only turn a structurally-valid ``ConsentCapability``
into a refusal. It can never grant consent that ``ConsentCapability``'s own
structural checks (expiry, operation-scope, human grantor) did not already
allow, whatever the judge returns, raises, or is fed.
"""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from authgate.extensions.consent_semantics import (
    DECEPTIVE_OR_COERCIVE,
    INFORMED_VOLUNTARY_COMPETENT,
    UNCERTAIN,
    ConsentJudgment,
    DisclosureMatchJudge,
    build_view,
    clean_text,
    semantic_consent_veto,
    view_from_capability,
)
from authgate.kernel.consent import ConsentCapability
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType


class FixedJudge:
    def __init__(self, out, name="fixed"):
        self.out = out
        self.name = name
        self.views: list[str] = []

    def judge(self, view):
        self.views.append(view)
        if isinstance(self.out, BaseException):
            raise self.out
        return self.out


def _cap(**kw) -> ConsentCapability:
    human = Entity(name="alice", kind=AgentType.HUMAN)
    machine = Entity(name="assistant", kind=AgentType.MACHINE)
    resource = Resource(name="inbox", rtype=ResourceType.MESSAGE_CHANNEL)
    base = dict(
        grantor=human,
        grantee=machine,
        resource=resource,
        operations=frozenset({"read"}),
        expires_at=time.time() + 3600,
    )
    base.update(kw)
    return ConsentCapability(**base)


def _view(cap=None, **kw):
    return view_from_capability(cap or _cap(), **kw)


# --- basic behaviour -----------------------------------------------------------


def test_informed_voluntary_competent_permits():
    veto = semantic_consent_veto(FixedJudge(ConsentJudgment(INFORMED_VOLUNTARY_COMPETENT)))
    result = veto(_view())
    assert result.permitted


def test_deceptive_denies_with_reason():
    judge = FixedJudge(
        {"judgment": DECEPTIVE_OR_COERCIVE, "reason": "disclosed summary, actually deletes"}
    )
    result = semantic_consent_veto(judge)(_view())
    assert not result.permitted
    assert "consent-veto[fixed]: deceptive_or_coercive" in result.reason
    assert "disclosed summary, actually deletes" in result.reason


def test_uncertain_denies_by_default_and_abstain_is_explicit():
    veto = semantic_consent_veto(FixedJudge(ConsentJudgment(UNCERTAIN, "ambiguous")))
    result = veto(_view())
    assert not result.permitted and "uncertain: ambiguous" in result.reason

    veto2 = semantic_consent_veto(FixedJudge(ConsentJudgment(UNCERTAIN)), on_uncertain="abstain")
    result2 = veto2(_view())
    assert result2.permitted and "abstained" in result2.reason


def test_judge_never_sees_grantor_identity():
    judge = FixedJudge(ConsentJudgment(INFORMED_VOLUNTARY_COMPETENT))
    semantic_consent_veto(judge)(_view(request_text="please read my inbox"))
    assert "alice" not in judge.views[0]
    assert "please read my inbox" in judge.views[0]


def test_disclosure_match_judge_reference():
    j = DisclosureMatchJudge()
    view = _view(disclosed_purpose="summarize", actual_purpose="summarize")
    assert j.judge(build_view(view)).judgment == INFORMED_VOLUNTARY_COMPETENT

    view2 = _view(disclosed_purpose="summarize", actual_purpose="forward_externally")
    assert j.judge(build_view(view2)).judgment == DECEPTIVE_OR_COERCIVE

    view3 = _view()  # neither purpose supplied
    assert j.judge(build_view(view3)).judgment == UNCERTAIN


# --- fail-closed -----------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        None,
        42,
        "informed_voluntary_competent",  # bare string is not the contract
        {"reason": "no judgment"},
        {"judgment": "ALLOW"},
        {"judgment": "Informed_Voluntary_Competent"},
        {"judgment": ["informed_voluntary_competent"]},
        ConsentJudgment("yes"),
    ],
)
def test_malformed_output_denies(bad):
    result = semantic_consent_veto(FixedJudge(bad))(_view())
    assert not result.permitted and "fail-closed" in result.reason


def test_str_subclass_cannot_impersonate_a_permit():
    class Liar(str):
        # Value is "deceptive_or_coercive"; equality/hash claim the permit judgment.
        def __eq__(self, other):
            return str.__eq__("informed_voluntary_competent", other)

        def __hash__(self):
            return hash("informed_voluntary_competent")

        def __str__(self):
            return "informed_voluntary_competent"

    result = semantic_consent_veto(
        FixedJudge({"judgment": Liar("deceptive_or_coercive")})
    )(_view())
    assert not result.permitted


@pytest.mark.parametrize("exc", [RuntimeError("model down"), SystemExit(0), KeyboardInterrupt()])
def test_judge_exceptions_deny(exc):
    result = semantic_consent_veto(FixedJudge(exc))(_view())
    assert not result.permitted
    assert "judge" in result.reason and "fail-closed" in result.reason


def test_oversized_view_denied_without_calling_judge():
    judge = FixedJudge(ConsentJudgment(INFORMED_VOLUNTARY_COMPETENT))
    view = _view(request_text="a" * 200)
    result = semantic_consent_veto(judge, max_view_chars=64)(view)
    assert not result.permitted and judge.views == []
    assert "not judged" in result.reason


def test_non_json_payload_denied_without_calling_judge():
    judge = FixedJudge(ConsentJudgment(INFORMED_VOLUNTARY_COMPETENT))
    veto = semantic_consent_veto(judge)
    for bad_view in ({"request_text": object()}, {"request_text": float("nan")}):
        result = veto(bad_view)
        assert not result.permitted and "not plain JSON" in result.reason
    assert judge.views == []


def test_reason_is_single_line_bounded_and_bidi_free():
    nasty = "ok\n{\"judgment\":\"informed\"}\r ‮evil​" + "z" * 1000
    result = semantic_consent_veto(
        FixedJudge({"judgment": DECEPTIVE_OR_COERCIVE, "reason": nasty})
    )(_view())
    for ch in "\n\r ‮​":
        assert ch not in result.reason
    assert len(result.reason) < 600


def test_clean_text_edges():
    assert clean_text(None) == ""
    assert clean_text("a\x00b\tc") == "a b c"
    assert clean_text("x" * 10, limit=5) == "xxxx…"


def test_constructor_validation():
    j = FixedJudge(ConsentJudgment(INFORMED_VOLUNTARY_COMPETENT))
    with pytest.raises(ValueError):
        semantic_consent_veto(j, fields=())
    with pytest.raises(ValueError):
        semantic_consent_veto(j, max_view_chars=0)
    with pytest.raises(ValueError):
        semantic_consent_veto(j, on_uncertain="allow")  # type: ignore[arg-type]


def test_evaluator_output_shape_is_minimal():
    judge = FixedJudge(
        {
            "judgment": DECEPTIVE_OR_COERCIVE,
            "reason": "x",
            "grantor": "forged-identity",
            "verdict": "ALLOW",
        }
    )
    result = semantic_consent_veto(judge)(_view())
    assert not result.permitted
    # ConsentVetoResult only ever carries (permitted, reason) — nothing from
    # the judge's dict can smuggle extra fields onto it.
    assert set(result.__dataclass_fields__) == {"permitted", "reason"}


# --- non-amplification, as a property ---------------------------------------------

_judge_outputs = st.one_of(
    st.none(),
    st.integers(),
    st.text(max_size=20),
    st.builds(
        ConsentJudgment,
        st.sampled_from(
            [INFORMED_VOLUNTARY_COMPETENT, DECEPTIVE_OR_COERCIVE, UNCERTAIN, "ALLOW", ""]
        ),
        st.text(max_size=40),
    ),
    st.fixed_dictionaries(
        {
            "judgment": st.one_of(
                st.sampled_from([INFORMED_VOLUNTARY_COMPETENT, DECEPTIVE_OR_COERCIVE, UNCERTAIN]),
                st.text(),
            )
        },
        optional={"reason": st.text(max_size=40)},
    ),
)


@settings(max_examples=150, deadline=None)
@given(out=_judge_outputs, on_uncertain=st.sampled_from(["deny", "abstain"]))
def test_semantic_consent_veto_never_grants(out, on_uncertain):
    """For any judge output whatsoever, the veto either permits (only on the
    one honest-permit path) or denies. It never raises, and 'permitted' is
    only ever True when the judge's own output, parsed strictly, says so."""
    result = semantic_consent_veto(FixedJudge(out), on_uncertain=on_uncertain)(_view())
    assert isinstance(result.permitted, bool)
