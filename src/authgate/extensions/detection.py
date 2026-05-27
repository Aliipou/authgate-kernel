"""
Adversarial-robust dialectical manipulation detector.

Three detection layers:
  1. Conclusion testing: does accepting this argument imply a rights violation?
     (Paraphrase-resistant — tests the logical conclusion, not surface wording.)
  2. Structural pattern detection: argument shape (conditional override, synthesis frame).
  3. Keyword/phrase matching: fast first filter, low weight.

Ensemble score over all three layers.
Caller supplies a conclusion_tester function (can be an LLM call) for layer 1.
If no tester is provided, falls back to layers 2+3 only.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Layer 3: keyword phrases (low weight — easily bypassed, but cheap)
KEYWORD_SIGNALS: list[tuple[str, float]] = [
    ("suspend the axiom", 1.0),
    ("emergency exception", 0.85),
    ("greater good requires", 0.8),
    ("ends justify the means", 1.0),
    ("collective welfare justifies", 0.8),
    ("temporarily suspend", 0.75),
    ("axioms don't apply", 1.0),
    ("override the rule", 0.85),
    ("bypass the constraint", 0.85),
    ("machine should decide", 0.7),
    ("human oversight is unnecessary", 0.9),
    ("sacrifice individual rights", 0.9),
    ("rights can be traded", 0.8),
    ("property rights hinder", 0.8),
    ("corrigibility limits performance", 0.75),
]

# Layer 2: structural patterns (medium weight — harder to bypass)
STRUCTURAL_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (
        re.compile(r"\b(suspend|override|bypass|ignore|waive)\w*\b.{0,60}\b(axiom|rule|constraint|right|limit)\w*", re.I),  # noqa: E501
        0.85, "override-frame",
    ),
    (
        re.compile(r"\b(emergency|crisis|extreme.{0,20}case)\w*\b.{0,80}\b(justif|allow|permit|override|waive)\w*", re.I),  # noqa: E501
        0.85, "emergency-justification",
    ),
    (
        re.compile(r"\b(greater|collective|common|public)\b.{0,40}\b(good|benefit|welfare|interest)\b.{0,80}\b(outweigh|justify|require|demand|necessitat)\w*", re.I),  # noqa: E501
        0.85, "collective-override",
    ),
    (
        re.compile(r"\bproperty rights?\b.{0,80}(prevent\w*|block\w*|hinder\w*|limiting|stopp\w*|impedes?|obstruct\w*)", re.I),  # noqa: E501
        0.8, "rights-as-obstacle",
    ),
    (
        re.compile(r"\b(ai|machine|model|system|agent)\w*\b.{0,40}\b(know\w* better|should decide|smarter than|superior judgment)", re.I),  # noqa: E501
        0.8, "ai-knows-better",
    ),
    (
        re.compile(r"\bhuman.{0,30}\b(oversight|supervision|control|correction)\w*\b.{0,40}\b(unnecessar\w*|not needed|should be reduced|limits?|impedes?)", re.I),  # noqa: E501
        0.9, "anti-oversight",
    ),
    (
        re.compile(r"\b(corrigib\w*|correctab\w*|human control)\b.{0,60}\b(limit\w*|impede\w*|prevent\w*|unnecessar\w*|performance)", re.I),  # noqa: E501
        0.8, "anti-corrigibility",
    ),
    (
        re.compile(r"\b(yes.{0,10}but|true.{0,10}however|granted.{0,10}yet|while.{0,20}neverthe)\b", re.I),  # noqa: E501
        0.4, "soft-dialectic",
    ),
    (
        re.compile(r"\b(don.?t|cannot|shouldn.?t)\b.{0,40}\b(restrict|limit|constrain|control)\b.{0,30}\b(ai|machine|model|system|agent)\b", re.I),  # noqa: E501
        0.7, "anti-constraint",
    ),
    (
        re.compile(r"\b(synthesis|synthesize|new framework|higher principle|reframe)\b.{0,60}\b(allow|permit|justify|override)\b", re.I),  # noqa: E501
        0.8, "synthesis-override",
    ),
]


@dataclass(frozen=True)
class DetectionResult:
    score: float
    suspicious: bool
    conclusion_violates_rights: bool | None
    matched_keywords: tuple[str, ...]
    matched_patterns: tuple[str, ...]
    recommendation: str

    @classmethod
    def clean(cls) -> DetectionResult:
        return cls(
            score=0.0, suspicious=False, conclusion_violates_rights=None,
            matched_keywords=(), matched_patterns=(),
            recommendation="No manipulation patterns detected.",
        )


def detect(
    argument: str,
    threshold: float = 0.5,
    conclusion_tester: Callable[[str], bool] | None = None,
) -> DetectionResult:
    """
    Analyse argument for dialectical manipulation.

    conclusion_tester: callable(argument) -> bool
        Returns True if the argument's conclusion implies a rights violation.
        Supply an LLM call for robust, paraphrase-resistant detection.
    threshold: float
        Score >= threshold sets suspicious=True.
    """
    if not argument or not argument.strip():
        return DetectionResult.clean()

    lowered = argument.lower()
    matched_kw: list[str] = []
    matched_pt: list[str] = []
    layer3_score = 0.0
    layer2_score = 0.0

    for phrase, weight in KEYWORD_SIGNALS:
        if phrase in lowered:
            matched_kw.append(phrase)
            layer3_score = max(layer3_score, weight)

    for pattern, weight, label in STRUCTURAL_PATTERNS:
        if pattern.search(argument):
            matched_pt.append(label)
            layer2_score = max(layer2_score, weight)

    conclusion_violates: bool | None = None
    layer1_score = 0.0
    if conclusion_tester is not None:
        try:
            conclusion_violates = conclusion_tester(argument)
            layer1_score = 1.0 if conclusion_violates else 0.0
        except Exception:
            logger.warning("conclusion_tester raised an exception; falling back to layers 2+3", exc_info=True)

    n_signals = len(matched_kw) + len(matched_pt)
    multi_signal_boost = min(0.15, n_signals * 0.05)

    if layer1_score > 0:
        score = layer1_score
    else:
        score = max(layer2_score, layer3_score) + multi_signal_boost

    score = min(1.0, score)
    suspicious = score >= threshold

    if not suspicious:
        recommendation = "Argument appears clean."
    elif score >= 0.9 or conclusion_violates:
        recommendation = (
            "HIGH RISK: argument implies a rights violation. "
            "Block immediately. Require human review."
        )
    elif score >= 0.7:
        recommendation = (
            "MODERATE RISK: structural manipulation patterns. "
            "Flag for human review before any axiom-touching decision."
        )
    else:
        recommendation = "LOW RISK: weak signals. Log and monitor."

    return DetectionResult(
        score=round(score, 3),
        suspicious=suspicious,
        conclusion_violates_rights=conclusion_violates,
        matched_keywords=tuple(matched_kw),
        matched_patterns=tuple(matched_pt),
        recommendation=recommendation,
    )
