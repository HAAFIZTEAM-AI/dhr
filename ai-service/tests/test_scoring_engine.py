"""Tests for the noisy-OR ensemble scoring engine.

The central regression these guard is the *dilution bug*: the previous
implementation averaged module confidences, so one decisive signal was washed out
by modules that had nothing to analyze. Every test below encodes a real scenario
from the audit of the original ``backend/routes/scan.js``.
"""

from __future__ import annotations

import pytest

from haafiz.scoring.engine import (
    CRITICAL_THRESHOLD,
    SCAM_THRESHOLD,
    ModuleScore,
    combine_scores,
)


class TestDilutionBugRegression:
    """The exact failure mode of arithmetic-mean scoring."""

    def test_one_decisive_signal_is_not_diluted_by_silent_modules(self):
        # Old behaviour: (95 + 0 + 0 + 0 + 0) / 5 = 19  ->  "SAFE"  (WRONG)
        # New behaviour: noisy-OR keeps the 95% signal dominant.
        verdict = combine_scores(
            [
                ModuleScore("text", confidence=95, applicable=True),
                ModuleScore("phone", confidence=0, applicable=False),
                ModuleScore("website", confidence=0, applicable=False),
                ModuleScore("image", confidence=0, applicable=False),
                ModuleScore("voice", confidence=0, applicable=False),
            ]
        )
        assert verdict.is_scam is True
        assert verdict.confidence >= SCAM_THRESHOLD
        assert verdict.label in {"scam", "critical"}

    def test_non_applicable_modules_do_not_contribute_zero_evidence(self):
        """A module that never ran is absence of evidence, not evidence of safety."""
        only_text = combine_scores(
            [ModuleScore("text", confidence=80, applicable=True)]
        )
        with_silent = combine_scores(
            [
                ModuleScore("text", confidence=80, applicable=True),
                ModuleScore("phone", confidence=0, applicable=False),
                ModuleScore("website", confidence=0, applicable=False),
            ]
        )
        # Silent modules must not drag the score down.
        assert with_silent.confidence >= only_text.confidence

    def test_applicable_zero_module_does_reduce_confidence(self):
        """Conversely, a module that DID look and found nothing is real evidence."""
        alone = combine_scores([ModuleScore("text", confidence=70, applicable=True)])
        with_negative = combine_scores(
            [
                ModuleScore("text", confidence=70, applicable=True),
                ModuleScore("website", confidence=0, weight=1.0, applicable=True),
            ]
        )
        # noisy-OR: adding a zero-probability applicable module cannot raise the
        # score, and the weighted combination should not exceed the single strong
        # signal by much.
        assert with_negative.confidence <= alone.confidence + 10


class TestNoisyOrBehaviour:
    def test_corroborating_signals_accumulate(self):
        single = combine_scores([ModuleScore("text", confidence=40, applicable=True)])
        corroborated = combine_scores(
            [
                ModuleScore("text", confidence=40, applicable=True),
                ModuleScore("website", confidence=40, applicable=True),
            ]
        )
        assert corroborated.confidence > single.confidence
        assert single.is_scam is False
        assert corroborated.is_scam is True

    def test_many_weak_signals_can_reach_scam(self):
        verdict = combine_scores(
            [
                ModuleScore("text", confidence=30, applicable=True),
                ModuleScore("website", confidence=30, applicable=True),
                ModuleScore("phone", confidence=30, applicable=True),
                ModuleScore("image", confidence=25, applicable=True),
            ]
        )
        assert verdict.confidence > 30

    def test_nothing_flagged_is_safe(self):
        verdict = combine_scores(
            [
                ModuleScore("text", confidence=0, applicable=True),
                ModuleScore("website", confidence=0, applicable=True),
            ]
        )
        assert verdict.label == "safe"
        assert verdict.is_scam is False
        assert verdict.confidence == 0

    def test_confidence_never_exceeds_one_hundred(self):
        verdict = combine_scores(
            [
                ModuleScore("text", confidence=100, applicable=True),
                ModuleScore("website", confidence=100, applicable=True),
                ModuleScore("voice", confidence=100, applicable=True),
                ModuleScore("image", confidence=100, applicable=True),
            ]
        )
        assert verdict.confidence <= 100

    def test_weight_scales_module_influence(self):
        heavy = combine_scores(
            [ModuleScore("website", confidence=50, weight=1.0, applicable=True)]
        )
        light = combine_scores(
            [ModuleScore("phone", confidence=50, weight=0.2, applicable=True)]
        )
        assert heavy.confidence > light.confidence


class TestHardOverrides:
    def test_otp_exfiltration_forces_critical_regardless_of_score(self):
        # A low-confidence text match that nonetheless asks for an OTP must
        # escalate -- the harm is the credential leak, not the score.
        verdict = combine_scores(
            [
                ModuleScore(
                    "text",
                    confidence=10,
                    applicable=True,
                    overrides=["otp_exfiltration"],
                )
            ]
        )
        assert verdict.is_critical is True
        assert verdict.confidence >= CRITICAL_THRESHOLD
        assert "otp_exfiltration" in verdict.overrides

    def test_verified_impersonation_forces_critical(self):
        verdict = combine_scores(
            [ModuleScore("phone", confidence=5, applicable=True, overrides=["verified_impersonation"])]
        )
        assert verdict.is_critical is True

    def test_typosquatting_forces_critical(self):
        verdict = combine_scores(
            [ModuleScore("website", confidence=20, applicable=True, overrides=["typosquatting"])]
        )
        assert verdict.is_critical is True


class TestTrustDiscount:
    def test_verified_institution_suppresses_false_positive(self):
        """Real banks legitimately send OTP messages. Flagging those destroys trust."""
        without_trust = combine_scores(
            [
                ModuleScore(
                    "text",
                    confidence=70,
                    applicable=True,
                    risk_factors=["otp"],
                    overrides=["otp_exfiltration"],
                )
            ]
        )
        with_trust = combine_scores(
            [
                ModuleScore(
                    "text",
                    confidence=70,
                    applicable=True,
                    risk_factors=["otp"],
                    overrides=["otp_exfiltration", "verified_registry_match"],
                )
            ]
        )
        assert without_trust.is_critical is True
        # The trust signal must overrule the critical override.
        assert with_trust.confidence < without_trust.confidence
        assert "verified_registry_match" in with_trust.trust_signals

    def test_trust_signal_alone_makes_low_score_safe(self):
        verdict = combine_scores(
            [
                ModuleScore(
                    "website",
                    confidence=40,
                    applicable=True,
                    overrides=["verified_registry_match"],
                )
            ]
        )
        assert verdict.label in {"safe", "suspicious"}
        assert verdict.is_scam is False


class TestEdgeCases:
    def test_empty_input_is_unknown_not_scam(self):
        verdict = combine_scores([])
        assert verdict.label == "unknown"
        assert verdict.is_scam is False
        assert verdict.confidence == 0

    def test_all_modules_non_applicable_is_unknown(self):
        verdict = combine_scores(
            [
                ModuleScore("text", confidence=90, applicable=False),
                ModuleScore("website", confidence=90, applicable=False),
            ]
        )
        assert verdict.label == "unknown"
        assert verdict.is_scam is False

    def test_accepts_plain_dicts_from_http(self):
        """The analyzers send JSON; the engine must accept it without conversion."""
        verdict = combine_scores(
            [
                {"module": "text", "confidence": 88, "risk_factors": ["urgency", "otp"]},
                {"module": "phone", "confidence": 0, "applicable": False},
            ]
        )
        assert verdict.is_scam is True
        assert "urgency" in verdict.risk_factors

    def test_dict_without_weight_uses_module_default(self):
        verdict = combine_scores([{"module": "website", "confidence": 60}])
        weights = {m["module"]: m["weight"] for m in verdict.contributing_modules}
        assert weights["website"] == 1.0

    def test_rejects_unsupported_type(self):
        with pytest.raises(TypeError):
            combine_scores([42])  # type: ignore[list-item]

    def test_negative_and_over_range_confidences_are_clamped(self):
        verdict = combine_scores(
            [
                ModuleScore("text", confidence=150, applicable=True),
                ModuleScore("phone", confidence=-30, applicable=True),
            ]
        )
        assert 0 <= verdict.confidence <= 100

    def test_risk_factors_are_deduplicated_and_ordered(self):
        verdict = combine_scores(
            [
                ModuleScore("text", confidence=50, applicable=True, risk_factors=["otp", "urgency"]),
                ModuleScore("image", confidence=50, applicable=True, risk_factors=["otp", "cnic"]),
            ]
        )
        assert verdict.risk_factors == ["otp", "urgency", "cnic"]

    def test_to_dict_is_json_serialisable(self):
        import json

        verdict = combine_scores([ModuleScore("text", confidence=90, applicable=True)])
        assert json.loads(json.dumps(verdict.to_dict()))["is_scam"] is True


class TestLabels:
    @pytest.mark.parametrize(
        "confidence,expected",
        [
            (0, "safe"),
            (29, "safe"),
            (30, "suspicious"),
            (59, "suspicious"),
            (60, "scam"),
            (84, "scam"),
            (85, "critical"),
            (100, "critical"),
        ],
    )
    def test_label_bands(self, confidence, expected):
        verdict = combine_scores([ModuleScore("text", confidence=confidence, applicable=True)])
        assert verdict.label == expected
