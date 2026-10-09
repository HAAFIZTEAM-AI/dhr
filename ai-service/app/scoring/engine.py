"""Ensemble scoring for multi-module scam detection.

WHY THIS EXISTS
---------------
The previous implementation in ``backend/routes/scan.js`` averaged module
confidences arithmetically:

    avg = sum(scores) / len(scores)

That is wrong for independent evidence. If the text analyzer is 95% certain a
message is an OTP-phishing attempt and four other modules simply had nothing to
look at (they returned 0), the mean reports 19% — "SAFE" — and the user loses
their money. Silent modules are not evidence of safety; they are *absence* of
evidence, and treating them as zeros actively dilutes real signal.

THE MODEL
---------
We use a **noisy-OR** combination. If each module i independently provides
probability p_i of the message being a scam, the probability that *none* of them
caught a real scam is the product of their misses:

    P(scam) = 1 - PRODUCT(1 - w_i * p_i)

This has exactly the right behaviour:
  * one strong signal dominates the verdict (no dilution)
  * many weak signals accumulate (corroboration raises confidence)
  * a module with nothing to say (p = 0) contributes nothing — it neither adds
    nor subtracts, which is the correct treatment of missing evidence

On top of that we apply:
  * **hard overrides** — certain findings are dispositive regardless of score
    (verified-bank impersonation, an OTP/CNIC exfiltration demand)
  * **trust discounts** — a destination on the verified institutional registry
    strongly suppresses the score, because false positives on real bank messages
    are what makes people uninstall a tool like this
  * **corroboration bonus** — when N >= 2 modules independently agree, that is
    meaningful evidence, so the combined score is nudged up

Weighting note: weights are *priors over module reliability*, not tuned knobs.
The website analyzer performs DNS + WHOIS + SSL + typosquat + content analysis
and is the most trustworthy single signal; the phone analyzer is often just a
format check and is weighted lowest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

__all__ = [
    "ModuleScore",
    "Verdict",
    "combine_scores",
    "SCAM_THRESHOLD",
    "CRITICAL_THRESHOLD",
]

#: At or above this, we tell the user it is a scam. Tuned for high recall:
#: the cost of a missed scam (money lost, unrecoverable — see BLUEPRINT.md §1.2,
#: ~0.04% conviction rate) far exceeds the cost of a false alarm.
SCAM_THRESHOLD = 60

#: At or above this, the verdict is escalated: family is notified, an audio
#: warning is spoken on IVR/WhatsApp, and an evidence bundle is offered.
CRITICAL_THRESHOLD = 85


@dataclass(frozen=True)
class ModuleScore:
    """One analyzer's contribution to the final verdict.

    Attributes:
        module: analyzer name, e.g. "text", "website", "voice", "phone", "image".
        confidence: 0-100, the analyzer's own estimate that this is a scam.
        weight: 0.0-1.0 prior reliability of this analyzer.
        applicable: whether the module actually had something to analyze. A
            module that was never invoked must be ``applicable=False`` so it does
            not silently contribute a zero. This is the bug that the old
            mean-averaging code could not express.
        risk_factors: findings to surface to the user.
        overrides: dispositive findings that force a verdict regardless of score.
    """

    module: str
    confidence: float
    weight: float = 1.0
    applicable: bool = True
    risk_factors: Sequence[str] = field(default_factory=tuple)
    overrides: Sequence[str] = field(default_factory=tuple)


#: Prior reliability of each analyzer, from most to least trustworthy.
DEFAULT_WEIGHTS: dict[str, float] = {
    "website": 1.00,  # DNS + WHOIS + SSL + typosquat + rendered content
    "text": 0.90,  # the primary channel; most scams arrive as text
    "voice": 0.85,  # transcript quality depends on ASR
    "image": 0.75,  # OCR introduces transcription error
    "phone": 0.50,  # often only a format check unless the registry knows it
    "digital_arrest": 1.00,  # signature match is dispositive by design
}

#: Findings that force an immediate critical verdict. Kept as a module-level
#: constant so tests, docs, and the API surface can all reference one source.
CRITICAL_OVERRIDES: frozenset[str] = frozenset(
    {
        "verified_impersonation",  # claims to be a bank/agency and is not theirs
        "otp_exfiltration",  # asks for an OTP / verification code
        "cnic_exfiltration",  # asks for CNIC
        "digital_arrest",  # fake arrest / FIR / "stay on the call" coercion
        "remote_access_request",  # asks victim to install AnyDesk/TeamViewer
        "typosquatting",  # domain within edit-distance 2 of a real institution
    }
)

#: Findings that strongly suppress the score. False positives on genuine
#: institutional messages are the fastest way to lose user trust.
TRUST_SIGNALS: frozenset[str] = frozenset(
    {
        "verified_registry_match",  # sender/domain is an authenticated institution
        "known_good_sender",  # user or family previously marked this sender safe
    }
)


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def combine_scores(
    scores: Iterable[ModuleScore | dict[str, Any]],
    *,
    scam_threshold: float = SCAM_THRESHOLD,
    critical_threshold: float = CRITICAL_THRESHOLD,
    corroboration_bonus: float = 4.0,
    trust_penalty: float = 45.0,
) -> Verdict:
    """Combine analyzer outputs into one defensible verdict.

    Args:
        scores: ``ModuleScore`` instances, or plain dicts with the same keys
            (the dict form is what arrives over HTTP from the analyzers).
        scam_threshold: confidence at which we declare a scam.
        critical_threshold: confidence at which we escalate.
        corroboration_bonus: points added per *additional* agreeing module
            (beyond the first) that independently crossed the scam threshold.
        trust_penalty: points subtracted when a verified-institution signal is
            present. Deliberately large: an authenticated bank domain is very
            strong evidence against fraud.

    Returns:
        A :class:`Verdict` with the score, label, contributing factors, and a
        per-module breakdown suitable for logging and for showing "why".
    """
    normalized: list[ModuleScore] = []
    for raw in scores:
        if isinstance(raw, ModuleScore):
            normalized.append(raw)
        elif isinstance(raw, dict):
            normalized.append(
                ModuleScore(
                    module=str(raw.get("module", "unknown")),
                    confidence=float(raw.get("confidence", 0) or 0),
                    weight=float(raw.get("weight", DEFAULT_WEIGHTS.get(str(raw.get("module")), 0.7))),
                    applicable=bool(raw.get("applicable", True)),
                    risk_factors=tuple(raw.get("risk_factors") or ()),
                    overrides=tuple(raw.get("overrides") or ()),
                )
            )
        else:  # pragma: no cover - defensive
            raise TypeError(f"Unsupported score type: {type(raw)!r}")

    applicable = [s for s in normalized if s.applicable]
    all_overrides = {o for s in normalized for o in s.overrides}
    all_factors: list[str] = []
    for s in normalized:
        for f in s.risk_factors:
            if f not in all_factors:
                all_factors.append(f)

    # ---- Hard overrides: dispositive findings win outright ------------------
    critical_hits = sorted(all_overrides & CRITICAL_OVERRIDES)
    trust_hits = sorted(all_overrides & TRUST_SIGNALS)

    if not applicable:
        return Verdict(
            confidence=0,
            label="unknown",
            is_scam=False,
            is_critical=False,
            risk_factors=[],
            contributing_modules=[],
            explanation="Nothing could be analyzed.",
            overrides=[],
            trust_signals=trust_hits,
        )

    # ---- Noisy-OR over applicable modules ----------------------------------
    miss_product = 1.0
    for s in applicable:
        w = _clamp(s.weight, 0.0, 1.0)
        p = _clamp(s.confidence, 0.0, 100.0) / 100.0
        contribution = w * p
        # Clamp so a weight can never push a single module above certainty.
        contribution = _clamp(contribution, 0.0, 0.99)
        miss_product *= 1.0 - contribution

    combined = (1.0 - miss_product) * 100.0

    # ---- Corroboration: independent agreement is real evidence --------------
    agreeing = [s for s in applicable if s.confidence >= scam_threshold]
    if len(agreeing) > 1:
        combined += corroboration_bonus * (len(agreeing) - 1)

    # ---- Trust discount ----------------------------------------------------
    if trust_hits:
        combined -= trust_penalty * len(trust_hits)

    combined = _clamp(combined)

    # ---- Overrides set the floor -------------------------------------------
    # A verified-institution match is the ONE signal allowed to overrule a hard
    # override, because institutions do legitimately send OTP messages to their
    # own authenticated customers. Everything else escalates.
    if critical_hits and not trust_hits:
        combined = max(combined, critical_threshold)

    is_critical = combined >= critical_threshold or (bool(critical_hits) and not trust_hits)
    is_scam = is_critical or combined >= scam_threshold

    if is_critical:
        label = "critical"
    elif is_scam:
        label = "scam"
    elif combined >= 30:
        label = "suspicious"
    else:
        label = "safe"

    if not applicable:  # pragma: no cover - unreachable, kept for symmetry
        explanation = "Nothing could be analyzed."
    elif label == "critical":
        explanation = "Multiple serious scam indicators found. Do not respond to this message."
    elif label == "scam":
        explanation = "This looks like a scam. Do not share any codes or personal details."
    elif label == "suspicious":
        explanation = "Some warning signs. Verify through an official channel before acting."
    else:
        explanation = "No significant scam indicators found."

    return Verdict(
        confidence=int(round(combined)),
        label=label,
        is_scam=is_scam,
        is_critical=is_critical,
        risk_factors=all_factors,
        contributing_modules=[
            {
                "module": s.module,
                "confidence": int(round(_clamp(s.confidence))),
                "weight": round(_clamp(s.weight, 0.0, 1.0), 2),
                "applicable": s.applicable,
            }
            for s in normalized
        ],
        explanation=explanation,
        overrides=critical_hits,
        trust_signals=trust_hits,
    )


@dataclass(frozen=True)
class Verdict:
    """The final, user-facing result of a scan.

    ``confidence`` is intentionally kept as an integer percentage for API
    compatibility with the existing frontend, but the frontend should render
    ``label`` and the localized advice from :mod:`app.verdict.render` — a bare
    percentage is not actionable for the audience this product serves.
    """

    confidence: int
    label: str  # "critical" | "scam" | "suspicious" | "safe" | "unknown"
    is_scam: bool
    is_critical: bool
    risk_factors: list[str]
    contributing_modules: list[dict[str, Any]]
    explanation: str
    overrides: list[str] = field(default_factory=list)
    trust_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "label": self.label,
            "is_scam": self.is_scam,
            "is_critical": self.is_critical,
            "risk_factors": self.risk_factors,
            "explanation": self.explanation,
            "critical_indicators": self.overrides,
            "trust_signals": self.trust_signals,
            "modules": self.contributing_modules,
        }
