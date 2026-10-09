"""Detector for the "digital arrest" / fake-official coercion scam.

This is the fastest-growing fraud pattern in South Asia and the one that causes
the largest individual losses, so it gets a dedicated detector rather than being
folded into generic keyword matching.

HOW THE SCAM WORKS
------------------
1. Initial contact by SMS / WhatsApp / call claiming the victim's CNIC, phone
   number, bank account, or a courier parcel is linked to a serious crime
   (money laundering, pornography, drugs, terror financing).
2. The victim is told to call a number urgently to avoid "arrest".
3. On the call, fraudsters impersonate FIA / NCCIA / NADRA / SBP / PTA / police
   / customs officers. 2026 variants use spoofed caller IDs, fake uniforms,
   forged FIRs and arrest warrants, and staged office backgrounds.
4. The victim is kept on a video call for HOURS -- explicitly to stop them
   consulting family, a lawyer, or the real institution.
5. The victim is told to install AnyDesk / TeamViewer / a "verification" app,
   which gives the fraudster the screen -- and therefore every OTP.
6. Money is transferred to mule accounts to "settle" or "verify" the case.

THE TELL
--------
Every stage depends on **secrecy and isolation**. A legitimate state institution
issues written notice, permits legal counsel, and never asks you to keep it from
your family. So any instruction not to consult anyone is, by itself, dispositive.

Detection strategy: look for the *coercion signature*, not just institution names.
Scoring ANY two of the signature categories as critical is what makes this work --
legitimate messages mention an institution OR mention a deadline, but they do not
pair an arrest threat with a demand for secrecy and a money transfer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = ["DigitalArrestResult", "detect_digital_arrest"]

# Pakistani institutions that are routinely impersonated. Matching these alone is
# NOT sufficient for a verdict -- a real NADRA SMS mentions NADRA.
_IMPERSONATED_AUTHORITIES: tuple[str, ...] = (
    # English / romanized
    "fia", "nccia", "nadra", "state bank", "sbp", "pta", "fbr", "nab",
    "cyber crime", "cybercrime", "police", "customs", "court", "judge",
    "magistrate", "investigation", "investigating officer", "io ",
    # Urdu
    "ایف آئی اے", "نیب", "نادرا", "اسٹیٹ بینک", "پولیس", "عدالت", "جج",
    "کسٹم", "تحقیقات", "سائبر کرائم",
)

# Category 1 -- legal threat / arrest coercion
_THREAT: tuple[str, ...] = (
    "arrest", "arrested", "arrest warrant", "warrant", "fir", "case registered",
    "case file", "digital arrest", "custody", "jail", "prison", "prosecution",
    "chargesheet", "charge sheet", "criminal case", "non-bailable",
    "money laundering", "terror financ", "drug", "obscene", "pornograph",
    "illegal transaction", "suspicious transaction", "account freeze",
    "account blocked", "account seal", "blacklisted",
    "گرفتار", "گرفتاری", "وارنٹ", "مقدمہ", "کیس درج", "جیل", "قید",
    "منی لانڈرنگ", "اکاؤنٹ بند", "اکاؤنٹ منجمد", "فوجداری", "غیر قانونی",
)

# Category 2 -- SECRECY / ISOLATION. This is the strongest single tell.
_SECRECY: tuple[str, ...] = (
    "do not tell", "don't tell", "dont tell", "do not inform", "don't inform",
    "keep it secret", "keep this secret", "confidential", "strictly confidential",
    "do not share with family", "don't tell your family", "do not tell anyone",
    "don't tell anyone", "nobody should know", "do not discuss", "hush",
    "secret", "not tell family", "without informing",
    "kisi ko mat bata", "kisi ko na bata", "kisi ko batana mat",
    "kisi ko nahi batana", "ghar walon ko mat bata", "family ko mat bata",
    "raaz", "khufiya", "khaufiya", "chup reh", "khamosh reh",
    "کسی کو مت بتا", "کسی کو نہ بتا", "گھر والوں کو مت بتا", "خفیہ", "راز",
)

# Category 3 -- keep the channel open / prevent verification
_ISOLATION: tuple[str, ...] = (
    "stay on the line", "stay on call", "remain on call", "do not hang up",
    "don't hang up", "keep the call", "video call", "video verification",
    "stay connected", "do not disconnect", "continuous monitoring",
    "under monitoring", "being monitored", "we are watching",
    "call par rahe", "line par rahe", "phone mat kaat", "call mat kaat",
    "video call par", "lagatar", "monitoring",
    "کال پر رہیں", "فون مت کاٹیں", "ویڈیو کال", "نظر رکھی جا رہی",
)

# Category 4 -- remote access / screen sharing (hands the attacker every OTP)
_REMOTE_ACCESS: tuple[str, ...] = (
    "anydesk", "teamviewer", "team viewer", "rustdesk", "ammyy", "logmein",
    "remote access", "remote desktop", "screen share", "screen sharing",
    "share your screen", "install this app", "download this app",
    "install the app", "verification app", "kyc app",
    "screen share karein", "app install karein", "app download karein",
    "اسکرین شیئر", "ایپ انسٹال", "ریموٹ اکسیس",
)

# Category 5 -- payment to "resolve" the fake case
_PAYMENT: tuple[str, ...] = (
    "settle", "settlement", "clear the case", "close the case", "compound",
    "compromise", "fine", "penalty", "security deposit", "verification amount",
    "transfer to verify", "transfer for verification", "prove your balance",
    "show your balance", "refundable", "will be returned", "safe account",
    "government account", "escrow", "bail amount",
    "case khatam", "case band", "settle kar", "jurmana", "zemanat",
    "amanat", "wapas kar denge", "safe account mein",
    "فیصلہ", "جرمانہ", "ضمانت", "رقم منتقل", "واپس کر دی جائے",
)

# Category 6 -- urgency + a demand for credentials, which is how the money moves
_CREDENTIALS: tuple[str, ...] = (
    "otp", "one time password", "one-time password", "verification code",
    "pin code", "cnic", "nadra number", "bank account number", "iban",
    "card number", "cvv", "password", "biometric", "fingerprint verification",
    "code bata", "code bhej", "otp bhej", "otp bata", "pin bata",
    "او ٹی پی", "کوڈ بتا", "کوڈ بھیج", "پن", "شناختی کارڈ", "پاس ورڈ",
)

_URGENCY: tuple[str, ...] = (
    "immediately", "urgent", "urgently", "within 24 hours", "within 2 hours",
    "within 1 hour", "right now", "last warning", "final warning", "last chance",
    "before its too late", "act now", "otherwise", "or else",
    "foran", "fauran", "abhi", "abhi ke abhi", "turant", "jald az jald",
    "aakhri", "warna", "فوری", "ابھی", "جلد از جلد", "ورنہ", "آخری",
)

#: The signature categories. Two or more => critical.
_SIGNATURE: dict[str, tuple[str, ...]] = {
    "legal_threat": _THREAT,
    "secrecy": _SECRECY,
    "isolation": _ISOLATION,
    "remote_access": _REMOTE_ACCESS,
    "payment_demand": _PAYMENT,
    "credential_demand": _CREDENTIALS,
    "urgency": _URGENCY,
}

#: Weight per category. Secrecy, isolation, and remote access are near-proof on
#: their own; urgency alone is common in legitimate marketing and scores low.
_CATEGORY_WEIGHT: dict[str, float] = {
    "secrecy": 55.0,
    "isolation": 50.0,
    "remote_access": 60.0,
    "legal_threat": 40.0,
    "payment_demand": 35.0,
    "credential_demand": 30.0,
    "urgency": 15.0,
}


@dataclass(frozen=True)
class DigitalArrestResult:
    """Result of the digital-arrest signature check.

    Attributes:
        confidence: 0-100.
        matched_categories: which signature categories fired.
        matched_terms: the literal phrases that fired, for the explanation UI.
        authority_claimed: which institution the message claims to be from.
        is_digital_arrest: True when the coercion signature is met.
        overrides: feeds straight into
            :func:`haafiz.scoring.engine.combine_scores`.
    """

    confidence: int
    matched_categories: list[str]
    matched_terms: list[str]
    authority_claimed: list[str]
    is_digital_arrest: bool
    overrides: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "matched_categories": self.matched_categories,
            "matched_terms": self.matched_terms,
            "authority_claimed": self.authority_claimed,
            "is_digital_arrest": self.is_digital_arrest,
            "risk_factors": self.matched_categories,
            "overrides": self.overrides,
        }


def _normalize(text: str) -> str:
    """Lowercase and collapse whitespace.

    We deliberately do NOT strip punctuation or diacritics: Urdu text and
    hyphenated phrases like "one-time" carry meaning in their punctuation.
    """
    return re.sub(r"\s+", " ", text.lower()).strip()


def detect_digital_arrest(text: str) -> DigitalArrestResult:
    """Check ``text`` for the digital-arrest coercion signature.

    Args:
        text: the message, transcript, or OCR output to analyze.

    Returns:
        A :class:`DigitalArrestResult`. Never raises on empty input; an empty
        string simply yields a zero-confidence negative result.
    """
    if not text or not text.strip():
        return DigitalArrestResult(
            confidence=0,
            matched_categories=[],
            matched_terms=[],
            authority_claimed=[],
            is_digital_arrest=False,
        )

    haystack = _normalize(text)
    # Word-ish boundaries matter for short tokens like "fir", "io", "pta", "nab"
    # which would otherwise match inside unrelated words. Urdu has no spaces
    # problem, so we fall back to substring matching for non-ASCII terms.
    padded = f" {haystack} "

    matched_categories: list[str] = []
    matched_terms: list[str] = []

    for category, phrases in _SIGNATURE.items():
        hit_terms: list[str] = []
        for phrase in phrases:
            p = phrase.strip().lower()
            if not p:
                continue
            is_ascii = all(ord(ch) < 128 for ch in p)
            if is_ascii:
                # Word-boundary match for latin tokens; a trailing space in the
                # source phrase ("io ") is intentional and preserved.
                pattern = r"(?<![a-z0-9])" + re.escape(p.rstrip()) + r"(?![a-z0-9])"
                if re.search(pattern, padded):
                    hit_terms.append(p.strip())
            else:
                if p in haystack:
                    hit_terms.append(p)

        if hit_terms:
            matched_categories.append(category)
            matched_terms.extend(hit_terms)

    authorities = [
        a.strip().lower()
        for a in _IMPERSONATED_AUTHORITIES
        if (
            re.search(r"(?<![a-z])" + re.escape(a.strip().lower()) + r"(?![a-z])", padded)
            if all(ord(ch) < 128 for ch in a)
            else a.strip() in haystack
        )
    ]

    if not matched_categories:
        return DigitalArrestResult(
            confidence=0,
            matched_categories=[],
            matched_terms=[],
            authority_claimed=authorities,
            is_digital_arrest=False,
        )

    # Noisy-OR across matched categories, so a single very strong tell (remote
    # access request) can carry the verdict on its own while weaker tells
    # accumulate.
    miss = 1.0
    for category in matched_categories:
        miss *= 1.0 - (_CATEGORY_WEIGHT.get(category, 20.0) / 100.0)
    confidence = (1.0 - miss) * 100.0

    # Claiming to be a state institution alongside a coercion signature is an
    # aggravating factor, not a standalone one.
    if authorities:
        confidence = min(100.0, confidence + 15.0)

    # Two or more distinct signature categories is the operational definition of
    # a digital-arrest attempt, and forces a critical verdict downstream.
    strong_categories = [c for c in matched_categories if c != "urgency"]
    is_digital_arrest = len(strong_categories) >= 2 or confidence >= 70.0

    overrides: list[str] = []
    if is_digital_arrest:
        overrides.append("digital_arrest")
    if "remote_access" in matched_categories:
        overrides.append("remote_access_request")
    if "credential_demand" in matched_categories and ("legal_threat" in matched_categories or authorities):
        overrides.append("otp_exfiltration")
    if "secrecy" in matched_categories:
        # Isolation demand => notify the family group even if the score is middling.
        overrides.append("isolation_demand")

    return DigitalArrestResult(
        confidence=int(round(min(100.0, confidence))),
        matched_categories=matched_categories,
        # De-duplicate while preserving order; cap so a long message cannot
        # flood the UI.
        matched_terms=list(dict.fromkeys(matched_terms))[:20],
        authority_claimed=list(dict.fromkeys(authorities)),
        is_digital_arrest=is_digital_arrest,
        overrides=overrides,
    )
