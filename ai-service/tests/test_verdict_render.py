"""Tests for plain-language verdict rendering.

The contract under test is a *product* rule, not just a formatting rule: a
non-technical user must receive a verdict word, a concrete reason, and an
imperative action -- and must never be shown a bare percentage.
"""

from __future__ import annotations

import pytest

from haafiz.verdict.render import SUPPORTED_LANGS, render_verdict


class TestNeverShowBarePercentage:
    """The single most important UX rule in the product."""

    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    @pytest.mark.parametrize("label", ["critical", "scam", "suspicious", "safe", "unknown"])
    def test_consumer_audience_never_sees_confidence(self, lang, label):
        msg = render_verdict(label=label, confidence=73, lang=lang, audience="consumer")
        assert msg.show_confidence is False
        # The rendered WhatsApp text is what the user actually reads.
        text = msg.as_whatsapp_text()
        assert "73" not in text
        assert "%" not in text

    def test_guardian_audience_does_see_confidence_flag(self):
        msg = render_verdict(label="scam", confidence=73, lang="roman", audience="guardian")
        assert msg.show_confidence is True
        assert msg.confidence == 73


class TestVerdictStructure:
    def test_scam_verdict_has_word_reason_and_action(self):
        msg = render_verdict(
            label="scam",
            risk_factors=["otp_exfiltration"],
            confidence=78,
            lang="roman",
        )
        assert msg.verdict_word
        assert msg.reasons, "every non-safe verdict must explain why"
        assert msg.actions, "every scam verdict must say what to do"
        assert len(msg.actions) >= 2

    def test_actions_are_ordered_by_urgency(self):
        """The most time-critical step must be first -- users often read only step 1."""
        msg = render_verdict(
            label="critical",
            risk_factors=["suspicious_link", "digital_arrest", "otp_exfiltration"],
            critical_indicators=["digital_arrest"],
            lang="roman",
        )
        assert "kaat" in msg.actions[0].lower() or "hang" in msg.actions[0].lower()

    def test_action_list_is_capped(self):
        """A list longer than five steps is a list nobody finishes."""
        msg = render_verdict(
            label="critical",
            risk_factors=[
                "digital_arrest",
                "remote_access_request",
                "otp_exfiltration",
                "isolation_demand",
                "cnic_request",
                "typosquatting",
                "suspicious_link",
                "domain_age",
                "ssl",
                "investment",
                "reward",
            ],
            lang="roman",
        )
        assert len(msg.actions) <= 5

    def test_no_duplicate_lines_in_one_message(self):
        """Repetition makes the message look broken to a low-literacy reader."""
        msg = render_verdict(
            label="critical",
            risk_factors=["otp_exfiltration", "cnic_request"],
            critical_indicators=["otp_exfiltration"],
            lang="roman",
        )
        assert len(msg.actions) == len(set(msg.actions))

    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    def test_reasons_explain_and_actions_instruct_never_identical(self, lang):
        """A sentence must not appear as both the reason and the instruction."""
        msg = render_verdict(
            label="critical",
            risk_factors=["digital_arrest", "otp_exfiltration", "remote_access_request"],
            critical_indicators=["digital_arrest"],
            lang=lang,
        )
        overlap = set(msg.reasons) & set(msg.actions)
        assert not overlap, f"reason and action duplicated: {overlap}"

    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    def test_reasons_are_distinct_from_each_other(self, lang):
        msg = render_verdict(
            label="critical",
            risk_factors=["digital_arrest", "otp_exfiltration", "suspicious_link", "domain_age"],
            lang=lang,
        )
        assert len(msg.reasons) == len(set(msg.reasons))

    def test_safe_verdict_has_no_actions_or_family_nudge(self):
        msg = render_verdict(label="safe", confidence=2, lang="roman")
        assert msg.actions == []
        assert msg.family_nudge is None
        assert msg.notify_family is False
        assert msg.escalate is False

    def test_unknown_label_is_handled_gracefully(self):
        msg = render_verdict(label="garbage_value", lang="roman")
        assert msg.label == "unknown"
        assert msg.verdict_word


class TestFamilyShieldIntegration:
    """Isolation is the scammer's main weapon; reaching family is the counter."""

    def test_critical_verdict_notifies_family(self):
        msg = render_verdict(label="critical", confidence=94, lang="roman")
        assert msg.notify_family is True
        assert msg.escalate is True

    def test_isolation_demand_alone_notifies_family(self):
        """Even a middling score must alert family if secrecy was demanded."""
        msg = render_verdict(
            label="suspicious",
            risk_factors=["isolation_demand"],
            confidence=40,
            lang="roman",
        )
        assert msg.notify_family is True
        assert msg.family_nudge is not None

    def test_digital_arrest_notifies_family(self):
        msg = render_verdict(label="scam", risk_factors=["digital_arrest"], lang="roman")
        assert msg.notify_family is True

    def test_family_nudge_present_on_every_non_safe_verdict(self):
        for label in ("critical", "scam", "suspicious", "unknown"):
            msg = render_verdict(label=label, lang="roman")
            assert msg.family_nudge, f"{label} must prompt involving family"


class TestSpeechOutput:
    """The IVR helpline and WhatsApp voice replies read ``speech`` aloud."""

    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    def test_speech_is_present_in_every_language(self, lang):
        msg = render_verdict(label="scam", lang=lang)
        assert msg.speech.strip()

    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    def test_speech_contains_no_numerals(self, lang):
        """Spoken output must be hearable -- '94%' is meaningless aloud."""
        msg = render_verdict(label="critical", confidence=94, lang=lang)
        assert not any(ch.isdigit() for ch in msg.speech)

    def test_speech_differs_from_verdict_word(self):
        msg = render_verdict(label="scam", lang="roman")
        assert msg.speech != msg.verdict_word
        assert len(msg.speech) > len(msg.verdict_word)


class TestLanguageCoverage:
    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    def test_every_label_renders_in_every_language(self, lang):
        for label in ("critical", "scam", "suspicious", "safe", "unknown"):
            msg = render_verdict(label=label, risk_factors=["otp_exfiltration"], lang=lang)
            assert msg.verdict_word.strip()
            assert msg.lang == lang

    @pytest.mark.parametrize(
        "alias,expected",
        [
            ("roman_urdu", "roman"),
            ("roman-urdu", "roman"),
            ("ur", "urdu"),
            ("ur-PK", "urdu"),
            ("EN", "en"),
            ("eng", "en"),
            ("pus", "ps"),
            ("brh", "bal"),
        ],
    )
    def test_language_aliases_resolve(self, alias, expected):
        msg = render_verdict(label="scam", lang=alias)
        assert msg.lang == expected

    def test_unknown_language_falls_back_to_roman_urdu(self):
        """Roman Urdu is the widest-reaching written form in Pakistan."""
        msg = render_verdict(label="scam", lang="zh")
        assert msg.lang == "roman"

    def test_missing_language_falls_back_to_roman_urdu(self):
        assert render_verdict(label="scam", lang=None).lang == "roman"
        assert render_verdict(label="scam", lang="").lang == "roman"

    def test_urdu_script_actually_uses_urdu_characters(self):
        msg = render_verdict(label="critical", lang="urdu")
        assert any("\u0600" <= ch <= "\u06FF" for ch in msg.verdict_word)

    def test_sindhi_and_punjabi_differ_from_urdu(self):
        """Guards against a copy-paste translation that silently reuses Urdu."""
        urdu = render_verdict(label="critical", risk_factors=["otp_exfiltration"], lang="urdu")
        sindhi = render_verdict(label="critical", risk_factors=["otp_exfiltration"], lang="sd")
        punjabi = render_verdict(label="critical", risk_factors=["otp_exfiltration"], lang="pa")
        assert urdu.actions[0] != sindhi.actions[0]
        assert urdu.actions[0] != punjabi.actions[0]


class TestWhatsAppRendering:
    def test_critical_uses_siren_emoji(self):
        msg = render_verdict(label="critical", risk_factors=["otp_exfiltration"], lang="roman")
        assert msg.as_whatsapp_text().startswith("🚨")

    def test_safe_uses_check_emoji(self):
        assert render_verdict(label="safe", lang="roman").as_whatsapp_text().startswith("✅")

    def test_suspicious_uses_warning_emoji(self):
        assert render_verdict(label="suspicious", lang="roman").as_whatsapp_text().startswith("⚠️")

    def test_actions_are_numbered(self):
        msg = render_verdict(label="scam", risk_factors=["otp_exfiltration"], lang="roman")
        text = msg.as_whatsapp_text()
        assert "1." in text

    def test_family_notification_is_disclosed(self):
        """Surveillance must be visible -- silently alerting family erodes trust."""
        msg = render_verdict(label="critical", lang="roman")
        assert "family group" in msg.as_whatsapp_text().lower()

    def test_no_html_in_output(self):
        """WhatsApp renders no HTML; raw tags would show up as literal text."""
        msg = render_verdict(label="scam", risk_factors=["otp_exfiltration"], lang="roman")
        text = msg.as_whatsapp_text()
        for tag in ("<b>", "<br>", "<p>", "<div>"):
            assert tag not in text

    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    def test_section_headers_are_localized(self, lang):
        """An Urdu-script message with Roman Urdu headers reads as half-translated."""
        msg = render_verdict(label="scam", risk_factors=["otp_exfiltration"], lang=lang)
        text = msg.as_whatsapp_text()
        if lang != "roman" and lang != "en":
            assert "Kyun:" not in text
            assert "Abhi kya karein:" not in text
        # The header must be present in SOME form.
        assert ":" in text

    @pytest.mark.parametrize("lang", SUPPORTED_LANGS)
    def test_family_notification_line_is_localized(self, lang):
        msg = render_verdict(label="critical", lang=lang)
        text = msg.as_whatsapp_text()
        assert "🔔" in text
        if lang == "urdu":
            assert "فیملی" in text
        elif lang == "en":
            assert "family group" in text.lower()
        elif lang == "roman":
            assert "family group" in text.lower()
        else:
            # Non-Roman, non-English scripts must not silently fall back to Roman Urdu.
            assert "Aap ke family group" not in text


class TestOfficialReportingGuidance:
    def test_scam_verdict_includes_official_report_channels(self):
        """HAAFIZ must route victims to PTA 9000 / NCCIA 1930, not just say 'scam'."""
        msg = render_verdict(label="scam", risk_factors=["otp_exfiltration"], lang="roman")
        joined = " ".join(msg.actions)
        assert "9000" in joined or "1930" in joined

    def test_urdu_verdict_includes_report_channels_in_urdu_digits_or_latin(self):
        msg = render_verdict(label="scam", risk_factors=["otp_exfiltration"], lang="urdu")
        joined = " ".join(msg.actions)
        assert "9000" in joined or "۹۰۰۰" in joined


class TestSerialisation:
    def test_to_dict_is_json_serialisable(self):
        import json

        msg = render_verdict(
            label="critical",
            risk_factors=["digital_arrest", "otp_exfiltration"],
            confidence=96,
            lang="roman",
            audience="guardian",
        )
        payload = json.loads(json.dumps(msg.to_dict()))
        assert payload["label"] == "critical"
        assert payload["escalate"] is True
        assert payload["show_confidence"] is True
        assert payload["language"] == "roman"
