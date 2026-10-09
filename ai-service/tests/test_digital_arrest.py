"""Tests for the digital-arrest coercion detector.

The test messages here are reconstructed from documented scam patterns (fake
FIA/NCCIA/NADRA/SBP officials, "digital arrest", secrecy demands, AnyDesk
installation, mule-account transfers). Equally important are the negative cases:
a genuine bank SMS or a genuine NADRA notification must NOT be flagged, because
false alarms on legitimate institutional messages are what makes people stop
using a protection tool.
"""

from __future__ import annotations

import pytest

from haafiz.analyzers.digital_arrest import detect_digital_arrest


class TestPositiveDetection:
    def test_full_english_digital_arrest(self):
        text = (
            "Dear Citizen, this is Investigating Officer Ahmed from FIA Cyber Crime Wing. "
            "Your CNIC has been linked to a money laundering case and an arrest warrant "
            "has been issued. Do not tell anyone in your family, this is strictly "
            "confidential. Stay on this video call while we verify. Install AnyDesk "
            "immediately so we can see your screen. Transfer a security deposit of "
            "Rs 250,000 to settle the case or you will be arrested within 24 hours."
        )
        result = detect_digital_arrest(text)
        assert result.is_digital_arrest is True
        assert result.confidence >= 85
        assert "digital_arrest" in result.overrides
        assert "remote_access_request" in result.overrides
        for category in ("legal_threat", "secrecy", "isolation", "remote_access", "payment_demand", "urgency"):
            assert category in result.matched_categories
        assert any("fia" in a for a in result.authority_claimed)

    def test_roman_urdu_digital_arrest(self):
        """The dominant real-world form -- Roman Urdu is how Pakistanis type."""
        text = (
            "Ye FIA Cyber Crime se officer bol raha hoon. Aap ka CNIC money laundering "
            "case mein involve hai aur arrest warrant issue ho chuka hai. Ghar walon ko "
            "mat batana, ye khufiya mamla hai. Phone mat kaat, video call par rahein. "
            "AnyDesk install karein foran. Case settle karne ke liye Rs 2 lakh transfer "
            "karein warna aaj hi giraftari ho jayegi."
        )
        result = detect_digital_arrest(text)
        assert result.is_digital_arrest is True
        assert "secrecy" in result.matched_categories
        assert "isolation" in result.matched_categories
        assert "remote_access" in result.matched_categories
        assert "isolation_demand" in result.overrides

    def test_urdu_script_digital_arrest(self):
        text = (
            "یہ ایف آئی اے سائبر کرائم سے بات ہو رہی ہے۔ آپ کا شناختی کارڈ منی لانڈرنگ "
            "کیس میں ملوث ہے۔ گرفتاری کا وارنٹ جاری ہو چکا ہے۔ کسی کو مت بتائیں، یہ خفیہ "
            "معاملہ ہے۔ فون مت کاٹیں، ویڈیو کال پر رہیں۔ کیس ختم کرنے کے لیے رقم منتقل کریں۔"
        )
        result = detect_digital_arrest(text)
        assert result.is_digital_arrest is True
        assert "secrecy" in result.matched_categories
        assert "legal_threat" in result.matched_categories

    def test_secrecy_alone_is_a_very_strong_tell(self):
        """'Don't tell your family' has no legitimate use in a financial message."""
        text = "Aap ka account verify karna hai, kisi ko mat batana, ye confidential hai."
        result = detect_digital_arrest(text)
        assert "secrecy" in result.matched_categories
        assert "isolation_demand" in result.overrides
        assert result.confidence >= 50

    def test_remote_access_request_is_dispositive(self):
        text = "Please install AnyDesk so our officer can verify your KYC and help you."
        result = detect_digital_arrest(text)
        assert "remote_access" in result.matched_categories
        assert "remote_access_request" in result.overrides
        assert result.confidence >= 55

    def test_short_sms_variant(self):
        """Real smishing SMS are terse; detection must not need a paragraph."""
        text = "FIA: arrest warrant issued ur CNIC. Call 03001234567 foran. Kisi ko batana mat."
        result = detect_digital_arrest(text)
        assert result.confidence >= 60
        assert "legal_threat" in result.matched_categories
        assert "urgency" in result.matched_categories

    def test_otp_demand_with_authority_claim_escalates(self):
        text = "State Bank: your account will be blocked. Share your OTP code to verify immediately."
        result = detect_digital_arrest(text)
        assert "otp_exfiltration" in result.overrides
        assert any("state bank" in a for a in result.authority_claimed)


class TestNegativeCases:
    """False positives destroy trust. These must all come back clean."""

    def test_empty_string(self):
        result = detect_digital_arrest("")
        assert result.confidence == 0
        assert result.is_digital_arrest is False
        assert result.overrides == []

    def test_none_like_whitespace(self):
        result = detect_digital_arrest("   \n\t ")
        assert result.confidence == 0
        assert result.is_digital_arrest is False

    def test_genuine_bank_transaction_alert(self):
        text = "HBL: Rs 5,000 debited from your account ****1234 on 09-Oct. If unauthorized call 1122."
        result = detect_digital_arrest(text)
        assert result.is_digital_arrest is False
        assert "secrecy" not in result.matched_categories
        assert "remote_access" not in result.matched_categories

    def test_genuine_delivery_notification(self):
        text = "Your TCS parcel has arrived at the Karachi branch. Collect between 9am and 6pm."
        result = detect_digital_arrest(text)
        assert result.is_digital_arrest is False

    def test_legitimate_otp_from_authenticated_bank(self):
        """A real OTP message mentions an OTP but has no coercion signature."""
        text = "Your HBL One-Time Password is 483921. Valid for 5 minutes."
        result = detect_digital_arrest(text)
        assert result.is_digital_arrest is False
        # Credential words alone must not escalate without a threat or authority claim.
        assert "otp_exfiltration" not in result.overrides

    def test_news_article_mentioning_arrest_is_not_flagged(self):
        """Reporting ABOUT arrests must not trip the detector."""
        text = "Dawn: Police arrested three suspects in a fraud case in Multan yesterday."
        result = detect_digital_arrest(text)
        # A single category (legal_threat) with no coercion pairing is not enough.
        assert result.is_digital_arrest is False

    def test_urgency_alone_is_not_a_scam(self):
        """Marketing urgency is common and legitimate; it must not escalate alone."""
        text = "Last chance! Sale ends today, shop now for discounts."
        result = detect_digital_arrest(text)
        assert result.is_digital_arrest is False
        assert "digital_arrest" not in result.overrides


class TestFalsePositiveHardening:
    def test_short_tokens_do_not_match_inside_words(self):
        """'fir' must not match 'first'; 'nab' must not match 'banana'."""
        text = "First, confirm your profile details. The banana shipment arrived."
        result = detect_digital_arrest(text)
        assert "legal_threat" not in result.matched_categories

    def test_pta_does_not_match_inside_another_word(self):
        text = "Please adapt the settings to your preference."
        result = detect_digital_arrest(text)
        assert not any(a == "pta" for a in result.authority_claimed)

    def test_matched_terms_are_deduplicated_and_capped(self):
        text = "OTP otp OTP verification code OTP code batao OTP bhejo " * 20
        result = detect_digital_arrest(text)
        assert len(result.matched_terms) <= 20
        assert len(result.matched_terms) == len(set(result.matched_terms))

    def test_whitespace_normalisation(self):
        a = detect_digital_arrest("FIA   arrest    warrant     issued")
        b = detect_digital_arrest("FIA arrest warrant issued")
        assert a.confidence == b.confidence


class TestResultShape:
    def test_to_dict_is_json_serialisable(self):
        import json

        result = detect_digital_arrest("FIA arrest warrant, kisi ko mat batana")
        payload = json.loads(json.dumps(result.to_dict()))
        assert payload["confidence"] >= 0
        assert isinstance(payload["matched_categories"], list)
        assert "risk_factors" in payload
        assert "overrides" in payload

    @pytest.mark.parametrize(
        "lang_text",
        [
            "FIA arrest warrant issued. Do not tell anyone. Install AnyDesk now.",
            "ایف آئی اے، وارنٹ، کسی کو مت بتائیں، ویڈیو کال پر رہیں",
            "FIA, warrant, kisi ko mat batao, video call par rahein",
        ],
    )
    def test_multilingual_consistency(self, lang_text):
        result = detect_digital_arrest(lang_text)
        assert result.confidence > 0
        assert result.matched_categories
