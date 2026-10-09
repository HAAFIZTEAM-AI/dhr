"""Tests for reply-language detection.

Getting this wrong is not a cosmetic bug. Unlike a website there is no language
selector to fall back on -- a verdict delivered in the wrong language is a verdict
the user cannot act on, and the whole zero-friction promise collapses.
"""

from __future__ import annotations

import pytest

from whatsapp.language import SUPPORTED_REPLY_LANGS, detect_language, parse_language_command, resolve_language


class TestScriptDetection:
    def test_urdu_script(self):
        assert detect_language("یہ ایف آئی اے سے بات ہو رہی ہے، آپ کا وارنٹ جاری ہے") == "urdu"

    def test_sindhi_specific_characters(self):
        """Sindhi uses letters Urdu does not: ڪ ڳ ڱ ڻ ھ ٿ ٺ ٽ."""
        assert detect_language("هي پيغام فراڊ آهي، ڪنهن کي به نه ٻڌايو") == "sd"

    def test_pashto_specific_characters(self):
        """Pashto uses ټ ځ څ ډ ړ ږ ښ ګ ڼ."""
        assert detect_language("دا پيغام درغلۍ ده، چا ته مه وايئ") == "ps"

    def test_punjabi_shahmukhi_specific_characters(self):
        """Shahmukhi uses ٻ ݙ ڳ ڵ which Urdu does not."""
        assert detect_language("ایہہ فراڈ اے، کسے نوں نہ دسو ٻئی") == "pa"

    def test_gurmukhi_is_punjabi(self):
        assert detect_language("ਇਹ ਫਰਾਡ ਹੈ ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ") == "pa"

    def test_shahmukhi_via_function_words(self):
        """Shahmukhi and Urdu share nearly their whole alphabet, so many Punjabi
        sentences contain no distinctive letter. Function words break the tie."""
        assert detect_language("ایہہ فراڈ اے، کسے نوں نہ دسو") == "pa"

    def test_shahmukhi_possessive_markers(self):
        assert detect_language("ایہہ تواڈے اکاؤنٹ دا مسئلہ اے، وی تفصیل دے") == "pa"

    def test_plain_urdu_is_not_mistaken_for_punjabi(self):
        """The marker fallback must not over-trigger on ordinary Urdu."""
        for text in (
            "آپ کا اکاؤنٹ بند ہو جائے گا، فوری رابطہ کریں",
            "یہ پیغام فراڈ ہے، کسی کو مت بتائیں",
            "براہ کرم اپنا او ٹی پی درج کریں",
        ):
            assert detect_language(text) == "urdu", text

    def test_sindhi_letters_win_over_punjabi_markers(self):
        """Letter scoring takes precedence; markers only break true ties."""
        assert detect_language("ڪنهن کي به نه ٻڌايو، ايہہ ڳالھ خفيه آهي") == "sd"

    def test_devanagari_falls_back_to_roman_urdu(self):
        """Hindi is answered in Roman Urdu: the closest widely-readable fallback."""
        assert detect_language("यह धोखाधड़ी है") == "roman"

    def test_plain_arabic_script_without_regional_markers_is_urdu(self):
        """Urdu is the safe default for undifferentiated Arabic script."""
        assert detect_language("فراڈ دھوکہ") == "urdu"


class TestRomanScriptDetection:
    def test_roman_urdu(self):
        assert detect_language("Aap ka account block hone wala hai, foran OTP bhejein") == "roman"

    def test_roman_urdu_scam_message(self):
        text = (
            "Ye FIA Cyber Crime se officer bol raha hoon. Aap ka CNIC case mein involve hai. "
            "Ghar walon ko mat batana. Phone mat kaat, video call par rahein."
        )
        assert detect_language(text) == "roman"

    def test_pure_english(self):
        """OCR'd English scam SMS is common and must not be answered in Urdu."""
        assert detect_language(
            "Congratulations! Your device has been selected for a cash prize. Claim now."
        ) == "en"

    def test_english_bank_notification(self):
        assert detect_language("Your transaction of PKR 5000 was successful. Reference 884213.") == "en"

    def test_roman_sindhi(self):
        assert detect_language("Tawhanjo account band thiyo aahe, monikho code diyo") == "sd"

    def test_empty_input_defaults_to_roman_urdu(self):
        """Roman Urdu is what Pakistanis actually type on phones."""
        assert detect_language("") == "roman"
        assert detect_language("   ") == "roman"

    def test_all_returned_values_are_supported(self):
        for sample in ("یہ فراڈ ہے", "ye scam hai", "this is a scam", "", "ټځڅډ", "ਕਿਸੇ"):
            assert detect_language(sample) in SUPPORTED_REPLY_LANGS


class TestLanguageCommands:
    @pytest.mark.parametrize(
        "command,expected",
        [
            ("LANG UR", "urdu"),
            ("lang ur", "urdu"),
            ("LANG ROMAN", "roman"),
            ("LANGUAGE ENGLISH", "en"),
            ("lang: sindhi", "sd"),
            ("LANG - PASHTO", "ps"),
            ("lang punjabi", "pa"),
            ("LANG BALOCHI", "bal"),
            ("LANG اردو", "urdu"),
            ("  LANG EN  ", "en"),
        ],
    )
    def test_command_parsed(self, command, expected):
        assert parse_language_command(command) == expected
        assert detect_language(command) == expected

    def test_unknown_language_in_command_returns_none(self):
        assert parse_language_command("LANG KLINGON") is None

    @pytest.mark.parametrize(
        "not_a_command",
        ["ye scam hai kya", "language barrier is hard", "mujhe lang chahiye", ""],
    )
    def test_non_commands_not_parsed(self, not_a_command):
        assert parse_language_command(not_a_command) is None


class TestResolveLanguage:
    def test_stored_preference_beats_detection(self):
        """An explicit prior choice must win over any guess.

        This is what stops the bot re-guessing wrong on every message from a
        Sindhi speaker whose text happens to look like Urdu in Arabic script.
        """
        store = {"923001234567": "sd"}
        lang, explicit = resolve_language(
            "یہ فراڈ ہے", "923001234567", preference_lookup=store.get
        )
        assert lang == "sd"
        assert explicit is False

    def test_command_overrides_stored_preference(self):
        store = {"923001234567": "sd"}
        lang, explicit = resolve_language("LANG EN", "923001234567", preference_lookup=store.get)
        assert lang == "en"
        assert explicit is True

    def test_detection_used_when_no_preference(self):
        lang, explicit = resolve_language("ye scam hai kya", "923009999999", preference_lookup={}.get)
        assert lang == "roman"
        assert explicit is False

    def test_invalid_stored_value_falls_through_to_detection(self):
        """A corrupt stored value must not break replies."""
        store = {"923001234567": "not-a-language"}
        lang, _ = resolve_language("ye scam hai", "923001234567", preference_lookup=store.get)
        assert lang == "roman"

    def test_no_lookup_callable(self):
        lang, _ = resolve_language("یہ فراڈ ہے", "923001234567", preference_lookup=None)
        assert lang == "urdu"

    def test_unknown_sender_with_no_text_defaults_to_roman(self):
        lang, explicit = resolve_language("", "", preference_lookup={}.get)
        assert lang == "roman"
        assert explicit is False
