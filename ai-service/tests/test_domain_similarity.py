"""Tests for brand-impersonation detection (Layer 2 of docs/DETECTION.md).

These are the domains a blocklist cannot help with. Every "phishing" case below
is a freshly-registrable name with no reputation anywhere -- exactly the class
of URL that VirusTotal reports as ``0/94 clean``.
"""

import pytest

from haafiz.intel.domain_similarity import (
    Brand,
    BrandImpersonationDetector,
    HIGH_ABUSE_TLDS,
    damerau_levenshtein,
    decode_idn,
    fold_to_ascii,
    is_punycode,
    load_brands_from_file,
    split_registrable_domain,
    tld_risk,
)

# A registry shaped like the real Pakistani target set: banks, wallets, telcos,
# government, marketplaces. Deliberately includes the pairs that collide
# (Jazz the telco vs JazzCash the wallet) to keep the validator honest.
BRANDS = [
    Brand("HBL", frozenset({"hbl.com", "hbl.com.pk"})),
    Brand("UBL", frozenset({"ubl.com", "ubl.com.pk"})),
    Brand("Meezan Bank", frozenset({"meezanbank.com"}), frozenset({"meezan"})),
    Brand("Jazz", frozenset({"jazz.com.pk"})),
    Brand("JazzCash", frozenset({"jazzcash.com.pk"}), frozenset({"jazzcash"})),
    Brand("Easypaisa", frozenset({"easypaisa.com.pk"})),
    Brand("NADRA", frozenset({"nadra.gov.pk"})),
    Brand("Daraz", frozenset({"daraz.pk"})),
    Brand("Apple", frozenset({"apple.com"})),
    Brand("Amazon", frozenset({"amazon.com"})),
]


@pytest.fixture(scope="module")
def detector() -> BrandImpersonationDetector:
    return BrandImpersonationDetector(BRANDS)


# ---------------------------------------------------------------------------
# Public suffix parsing
# ---------------------------------------------------------------------------

class TestSplitRegistrableDomain:
    """Getting this wrong silently corrupts every other check."""

    @pytest.mark.parametrize(
        "hostname,expected",
        [
            # The trap: a two-label suffix must consume two labels.
            ("hbl.com.pk", ("", "hbl.com.pk")),
            ("hblpayment.com.pk", ("", "hblpayment.com.pk")),
            ("login.hbl.com.pk", ("login", "hbl.com.pk")),
            ("a.b.hbl.com.pk", ("a.b", "hbl.com.pk")),
            # mobi.pk is a real PKNIC second-level domain.
            ("meezanbank.mobi.pk", ("", "meezanbank.mobi.pk")),
            ("x.meezanbank.mobi.pk", ("x", "meezanbank.mobi.pk")),
            # Single-label suffixes.
            ("hblstocks.com", ("", "hblstocks.com")),
            ("a.b.hblstocks.com", ("a.b", "hblstocks.com")),
            ("hbl.co.uk", ("", "hbl.co.uk")),
            ("sub.hbl.co.uk", ("sub", "hbl.co.uk")),
            # Degenerate input must not raise.
            ("pk", ("", "pk")),
            ("", ("", "")),
            ("....", ("", "")),
            ("localhost", ("", "localhost")),
        ],
    )
    def test_split(self, hostname, expected):
        assert split_registrable_domain(hostname) == expected

    def test_strips_trailing_dot_and_uppercase(self):
        assert split_registrable_domain("HBL.COM.PK.") == ("", "hbl.com.pk")


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

class TestFolding:
    def test_cyrillic_homoglyph(self):
        # The 'a' here is U+0430 CYRILLIC SMALL LETTER A, not ASCII.
        assert fold_to_ascii("\u0430pple") == "apple"

    def test_fullwidth_ascii(self):
        assert fold_to_ascii("\uff47\uff4f\uff4f\uff47\uff4c\uff45") == "google"

    def test_zero_width_characters_are_stripped(self):
        assert fold_to_ascii("hbl\u200b.com") == "hbl.com"
        assert fold_to_ascii("hbl\ufeff.com") == "hbl.com"

    def test_isolated_leet_digit_folds(self):
        assert fold_to_ascii("hblc0m.pk") == "hblcom.pk"
        assert fold_to_ascii("paypa1") == "paypal"
        assert fold_to_ascii("hb1.com.pk") == "hbl.com.pk"

    def test_digit_runs_are_preserved(self):
        """A numeric suffix distinguishes; it is not a character substitution."""
        assert fold_to_ascii("jazzcash88.com") == "jazzcash88.com"

    def test_purely_numeric_label_untouched(self):
        assert fold_to_ascii("786") == "786"

    def test_no_destructive_multichar_substitution(self):
        """Regression: an ``lc``->``d`` rule once turned ``hblc0m`` into
        ``hbdom``, erasing the brand and letting the domain through as clean."""
        assert fold_to_ascii("hblc0m") == "hblcom"
        assert fold_to_ascii("arnazon") == "arnazon"  # edit distance handles it

    def test_case_insensitive(self):
        assert fold_to_ascii("HBL") == "hbl"


class TestPunycode:
    def test_detection(self):
        assert is_punycode("xn--80ak6aa92e")
        assert not is_punycode("apple")

    def test_decode_roundtrip(self):
        # The canonical homoglyph example: every letter of "apple" is Cyrillic.
        assert decode_idn("xn--80ak6aa92e.com") == "\u0430\u0440\u0440\u04cf\u0435.com"

    def test_decoded_homoglyph_folds_to_the_brand(self):
        """The whole pipeline: punycode -> Unicode -> ASCII fold -> brand."""
        decoded = decode_idn("xn--80ak6aa92e.com")
        assert fold_to_ascii(decoded.split(".")[0]) == "apple"

    def test_detector_catches_the_homoglyph_domain(self):
        detector = BrandImpersonationDetector(BRANDS)
        result = detector.assess("xn--80ak6aa92e.com")
        assert result.suspicious
        assert result.impersonated_brand == "Apple"

    def test_decode_failure_is_not_fatal(self):
        assert decode_idn("xn--not-valid-.com") == "xn--not-valid-.com"


class TestDamerauLevenshtein:
    @pytest.mark.parametrize(
        "a,b,expected",
        [
            ("hbl", "hbl", 0),
            ("hbl", "hbi", 1),           # substitution
            ("hbl", "hb", 1),            # deletion
            ("hbl", "hblo", 1),          # insertion
            ("jazzcahs", "jazzcash", 1), # transposition -- Damerau, not plain
            ("paypai", "paypal", 1),
            ("", "abc", 3),
            ("abc", "", 3),
        ],
    )
    def test_distance(self, a, b, expected):
        assert damerau_levenshtein(a, b) == expected

    def test_symmetric(self):
        assert damerau_levenshtein("amazon", "arnazon") == damerau_levenshtein(
            "arnazon", "amazon"
        )

    def test_absurdly_long_input_is_capped_not_crashing(self):
        long = "a" * 5000
        assert damerau_levenshtein(long, "b" * 5000) == 5000


# ---------------------------------------------------------------------------
# Phishing detection -- the whole point of the module
# ---------------------------------------------------------------------------

PHISHING = [
    # 1. Separator substitution: the brand's own domain with punctuation changed.
    ("hbl-com.pk", "separator_substitution"),
    ("hb1.com.pk", "separator_substitution"),
    # 2. Homoglyph / IDN.
    ("xn--80ak6aa92e.com", "homoglyph_idn"),
    # 3. Keyword stuffing -- credential capture and urgency vocabulary.
    ("secure-hbl-login.com", "keyword_stuffing"),
    ("verify-hbl-account.xyz", "keyword_stuffing"),
    ("hbl-secure.online", "keyword_stuffing"),
    ("jazzcash-update.top", "keyword_stuffing"),
    ("meezanbank-secure.com", "keyword_stuffing"),
    ("nadra-kyc.xyz", "keyword_stuffing"),
    ("daraz-prize.win", "keyword_stuffing"),
    ("meezan-login.com", "keyword_stuffing"),
    ("hbl_confirm.xyz", "keyword_stuffing"),
    ("verifyhblaccount.com", "keyword_stuffing"),  # separator-free
    ("securehbl.online", "keyword_stuffing"),      # separator-free + infix
    # 4. Subdomain abuse.
    ("hbl-login.attacker.com", "keyword_stuffing"),
    ("jazzcash.attacker.net", "subdomain_abuse"),
    ("hbl.com.pk.evil.tld", "subdomain_abuse"),
    ("nadra.gov.pk.online-forms.com", "keyword_stuffing"),
    # 5. TLD variation / concatenation.
    ("hbl.co", "tld_variation"),
    ("easypaisa.co", "tld_variation"),
    ("jazzcash.mobi", "tld_variation"),
    ("hblc0m.pk", "tld_concatenation"),
    # 6. Typosquatting.
    ("ubI.com.pk", "typosquatting"),
    ("arnazon.com", "typosquatting"),
    # 7. Structural deception, no brand needed.
    ("hbl@evil.tld", "userinfo_decoy"),
    ("192.168.1.1", "ip_literal"),
]


class TestPhishingDetected:
    @pytest.mark.parametrize("hostname,technique", PHISHING)
    def test_flagged(self, detector, hostname, technique):
        result = detector.assess(hostname)
        assert result.suspicious, f"{hostname} should be suspicious (risk={result.risk})"
        assert result.risk >= 0.5
        assert technique in result.techniques

    @pytest.mark.parametrize("hostname,technique", PHISHING)
    def test_has_user_facing_evidence(self, detector, hostname, technique):
        """Every verdict must be explainable -- see docs/DETECTION.md on XAI."""
        result = detector.assess(hostname)
        assert result.evidence, f"{hostname} produced no explanation"
        assert all(isinstance(e, str) and e for e in result.evidence)

    def test_no_duplicate_evidence(self, detector):
        """Users saw doubled reasons during the live demo of the WhatsApp
        verdict renderer; the same class of bug must not recur here."""
        result = detector.assess("secure-hbl-login.com")
        assert len(result.evidence) == len(set(result.evidence))

    def test_names_the_impersonated_brand(self, detector):
        result = detector.assess("secure-hbl-login.com")
        assert result.impersonated_brand == "HBL"

    def test_short_url_forms_are_expanded_before_assessment(self, detector):
        """A caller that passes a full URL must still get the right answer."""
        for form in (
            "https://secure-hbl-login.com/path?q=1#frag",
            "HTTP://SECURE-HBL-LOGIN.COM",
            "secure-hbl-login.com:8443/login",
        ):
            assert detector.assess(form).suspicious, form

    def test_brand_plus_digits_on_high_abuse_tld_is_caught(self, detector):
        # brand_embedded (0.35) corroborated by the TLD signal, via noisy-OR.
        assert detector.assess("daraz-offer.win").suspicious
        assert detector.assess("hbl-payments.top").suspicious


# ---------------------------------------------------------------------------
# Legitimate domains -- false positives destroy trust faster than misses
# ---------------------------------------------------------------------------

LEGITIMATE = [
    "hbl.com", "hbl.com.pk", "www.hbl.com.pk", "internetbanking.hbl.com.pk",
    "careers.hbl.com.pk", "ubl.com.pk", "meezanbank.com", "jazz.com.pk",
    "jazzcash.com.pk", "easypaisa.com.pk", "nadra.gov.pk", "daraz.pk",
    "apple.com", "amazon.com",
    # Real subsidiary / product domains that merely contain a brand name.
    "hblstocks.com", "hblstocktrading.com", "meezaninvestments.com",
    "darazfoundation.pk", "hbl-careers.info",
    # Unrelated domains that share no brand term at all.
    "google.com", "facebook.com", "gmail.com", "github.com",
    "stackoverflow.com", "example.xyz", "habibbank.com",
]


class TestLegitimateNotFlagged:
    @pytest.mark.parametrize("hostname", LEGITIMATE)
    def test_clean(self, detector, hostname):
        result = detector.assess(hostname)
        assert not result.suspicious, (
            f"{hostname} false-positive: risk={result.risk} "
            f"brand={result.impersonated_brand} techniques={result.techniques}"
        )

    def test_verified_domain_reports_its_owner(self, detector):
        result = detector.assess("hbl.com.pk")
        assert result.risk == 0.0
        assert any("verified official domain" in e for e in result.evidence)

    def test_business_words_do_not_trigger_keyword_stuffing(self, detector):
        """``care`` inside ``careers`` is not an impersonation keyword.

        Regression guard: substring matching once flagged hbl-careers.info.
        """
        result = detector.assess("hbl-careers.info")
        assert "keyword_stuffing" not in result.techniques


# ---------------------------------------------------------------------------
# Ambiguous-but-correct: the verified registry is the escape hatch
# ---------------------------------------------------------------------------

class TestAmbiguousVariants:
    """A brand's exact name on a TLD it does not own is flagged at 0.88.

    That is intentional. ``daraz.com.pk`` is either Daraz's own defensive
    registration or a phisher's -- nothing in the name can tell you which, so
    the answer is "verify it", and the verified registry is how an operator
    resolves it permanently.
    """

    @pytest.mark.parametrize(
        "hostname", ["daraz.com.pk", "easypaisa.com", "meezanbank.mobi.pk"]
    )
    def test_flagged_until_verified(self, detector, hostname):
        assert detector.assess(hostname).suspicious

    def test_adding_to_registry_clears_it(self, detector):
        before = detector.assess("daraz.com.pk")
        assert before.suspicious

        extended = BrandImpersonationDetector(BRANDS)
        extended.add_brand(Brand("Daraz", frozenset({"daraz.pk", "daraz.com.pk"})))
        after = extended.assess("daraz.com.pk")
        assert not after.suspicious
        assert after.risk == 0.0


# ---------------------------------------------------------------------------
# Registry hygiene
# ---------------------------------------------------------------------------

class TestRegistryValidation:
    def test_clean_registry_has_no_problems(self):
        detector = BrandImpersonationDetector(BRANDS)
        assert detector.validate_registry() == []

    def test_alias_colliding_with_another_brand_is_reported(self):
        detector = BrandImpersonationDetector(
            [
                Brand("Jazz", frozenset({"jazz.com.pk"})),
                Brand("JazzCash", frozenset({"jazzcash.com.pk"}),
                      frozenset({"jazz"})),
            ]
        )
        problems = detector.validate_registry()
        assert len(problems) == 1
        assert "Jazz" in problems[0] and "JazzCash" in problems[0]

    def test_malformed_domain_is_reported(self):
        detector = BrandImpersonationDetector(
            [Brand("HBL", frozenset({"hbl.com.pk", "notadomain"}))]
        )
        problems = detector.validate_registry()
        assert any("notadomain" in p for p in problems)


# ---------------------------------------------------------------------------
# TLD signal
# ---------------------------------------------------------------------------

class TestTldRisk:
    @pytest.mark.parametrize("tld", sorted(HIGH_ABUSE_TLDS)[:12])
    def test_high_abuse_tld_contributes(self, tld):
        score, evidence = tld_risk(f"something.{tld}")
        assert score == pytest.approx(0.25)
        assert evidence

    def test_neutral_tld_contributes_nothing(self):
        assert tld_risk("bank.com.pk") == (0.0, None)

    def test_handles_full_url_and_empty_input(self):
        assert tld_risk("https://x.xyz/path")[0] == pytest.approx(0.25)
        assert tld_risk("") == (0.0, None)


# ---------------------------------------------------------------------------
# Registry file loading
# ---------------------------------------------------------------------------

class TestLoadBrandsFromFile:
    def test_bare_domains_group_by_label(self, tmp_path):
        path = tmp_path / "verified_domains.txt"
        path.write_text(
            "# comment line\n"
            "\n"
            "hbl.com\n"
            "hbl.com.pk      # trailing comment\n"
            "daraz.pk\n",
            encoding="utf-8",
        )
        brands = load_brands_from_file(str(path))
        by_name = {b.name: b for b in brands}
        assert by_name["HBL"].official_domains == frozenset({"hbl.com", "hbl.com.pk"})
        assert by_name["DARAZ"].official_domains == frozenset({"daraz.pk"})

    def test_pipe_syntax_sets_explicit_brand_name(self, tmp_path):
        path = tmp_path / "verified_domains.txt"
        path.write_text("Meezan Bank | meezanbank.com meezaninvestments.com\n")
        brands = load_brands_from_file(str(path))
        assert len(brands) == 1
        assert brands[0].name == "Meezan Bank"
        assert "meezaninvestments.com" in brands[0].official_domains

    def test_explicit_entry_wins_over_grouping(self, tmp_path):
        path = tmp_path / "verified_domains.txt"
        path.write_text("Meezan Bank | meezanbank.com\nmeezangroup.com\n")
        brands = load_brands_from_file(str(path))
        names = {b.name for b in brands}
        assert "Meezan Bank" in names
        # meezangroup.com is not swallowed into the explicit entry.
        assert "MEEZANGROUP" in names

    def test_missing_file_returns_empty_list(self):
        assert load_brands_from_file("/nonexistent/path/verified_domains.txt") == []

    def test_from_pairs_constructor(self):
        detector = BrandImpersonationDetector.from_pairs(
            [("HBL", ["hbl.com", "HBL.COM.PK"])]
        )
        assert not detector.assess("hbl.com.pk").suspicious
        assert detector.assess("secure-hbl-login.com").suspicious


# ---------------------------------------------------------------------------
# Robustness -- an attacker controls this input
# ---------------------------------------------------------------------------

class TestHostileInput:
    @pytest.mark.parametrize(
        "hostname",
        [
            "", "   ", None, ".", "..", "...", "a" * 5000, "." * 500,
            "\x00\x01", "hbl.com\x00.evil.tld", "٭٭٭", "hbl..com.pk",
            "-.com", "xn--", "xn--a", "[::1]", "::1", "1.2.3",
            "https://", "@", "hbl.com@", "%2e%2e", "hbl.com/p?q=@x",
        ],
    )
    def test_never_raises(self, detector, hostname):
        result = detector.assess(hostname)
        assert 0.0 <= result.risk <= 1.0

    def test_ipv6_literal_is_flagged(self, detector):
        result = detector.assess("[2001:db8::1]")
        assert result.suspicious
        assert "ip_literal" in result.techniques

    def test_ipv4_literal_is_flagged(self, detector):
        assert detector.assess("8.8.8.8").suspicious

    def test_assessment_is_serialisable(self, detector):
        payload = detector.assess("secure-hbl-login.com").as_dict()
        assert payload["suspicious"] is True
        assert payload["impersonated_brand"] == "HBL"
        assert isinstance(payload["risk"], float)
        import json
        json.dumps(payload)

    def test_empty_registry_flags_nothing(self):
        detector = BrandImpersonationDetector()
        assert not detector.assess("secure-hbl-login.com").suspicious


class TestPortHandling:
    """A port left on the hostname breaks suffix parsing entirely."""

    @pytest.mark.parametrize(
        "hostname",
        [
            "hbl.com:8443",
            "https://hbl.com:443/x",
            "secure-hbl-login.com:8080",
            "hbl.com.pk:80",
        ],
    )
    def test_port_is_stripped(self, detector, hostname):
        assert ":" not in detector.assess(hostname).registrable_domain

    def test_verified_domain_with_port_still_verifies(self, detector):
        result = detector.assess("hbl.com.pk:8443")
        assert not result.suspicious
        assert result.risk == 0.0

    def test_ipv6_literal_with_port_is_not_mangled(self, detector):
        result = detector.assess("[2001:db8::1]:443")
        assert result.suspicious
        assert "ip_literal" in result.techniques
