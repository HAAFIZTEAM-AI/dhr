"""Tests for federated threat intelligence (Layer 1 of docs/DETECTION.md).

The behaviour that matters most is the one a naive implementation gets wrong:
sources that fail to answer must be *excluded*, never averaged in as a vote for
safety. That single mistake is what makes a tool report a phishing site as clean.
"""

import time

import pytest

from haafiz.intel.domain_similarity import Brand, BrandImpersonationDetector
from haafiz.intel.federation import (
    BrandImpersonationSource,
    CallableSource,
    FederatedVerdict,
    Federation,
    FeedSource,
    LocalRegistrySource,
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    SourceVerdict,
    TtlCache,
    build_default_federation,
    classify,
    normalise_host,
    noisy_or,
    url_fingerprint,
)


@pytest.fixture(scope="module")
def detector() -> BrandImpersonationDetector:
    return BrandImpersonationDetector(
        [
            Brand("HBL", frozenset({"hbl.com", "hbl.com.pk"})),
            Brand("JazzCash", frozenset({"jazzcash.com.pk"})),
            Brand("Daraz", frozenset({"daraz.pk"})),
        ]
    )


def const(probability: float, applicable: bool = True, label: str = "x"):
    """A source that always returns the same verdict."""

    def _check(url: str) -> SourceVerdict:
        return SourceVerdict("stub", probability, label, applicable=applicable)

    return _check


def sleeping(seconds: float):
    def _check(url: str) -> SourceVerdict:
        time.sleep(seconds)
        return SourceVerdict("stub", 0.99, "malicious")

    return _check


# ---------------------------------------------------------------------------
# Combination maths
# ---------------------------------------------------------------------------

class TestNoisyOr:
    def test_single_source_passes_through(self):
        assert noisy_or([0.73]) == pytest.approx(0.73)

    def test_empty_is_zero(self):
        assert noisy_or([]) == 0.0

    def test_independent_sources_compound(self):
        # 1 - (0.1 * 0.8) = 0.92
        assert noisy_or([0.9, 0.2]) == pytest.approx(0.92)

    def test_certain_source_saturates(self):
        assert noisy_or([1.0, 0.0, 0.0]) == pytest.approx(1.0)

    def test_all_zero_is_zero(self):
        assert noisy_or([0.0, 0.0, 0.0]) == 0.0

    def test_clamps_out_of_range_input(self):
        assert noisy_or([1.5, -0.4]) == pytest.approx(1.0)

    def test_the_dilution_case_this_design_exists_to_prevent(self):
        """One 0.95 signal plus four silent zeros.

        A mean gives 0.19 -- "clean". The whole module exists so that this
        cannot happen.
        """
        mean = sum([0.95, 0.0, 0.0, 0.0, 0.0]) / 5
        assert mean == pytest.approx(0.19)
        assert classify(mean) == "clean"
        assert noisy_or([0.95, 0.0, 0.0, 0.0, 0.0]) == pytest.approx(0.95)
        assert classify(noisy_or([0.95])) == "malicious"


class TestClassify:
    @pytest.mark.parametrize(
        "probability,expected",
        [
            (0.0, "clean"), (0.34, "clean"),
            (SUSPICIOUS_THRESHOLD, "suspicious"), (0.5, "suspicious"),
            (0.699, "suspicious"),
            (MALICIOUS_THRESHOLD, "malicious"), (1.0, "malicious"),
        ],
    )
    def test_thresholds(self, probability, expected):
        assert classify(probability) == expected


# ---------------------------------------------------------------------------
# Offline sources
# ---------------------------------------------------------------------------

class TestLocalRegistrySource:
    def test_exact_url_hit(self):
        source = LocalRegistrySource(["scam-free-prize.xyz"])
        verdict = source.check("http://scam-free-prize.xyz/page")
        assert verdict.probability > 0.95
        assert verdict.label == "confirmed"
        assert verdict.applicable

    def test_domain_level_hit(self):
        """Any subdomain of a known-bad registrable domain is bad."""
        source = LocalRegistrySource(["scam-free-prize.xyz"])
        verdict = source.check("http://login.scam-free-prize.xyz/")
        assert verdict.probability > 0.9
        assert verdict.label == "confirmed_domain"

    def test_clean_lookup_still_speaks(self):
        """Not-listed is a real answer, not an unavailable source.

        This distinguishes the registry from a vendor that timed out: the
        registry *did* look and found nothing.
        """
        source = LocalRegistrySource(["known-bad.xyz"])
        verdict = source.check("https://example.com")
        assert verdict.applicable is True
        assert verdict.probability == 0.0
        assert verdict.label == "not_listed"

    def test_normalises_scheme_case_and_port(self):
        source = LocalRegistrySource(["Known-Bad.XYZ"])
        assert source.check("HTTPS://KNOWN-BAD.XYZ:8443/x").label == "confirmed"

    def test_empty_input_is_unavailable_not_clean(self):
        verdict = LocalRegistrySource().check("")
        assert verdict.applicable is False

    def test_ignores_blank_entries(self):
        source = LocalRegistrySource(["", "   ", "real-bad.xyz"])
        assert len(source) == 1


class TestBrandImpersonationSource:
    def test_flags_a_fresh_lookalike(self, detector):
        verdict = BrandImpersonationSource(detector).check("https://secure-hbl-login.com/x")
        assert verdict.probability >= 0.85
        assert verdict.label == "malicious"
        assert verdict.evidence

    def test_clean_on_the_verified_domain(self, detector):
        verdict = BrandImpersonationSource(detector).check("https://www.hbl.com.pk/")
        assert verdict.probability == 0.0
        assert verdict.label == "clean"

    def test_tld_signal_is_corroborated(self, detector):
        """``daraz-offer.win``: weak brand embedding + high-abuse TLD."""
        verdict = BrandImpersonationSource(detector).check("http://daraz-offer.win")
        assert verdict.probability > 0.35
        assert verdict.applicable

    def test_unparseable_host_is_unavailable(self, detector):
        assert BrandImpersonationSource(detector).check("").applicable is False


class TestFeedSource:
    def test_exact_and_domain_matches(self):
        feed = FeedSource("openphish", ["https://bad.example/phish", "worse.example/x"])
        assert feed.check("http://bad.example/phish").label == "listed"
        assert feed.check("http://sub.worse.example/y").label == "listed_domain"
        assert feed.check("http://clean.example/").label == "not_listed"

    def test_an_unloaded_feed_is_unavailable_not_clean(self):
        """The critical case: an empty feed must never read as safety.

        If the download failed and we returned probability 0.0 with
        ``applicable=True``, every URL would score clean.
        """
        verdict = FeedSource("openphish").check("http://anything.example/")
        assert verdict.applicable is False

    def test_comments_and_blanks_skipped(self):
        feed = FeedSource("f", ["# comment", "", "  ", "real.example/x"])
        assert len(feed) == 1

    def test_refresh_loads_from_callable(self):
        calls = []

        def loader():
            calls.append(1)
            return ["fresh.example/x"]

        feed = FeedSource("f", loader=loader, refresh_seconds=0.0)
        assert feed.refresh() == 1
        assert feed.check("http://fresh.example/x").label == "listed"

    def test_refresh_respects_ttl(self):
        calls = []

        def loader():
            calls.append(1)
            return ["a.example"]

        feed = FeedSource("f", loader=loader, refresh_seconds=60.0)
        feed.refresh()
        feed.refresh()
        assert len(calls) == 1

    def test_refresh_swallows_loader_errors(self):
        def loader():
            raise OSError("network down")

        feed = FeedSource("f", loader=loader)
        assert feed.refresh() == 0
        assert feed.check("http://a.example").applicable is False


# ---------------------------------------------------------------------------
# The federation
# ---------------------------------------------------------------------------

class TestFederationCombination:
    def test_no_sources_is_unknown_not_clean(self):
        verdict = Federation().check("https://example.com")
        assert verdict.label == "unknown"

    def test_empty_url_short_circuits(self):
        verdict = Federation([LocalRegistrySource()]).check("   ")
        assert verdict.probability == 0.0
        assert verdict.evidence

    def test_strongest_source_dominates(self):
        fed = Federation(
            [
                CallableSource("a", const(0.9), timeout_seconds=1),
                CallableSource("b", const(0.1), timeout_seconds=1),
            ]
        )
        assert fed.check("x.com").probability == pytest.approx(0.91)

    def test_all_clean_is_clean(self):
        fed = Federation(
            [
                CallableSource("a", const(0.0), timeout_seconds=1),
                CallableSource("b", const(0.0), timeout_seconds=1),
            ]
        )
        result = fed.check("x.com")
        assert result.probability == 0.0
        assert result.label == "clean"
        assert result.contributing == []

    def test_contributing_lists_only_positive_sources(self):
        fed = Federation(
            [
                CallableSource("a", const(0.9), timeout_seconds=1),
                CallableSource("b", const(0.0), timeout_seconds=1),
            ]
        )
        result = fed.check("x.com")
        assert result.contributing == ["a"]
        assert result.unavailable == []


class TestFederationResilience:
    """A failing source must weaken coverage, never flip the verdict."""

    def test_timeout_does_not_dilute_a_strong_signal(self, detector):
        fed = Federation(
            [
                BrandImpersonationSource(detector),
                CallableSource("vendor", sleeping(5), timeout_seconds=0.2),
            ]
        )
        result = fed.check("https://secure-hbl-login.com/")
        assert result.label == "malicious"
        assert result.unavailable == ["vendor"]
        assert result.contributing == ["brand_impersonation"]

    def test_raising_source_is_isolated(self):
        def boom(url):
            raise RuntimeError("vendor returned 500")

        fed = Federation(
            [
                CallableSource("exploding", boom, timeout_seconds=1),
                CallableSource("healthy", const(0.9), timeout_seconds=1),
            ]
        )
        result = fed.check("x.com")
        assert result.unavailable == ["exploding"]
        assert result.probability == pytest.approx(0.9)

    def test_wrong_return_type_is_isolated(self):
        fed = Federation(
            [CallableSource("broken", lambda url: {"not": "a verdict"}, timeout_seconds=1)]
        )
        result = fed.check("x.com")
        assert result.unavailable == ["broken"]
        assert result.probability == 0.0

    def test_source_names_are_stamped_not_trusted(self):
        """An adapter returning the wrong ``source`` must not break weighting."""
        fed = Federation(
            [CallableSource("registered_name", const(0.9), timeout_seconds=1, weight=0.5)]
        )
        result = fed.check("x.com")
        assert [v.source for v in result.sources] == ["registered_name"]
        assert result.contributing == ["registered_name"]
        # weight 0.5 applied: noisy_or(0.45)
        assert result.probability == pytest.approx(0.45)

    def test_probability_is_clamped(self):
        fed = Federation(
            [CallableSource("over", lambda u: SourceVerdict("over", 1.7, "x"), timeout_seconds=1)]
        )
        assert fed.check("x.com").probability == pytest.approx(1.0)

    def test_failure_reasons_reach_the_user(self):
        fed = Federation(
            [CallableSource("vendor", sleeping(5), timeout_seconds=0.1)]
        )
        evidence = fed.check("x.com").evidence
        assert any("vendor" in e for e in evidence)


class TestFederationLatency:
    """Latency is a product requirement, not an implementation detail: the
    whole point is to answer before the user finishes reading the SMS."""

    def test_sources_run_in_parallel(self):
        fed = Federation(
            [CallableSource(f"s{i}", sleeping(0.15), timeout_seconds=2) for i in range(4)]
        )
        started = time.monotonic()
        fed.check("x.com")
        elapsed = time.monotonic() - started
        assert elapsed < 0.5, f"sources ran serially: {elapsed:.2f}s"

    def test_one_generous_timeout_does_not_hold_open_the_others(self):
        """Regression: waiting on max(budgets) once made three 0.3 s vendors
        wait for a 1.0 s source."""
        fed = Federation(
            [
                CallableSource("generous", const(0.9), timeout_seconds=1.0),
                CallableSource("a", sleeping(5), timeout_seconds=0.2),
                CallableSource("b", sleeping(5), timeout_seconds=0.2),
                CallableSource("c", sleeping(5), timeout_seconds=0.2),
            ]
        )
        started = time.monotonic()
        result = fed.check("x.com")
        elapsed = time.monotonic() - started
        assert elapsed < 0.6, f"deadline was max(budgets), not per-source: {elapsed:.2f}s"
        assert len(result.unavailable) == 3

    def test_returns_early_when_everything_answers(self):
        fed = Federation(
            [CallableSource(f"s{i}", const(0.1), timeout_seconds=5) for i in range(3)]
        )
        started = time.monotonic()
        fed.check("x.com")
        assert time.monotonic() - started < 0.5

    def test_single_source_still_enforces_its_deadline(self):
        fed = Federation([CallableSource("only", sleeping(5), timeout_seconds=0.2)])
        started = time.monotonic()
        result = fed.check("x.com")
        assert time.monotonic() - started < 0.6
        assert result.unavailable == ["only"]


class TestFederationWeights:
    def test_down_weighted_source_contributes_less(self):
        trusted = Federation(
            [CallableSource("s", const(0.8), timeout_seconds=1, weight=1.0)]
        )
        noisy = Federation(
            [CallableSource("s", const(0.8), timeout_seconds=1, weight=0.25)]
        )
        assert trusted.check("x").probability > noisy.check("x").probability
        assert noisy.check("x").probability == pytest.approx(0.2)


# ---------------------------------------------------------------------------
# The default, zero-configuration federation
# ---------------------------------------------------------------------------

class TestDefaultFederation:
    def test_answers_the_virustotal_question_with_no_network(self, detector):
        """A domain registered twenty minutes ago, on no blocklist anywhere.

        This is precisely the URL that VirusTotal reports as ``0/94 clean``.
        """
        fed = build_default_federation(detector)
        result = fed.check("https://secure-hbl-login.com/verify-account")
        assert result.label == "malicious"
        assert result.probability >= 0.85
        assert result.contributing == ["brand_impersonation"]
        assert result.unavailable == []

    def test_registry_entry_is_decisive(self, detector):
        fed = build_default_federation(detector, registry_entries=["bad-actor.xyz"])
        assert fed.check("http://bad-actor.xyz/win").label == "malicious"

    def test_verified_domain_is_clean(self, detector):
        fed = build_default_federation(detector)
        result = fed.check("https://www.hbl.com.pk/personal-banking")
        assert result.label == "clean"
        assert result.probability == 0.0

    def test_extra_sources_are_appended(self, detector):
        extra = CallableSource("vendor", const(0.6), timeout_seconds=1)
        fed = build_default_federation(detector, extra_sources=[extra])
        assert "vendor" in {s.name for s in fed.sources}

    def test_evidence_is_deduplicated(self, detector):
        fed = build_default_federation(detector)
        result = fed.check("https://secure-hbl-login.com")
        assert len(result.evidence) == len(set(result.evidence))


# ---------------------------------------------------------------------------
# Serialisation, caching, fingerprints
# ---------------------------------------------------------------------------

class TestVerdictSerialisation:
    def test_round_trips_to_json(self, detector):
        import json

        payload = build_default_federation(detector).check("https://hbl.co").to_dict()
        encoded = json.dumps(payload)
        decoded = json.loads(encoded)
        assert decoded["label"] == payload["label"]
        assert decoded["sources"][0]["source"] == "haafiz_registry"
        assert isinstance(decoded["probability"], float)

    def test_unavailable_verdict_helper(self):
        verdict = SourceVerdict.unavailable("vendor", "timed out")
        assert verdict.applicable is False
        assert verdict.evidence == ("timed out",)
        assert verdict.probability == 0.0

    def test_unavailable_without_reason(self):
        assert SourceVerdict.unavailable("vendor").evidence == ()


class TestTtlCache:
    def test_set_and_get(self):
        cache = TtlCache(ttl_seconds=60)
        cache.set("k", "v")
        assert cache.get("k") == "v"

    def test_expiry(self):
        cache = TtlCache(ttl_seconds=0.01)
        cache.set("k", "v")
        time.sleep(0.02)
        assert cache.get("k") is None

    def test_miss_counting(self):
        cache = TtlCache()
        cache.get("absent")
        assert cache.misses == 1 and cache.hits == 0

    def test_hit_counting(self):
        cache = TtlCache()
        cache.set("k", "v")
        cache.get("k")
        assert cache.hits == 1

    def test_eviction_at_capacity(self):
        cache = TtlCache(ttl_seconds=60, max_entries=2)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        assert len(cache) == 2
        assert cache.get("a") is None  # oldest evicted

    def test_per_entry_ttl_override(self):
        cache = TtlCache(ttl_seconds=60)
        cache.set("k", "v", ttl=0.01)
        time.sleep(0.02)
        assert cache.get("k") is None

    def test_clear(self):
        cache = TtlCache()
        cache.set("a", 1)
        cache.clear()
        assert len(cache) == 0

    def test_callable_source_uses_cache(self):
        calls = []

        def counting(url):
            calls.append(url)
            return SourceVerdict("s", 0.5, "x")

        cache = TtlCache(ttl_seconds=60)
        source = CallableSource("s", counting, cache=cache, cache_ttl=60)
        source.check("u")
        source.check("u")
        assert len(calls) == 1

    def test_unavailable_results_are_not_cached(self):
        attempts = []

        def flaky(url):
            attempts.append(url)
            raise OSError("down")

        source = CallableSource("s", flaky, cache=TtlCache(ttl_seconds=60))
        source.check("u")
        source.check("u")
        assert len(attempts) == 2


class TestUrlFingerprint:
    def test_stable_and_normalised(self):
        assert url_fingerprint("HTTPS://X.COM/") == url_fingerprint("https://x.com")

    def test_distinct_urls_differ(self):
        assert url_fingerprint("https://a.com") != url_fingerprint("https://b.com")

    def test_length_is_bounded(self):
        assert len(url_fingerprint("x" * 5000)) == 16

    def test_does_not_leak_the_url(self):
        assert "hbl" not in url_fingerprint("https://secure-hbl-login.com")

    def test_empty_input(self):
        assert url_fingerprint("") == url_fingerprint(None)


class TestNormaliseHost:
    """One helper, used on both the write and the read side of every list.

    If the two sides disagree the registry silently stops matching.
    """

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("known-bad.xyz", "known-bad.xyz"),
            ("Known-Bad.XYZ", "known-bad.xyz"),
            ("  known-bad.xyz  ", "known-bad.xyz"),
            ("http://known-bad.xyz", "known-bad.xyz"),
            ("HTTPS://KNOWN-BAD.XYZ/x/y?z=1#f", "known-bad.xyz"),
            ("known-bad.xyz:8443", "known-bad.xyz"),
            ("https://known-bad.xyz:443/", "known-bad.xyz"),
            ("known-bad.xyz.", "known-bad.xyz"),
            ("hbl.com@known-bad.xyz", "known-bad.xyz"),   # userinfo decoy
            ("https://user:pass@known-bad.xyz", "known-bad.xyz"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("", ""),
            ("   ", ""),
            (None, ""),
        ],
    )
    def test_normalisation(self, value, expected):
        assert normalise_host(value) == expected

    def test_write_and_read_sides_agree(self):
        """Regression: add() stripped the port but check() did not."""
        source = LocalRegistrySource(["Known-Bad.XYZ"])
        assert source.check("HTTPS://KNOWN-BAD.XYZ:8443/x").label == "confirmed"

    def test_feed_write_and_read_sides_agree(self):
        """Regression: the feed stored the raw entry with its port and path,
        so a lookup on the bare host never matched."""
        feed = FeedSource("f", ["https://Bad.Example:8080/phish?x=1"])
        assert feed.check("BAD.EXAMPLE:443").label == "listed"
        assert feed.check("https://sub.bad.example/other").label == "listed_domain"
