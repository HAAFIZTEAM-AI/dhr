"""Tests for webhook idempotency.

Meta retries any webhook that is not acknowledged quickly. Without dedup a user
who forwards one message receives three identical verdicts -- and, worse, a voice
note gets transcribed three times, which is the most expensive operation in the
system and an easy amplification DoS.
"""

from __future__ import annotations

import time

import pytest

from whatsapp.dedupe import DEFAULT_MAX_ENTRIES, DEFAULT_TTL_SECONDS, DedupeResult, InMemoryDedupe


class TestFirstAndRepeat:
    def test_first_sighting_is_not_a_duplicate(self):
        d = InMemoryDedupe()
        result = d.check_and_record("wamid.1")
        assert result.is_duplicate is False
        assert result.message_id == "wamid.1"

    def test_second_sighting_is_a_duplicate(self):
        d = InMemoryDedupe()
        d.check_and_record("wamid.1")
        assert d.check_and_record("wamid.1").is_duplicate is True

    def test_third_sighting_still_duplicate(self):
        d = InMemoryDedupe()
        for _ in range(2):
            d.check_and_record("wamid.1")
        assert d.check_and_record("wamid.1").is_duplicate is True

    def test_distinct_ids_are_independent(self):
        d = InMemoryDedupe()
        assert d.check_and_record("wamid.1").is_duplicate is False
        assert d.check_and_record("wamid.2").is_duplicate is False
        assert d.check_and_record("wamid.1").is_duplicate is True
        assert d.check_and_record("wamid.2").is_duplicate is True


class TestEmptyIds:
    def test_missing_id_is_never_treated_as_duplicate(self):
        """Refusing to process a message because Meta omitted its ID would deny
        service to a real user. The ID is Meta's responsibility, not theirs."""
        d = InMemoryDedupe()
        assert d.check_and_record("").is_duplicate is False
        assert d.check_and_record("").is_duplicate is False

    def test_empty_id_is_not_stored(self):
        d = InMemoryDedupe()
        d.check_and_record("")
        assert len(d) == 0


class TestTtlExpiry:
    def test_expired_entry_is_not_a_duplicate(self):
        """A user forwarding the same scam an hour later deserves a fresh answer."""
        d = InMemoryDedupe(ttl_seconds=1)
        d.check_and_record("wamid.1")
        assert d.check_and_record("wamid.1").is_duplicate is True
        time.sleep(1.05)
        assert d.check_and_record("wamid.1").is_duplicate is False

    def test_len_excludes_expired(self):
        d = InMemoryDedupe(ttl_seconds=1)
        d.check_and_record("wamid.1")
        assert len(d) == 1
        time.sleep(1.05)
        assert len(d) == 0

    def test_retry_within_ttl_is_still_blocked(self):
        d = InMemoryDedupe(ttl_seconds=60)
        d.check_and_record("wamid.1")
        time.sleep(0.01)
        assert d.check_and_record("wamid.1").is_duplicate is True

    def test_default_ttl_covers_meta_retry_window(self):
        assert DEFAULT_TTL_SECONDS >= 600

    def test_rejected_non_positive_ttl(self):
        with pytest.raises(ValueError):
            InMemoryDedupe(ttl_seconds=0)
        with pytest.raises(ValueError):
            InMemoryDedupe(ttl_seconds=-1)


class TestMemoryBounds:
    def test_evicts_oldest_when_full(self):
        """An unbounded dict on a public endpoint is a memory-exhaustion DoS."""
        d = InMemoryDedupe(max_entries=3)
        for i in range(5):
            d.check_and_record(f"wamid.{i}")
        assert len(d) == 3
        # The oldest entries were evicted, so they look new again.
        assert d.check_and_record("wamid.0").is_duplicate is False
        assert d.check_and_record("wamid.4").is_duplicate is True

    def test_eviction_preserves_recent_entries(self):
        d = InMemoryDedupe(max_entries=2)
        d.check_and_record("a")
        d.check_and_record("b")
        d.check_and_record("c")  # evicts "a"
        assert d.check_and_record("b").is_duplicate is True
        assert d.check_and_record("c").is_duplicate is True

    def test_default_max_entries_is_bounded(self):
        assert DEFAULT_MAX_ENTRIES == 50_000

    def test_rejected_non_positive_max_entries(self):
        with pytest.raises(ValueError):
            InMemoryDedupe(max_entries=0)

    def test_scales_to_many_entries(self):
        d = InMemoryDedupe(max_entries=DEFAULT_MAX_ENTRIES)
        for i in range(2000):
            d.check_and_record(f"wamid.{i}")
        assert len(d) == 2000
        assert d.check_and_record("wamid.0").is_duplicate is True


class TestThreadSafety:
    def test_concurrent_records_produce_exactly_one_first_sighting(self):
        """Under retries from multiple workers, only ONE may be treated as new."""
        import threading

        d = InMemoryDedupe()
        results: list[bool] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            r = d.check_and_record("wamid.same")
            with lock:
                results.append(r.is_duplicate)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(False) == 1, "exactly one worker may process the message"
        assert results.count(True) == 7


class TestResultShape:
    def test_result_is_frozen(self):
        r = DedupeResult(is_duplicate=True, message_id="x")
        with pytest.raises(Exception):
            r.is_duplicate = False  # type: ignore[misc]
