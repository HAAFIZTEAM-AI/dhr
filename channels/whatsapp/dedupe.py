"""Webhook idempotency.

Meta retries a webhook if it does not receive a fast HTTP 200. Retries are common
under load, and without de-duplication a user who forwards one message can receive
three identical verdicts -- which reads as a broken product to exactly the
audience least able to diagnose why.

Worse, each duplicate re-runs the analyzer. A voice note means re-running Whisper
transcription, which is the most expensive operation in the whole system.

We key on the WhatsApp message ID (``wamid``), which Meta guarantees is unique per
message and stable across retries.

The default backend is in-process. That is correct for a single container and for
local development, and is deliberately not a distributed lock -- running more than
one replica requires the Redis backend (see ``redis_dedupe``), otherwise each
replica keeps its own memory and duplicates get through.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

__all__ = ["DedupeResult", "InMemoryDedupe", "MessageDedupe"]

#: How long a message ID is remembered. Meta's retry window is short (seconds to
#: a couple of minutes), but a user may also genuinely forward the same message
#: twice an hour apart and want a fresh answer -- so this is intentionally not
#: "forever". 10 minutes covers every realistic retry without blocking a
#: deliberate re-check.
DEFAULT_TTL_SECONDS = 600

#: Bound on the number of tracked IDs. Unbounded growth on a public endpoint is a
#: memory-exhaustion DoS. When the cap is reached the oldest entries are evicted.
DEFAULT_MAX_ENTRIES = 50_000


@dataclass(frozen=True)
class DedupeResult:
    """Outcome of a de-duplication check.

    Attributes:
        is_duplicate: True when this message ID has already been seen recently.
        message_id: the key that was checked.
    """

    is_duplicate: bool
    message_id: str


class MessageDedupe:
    """Interface for message de-duplication backends."""

    def check_and_record(self, message_id: str) -> DedupeResult:  # pragma: no cover
        raise NotImplementedError


class InMemoryDedupe(MessageDedupe):
    """Thread-safe, TTL-bounded, in-process de-duplication.

    Uses an ``OrderedDict`` as an LRU so eviction is O(1): insertion order is
    already recency order, so the oldest key is always at the front.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._ttl = ttl_seconds
        self._max = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_record(self, message_id: str) -> DedupeResult:
        """Record ``message_id`` and report whether it was already present.

        Args:
            message_id: the WhatsApp ``wamid``. Empty or missing IDs are treated
                as *not* duplicates -- refusing to process a message because its
                ID was absent would deny service to a real user, and the ID is
                Meta's responsibility, not the user's.

        Returns:
            A :class:`DedupeResult`.
        """
        if not message_id:
            return DedupeResult(is_duplicate=False, message_id="")

        now = time.monotonic()
        with self._lock:
            self._evict_expired(now)

            if message_id in self._seen:
                # Refresh recency so a still-retrying message keeps its slot.
                self._seen.move_to_end(message_id)
                self._seen[message_id] = now
                return DedupeResult(is_duplicate=True, message_id=message_id)

            self._seen[message_id] = now
            while len(self._seen) > self._max:
                self._seen.popitem(last=False)
            return DedupeResult(is_duplicate=False, message_id=message_id)

    def _evict_expired(self, now: float) -> None:
        """Drop entries older than the TTL.

        Iterating from the front stops at the first live entry, because insertion
        order equals recency order -- so this is O(expired), not O(n).
        """
        cutoff = now - self._ttl
        for key, seen_at in list(self._seen.items()):
            if seen_at > cutoff:
                break
            del self._seen[key]

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired(time.monotonic())
            return len(self._seen)
