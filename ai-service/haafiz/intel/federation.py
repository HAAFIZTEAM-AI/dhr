"""Federated threat intelligence -- Layer 1 of docs/DETECTION.md.

The problem this solves is the one a user hits by hand: they paste a suspicious
URL into VirusTotal, it reports ``0/94``, and they conclude the site is safe.
It is not. ``0/94`` means *nobody has reported it yet*, and a domain registered
twenty minutes ago has not been reported by anyone.

Two design rules follow, and the whole module is built around them:

1. **No single source may decide.** Google Safe Browsing misses URLs younger
   than ~30 minutes, URLhaus covers malware but not phishing, PhishTank waits on
   community validation, VirusTotal waits on its vendors. Combining four sources
   cuts false negatives by 15-30% versus any one of them.

2. **A source that fails must not dilute the verdict.** If PhishTank times out,
   that is *absence of evidence*, not evidence of safety. Such a source returns
   ``applicable=False`` and is excluded from the combination entirely -- the same
   fix the scoring engine applies to silent analyzer modules. Getting this wrong
   is what turns one strong signal into an average that reads "SAFE".

The core combination is pure and offline. Network sources are adapters behind
the same interface, so detection works with zero connectivity -- it just gets
weaker, never silently wrong.
"""

from __future__ import annotations

import hashlib
import threading
import time
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence
from urllib.parse import urlsplit

from haafiz.intel.domain_similarity import (
    BrandImpersonationDetector,
    split_registrable_domain,
    tld_risk,
)


# ---------------------------------------------------------------------------
# Verdict types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceVerdict:
    """One source's opinion about one URL.

    ``probability`` is P(malicious | this source spoke). ``applicable=False``
    means the source did not speak at all -- it timed out, errored, or has no
    coverage for this input -- and must be dropped from the combination rather
    than counted as a vote for safety.
    """

    source: str
    probability: float = 0.0
    label: str = "unknown"
    evidence: tuple[str, ...] = ()
    applicable: bool = True
    latency_ms: int = 0

    @classmethod
    def unavailable(cls, source: str, reason: str = "") -> "SourceVerdict":
        """The source could not answer. Excluded from scoring."""
        return cls(
            source=source,
            probability=0.0,
            label="unavailable",
            evidence=(reason,) if reason else (),
            applicable=False,
        )

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "probability": round(self.probability, 4),
            "label": self.label,
            "evidence": list(self.evidence),
            "applicable": self.applicable,
            "latency_ms": self.latency_ms,
        }


@dataclass
class FederatedVerdict:
    """Combined result across every source that actually spoke."""

    url: str
    probability: float
    label: str
    sources: list[SourceVerdict] = field(default_factory=list)
    contributing: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    latency_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "probability": round(self.probability, 4),
            "label": self.label,
            "sources": [s.as_dict() for s in self.sources],
            "contributing": list(self.contributing),
            "unavailable": list(self.unavailable),
            "evidence": list(self.evidence),
            "latency_ms": self.latency_ms,
        }


#: Above this the verdict is "malicious"; above half of it, "suspicious".
MALICIOUS_THRESHOLD = 0.70
SUSPICIOUS_THRESHOLD = 0.35


def classify(probability: float) -> str:
    if probability >= MALICIOUS_THRESHOLD:
        return "malicious"
    if probability >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def noisy_or(probabilities: Iterable[float]) -> float:
    """``1 - Π(1 - pᵢ)`` -- the probability that *at least one* is right.

    A plain mean is wrong here and demonstrably so: one source at 0.95 plus
    four silent sources at 0.0 averages to 0.19, which reads as clean. The
    product form gives 0.95. Independent sources that disagree by *not
    knowing* must not cancel a source that does know.
    """
    complement = 1.0
    for value in probabilities:
        complement *= 1.0 - min(max(value, 0.0), 1.0)
    return 1.0 - complement


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

class TtlCache:
    """Thread-safe TTL cache.

    Threat feeds change on the order of minutes; per-URL lookups are hammered by
    retries. Caching is what makes a free-tier API quota survivable.
    """

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 10_000) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._store: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> object | None:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.misses += 1
                return None
            expires_at, value = entry
            if expires_at <= now:
                del self._store[key]
                self.misses += 1
                return None
            self.hits += 1
            return value

    def set(self, key: str, value: object, ttl: float | None = None) -> None:
        with self._lock:
            if len(self._store) >= self.max_entries:
                self._evict_oldest_locked()
            self._store[key] = (time.monotonic() + (self.ttl if ttl is None else ttl), value)

    def _evict_oldest_locked(self) -> None:
        if not self._store:
            return
        oldest = min(self._store.items(), key=lambda kv: kv[1][0])
        self._store.pop(oldest[0], None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# ---------------------------------------------------------------------------
# Source interface
# ---------------------------------------------------------------------------

def normalise_host(value: str) -> str:
    """Reduce a URL, host or registry entry to a comparable lowercase host.

    Strips the scheme, userinfo, path, query, fragment and port. One shared
    helper matters because list-backed sources compare on both the write side
    and the read side: if ``add`` normalises differently from ``check``, an
    entry registered as ``bad.xyz`` never matches a lookup of
    ``https://bad.xyz:8443/x`` and the registry silently stops working.
    """
    cleaned = (value or "").strip().lower()
    if not cleaned:
        return ""
    cleaned = cleaned.split("://")[-1]
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
    if "@" in cleaned:
        cleaned = cleaned.rsplit("@", 1)[-1]
    if cleaned.startswith("["):  # bracketed IPv6 literal
        return cleaned[1:].split("]", 1)[0]
    if ":" in cleaned:
        head, _, port = cleaned.rpartition(":")
        if head and port.isdigit():
            cleaned = head
    return cleaned.strip(".")


class ThreatSource:
    """Anything that can opine on a URL.

    Implementations must never raise: return ``SourceVerdict.unavailable`` with
    a reason instead. A source that throws takes the whole federation down with
    it, and an attacker can trigger that deliberately by handing us a URL that
    makes one vendor 500.
    """

    name: str = "unnamed"
    #: How long to wait for this source before treating it as unavailable.
    timeout_seconds: float = 3.0
    #: Multiplier on the source's raw probability. A source with a history of
    #: false positives is down-weighted rather than removed.
    weight: float = 1.0

    def check(self, url: str) -> SourceVerdict:  # pragma: no cover - interface
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Offline sources -- these work with no network at all
# ---------------------------------------------------------------------------

class LocalRegistrySource(ThreatSource):
    """The crowdsourced registry: URLs, domains and hosts HAAFIZ already knows.

    This is the only source that gets *stronger* as HAAFIZ is used. Every
    user-confirmed scam adds an entry, and unlike a vendor blocklist it can hold
    the things no global feed will ever contain -- a JazzCash impersonator's
    0300 number, a Roman-Urdu SMS template, a Karachi-specific investment scam.
    """

    name = "haafiz_registry"
    timeout_seconds = 0.5
    weight = 1.0

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._exact: set[str] = set()
        self._domains: set[str] = set()
        for entry in entries:
            self.add(entry)

    def add(self, entry: str) -> None:
        cleaned = normalise_host(entry)
        if not cleaned:
            return
        self._exact.add(cleaned)
        _, registrable = split_registrable_domain(cleaned)
        if registrable:
            self._domains.add(registrable)

    def __len__(self) -> int:
        return len(self._exact)

    def check(self, url: str) -> SourceVerdict:
        target = normalise_host(url)
        if not target:
            return SourceVerdict.unavailable(self.name, "koi URL nahi diya gaya")
        if target in self._exact:
            return SourceVerdict(
                source=self.name, probability=0.99, label="confirmed",
                evidence=(f"'{target}' pehle se confirmed scam registry mein hai",),
            )
        _, registrable = split_registrable_domain(target)
        if registrable and registrable in self._domains:
            return SourceVerdict(
                source=self.name, probability=0.97, label="confirmed_domain",
                evidence=(
                    f"'{registrable}' ka domain confirmed scam registry mein hai",
                ),
            )
        # Present and answerable, just not listed. That is a real (weak) vote
        # for clean -- unlike a timeout, this source *did* look.
        return SourceVerdict(
            source=self.name, probability=0.0, label="not_listed",
            evidence=("HAAFIZ registry mein ye URL maujood nahi",),
        )


class BrandImpersonationSource(ThreatSource):
    """Wraps the domain-similarity detector. Pure, offline, zero-hour capable."""

    name = "brand_impersonation"
    timeout_seconds = 1.0
    weight = 1.0

    def __init__(self, detector: BrandImpersonationDetector) -> None:
        self.detector = detector

    def check(self, url: str) -> SourceVerdict:
        target = (url or "").strip()
        if not target:
            return SourceVerdict.unavailable(self.name, "koi URL nahi diya gaya")
        host = urlsplit(target if "://" in target else f"//{target}").hostname or target
        try:
            assessment = self.detector.assess(host)
        except Exception as exc:  # never let a hostile hostname take us down
            return SourceVerdict.unavailable(self.name, f"assessor error: {exc}")

        if not assessment.registrable_domain:
            return SourceVerdict.unavailable(self.name, "hostname parse nahi hua")

        evidence = list(assessment.evidence)
        tld_score, tld_evidence = tld_risk(host)
        probability = assessment.risk
        if tld_score:
            probability = 1.0 - (1.0 - probability) * (1.0 - tld_score)
            if tld_evidence:
                evidence.append(tld_evidence)

        return SourceVerdict(
            source=self.name,
            probability=probability,
            label=classify(probability),
            evidence=tuple(evidence),
            applicable=True,
        )


# ---------------------------------------------------------------------------
# Network adapters -- thin, and never fatal
# ---------------------------------------------------------------------------

class CallableSource(ThreatSource):
    """Adapts a plain ``url -> SourceVerdict`` function into a source.

    Used for the network-backed vendors so that the federation itself stays
    dependency-free and fully testable with stubs.
    """

    def __init__(
        self,
        name: str,
        func: Callable[[str], SourceVerdict],
        timeout_seconds: float = 3.0,
        weight: float = 1.0,
        cache: TtlCache | None = None,
        cache_ttl: float = 300.0,
    ) -> None:
        self.name = name
        self._func = func
        self.timeout_seconds = timeout_seconds
        self.weight = weight
        self._cache = cache
        self._cache_ttl = cache_ttl

    def check(self, url: str) -> SourceVerdict:
        key = f"{self.name}:{url.strip().lower()}"
        if self._cache is not None:
            cached = self._cache.get(key)
            if isinstance(cached, SourceVerdict):
                return cached
        try:
            verdict = self._func(url)
        except Exception as exc:
            # A vendor that errors, 500s or is rate-limited has told us nothing.
            return SourceVerdict.unavailable(self.name, f"{type(exc).__name__}: {exc}")
        if not isinstance(verdict, SourceVerdict):
            return SourceVerdict.unavailable(self.name, "source ne galat type lotaya")
        if self._cache is not None and verdict.applicable:
            self._cache.set(key, verdict, self._cache_ttl)
        return verdict


class FeedSource(ThreatSource):
    """A bulk community feed (OpenPhish, URLhaus) held in memory.

    Feeds are downloaded wholesale and matched locally, so per-check cost is a
    hash lookup rather than an API call. This is what makes the free tiers
    viable at national scale: URLhaus has no quota at all, and OpenPhish's feed
    is a plain text file.
    """

    def __init__(
        self,
        name: str,
        entries: Iterable[str] = (),
        probability: float = 0.95,
        loader: Callable[[], Iterable[str]] | None = None,
        refresh_seconds: float = 3600.0,
    ) -> None:
        self.name = name
        self.probability = probability
        self._loader = loader
        self._refresh = refresh_seconds
        self._lock = threading.Lock()
        self._hosts: set[str] = set()
        self._domains: set[str] = set()
        self._loaded_at: float = 0.0
        self.add_many(entries)

    # -- population --------------------------------------------------------

    def add_many(self, entries: Iterable[str]) -> int:
        added = 0
        with self._lock:
            for entry in entries:
                if (entry or "").strip().startswith("#"):
                    continue
                cleaned = normalise_host(entry)
                if not cleaned:
                    continue
                self._hosts.add(cleaned)
                _, registrable = split_registrable_domain(cleaned)
                if registrable:
                    self._domains.add(registrable)
                added += 1
        return added

    def refresh(self) -> int:
        """Reload from the loader if one was supplied and the TTL has elapsed."""
        if self._loader is None:
            return 0
        now = time.monotonic()
        if self._loaded_at and now - self._loaded_at < self._refresh:
            return 0
        try:
            entries = self._loader()
        except Exception:
            return 0
        count = self.add_many(entries)
        self._loaded_at = now
        return count

    def __len__(self) -> int:
        with self._lock:
            return len(self._hosts)

    # -- lookup ------------------------------------------------------------

    def check(self, url: str) -> SourceVerdict:
        target = normalise_host(url)
        if not target:
            return SourceVerdict.unavailable(self.name, "koi URL nahi diya gaya")
        with self._lock:
            if not self._hosts:
                # An empty feed has not been loaded yet -- that is not evidence
                # of cleanliness, it is an unavailable source.
                return SourceVerdict.unavailable(self.name, "feed abhi load nahi hua")
            exact = target in self._hosts
            _, registrable = split_registrable_domain(target)
            domain_hit = bool(registrable) and registrable in self._domains
        if exact:
            return SourceVerdict(
                source=self.name, probability=self.probability, label="listed",
                evidence=(f"'{target}' {self.name} feed mein maujood hai",),
            )
        if domain_hit:
            return SourceVerdict(
                source=self.name, probability=self.probability * 0.9,
                label="listed_domain",
                evidence=(f"'{registrable}' ka domain {self.name} feed mein hai",),
            )
        return SourceVerdict(
            source=self.name, probability=0.0, label="not_listed",
            evidence=(f"{self.name} feed mein ye URL nahi",),
        )


# ---------------------------------------------------------------------------
# The federation
# ---------------------------------------------------------------------------

class Federation:
    """Query every source in parallel and combine the ones that answered.

    Runs sources concurrently with per-source timeouts, because the whole point
    is to beat the latency of any single vendor. Total wall-clock cost is the
    slowest source that is still inside its timeout -- not the sum.
    """

    def __init__(
        self,
        sources: Sequence[ThreatSource] = (),
        max_workers: int = 8,
        default_timeout: float = 3.0,
    ) -> None:
        self.sources: list[ThreatSource] = list(sources)
        self.max_workers = max(1, max_workers)
        self.default_timeout = default_timeout

    def add(self, source: ThreatSource) -> None:
        self.sources.append(source)

    def check(self, url: str) -> FederatedVerdict:
        started = time.monotonic()
        target = (url or "").strip()
        if not target:
            return FederatedVerdict(
                url=target, probability=0.0, label="clean",
                evidence=["Check karne ke liye koi URL nahi diya gaya"],
            )

        if not self.sources:
            return FederatedVerdict(
                url=target, probability=0.0, label="unknown",
                evidence=["Koi intelligence source configure nahi hai"],
            )

        verdicts = self._run_all(target)
        return self._combine(target, verdicts, started)

    # -- internals ---------------------------------------------------------

    def _run_all(self, url: str) -> list[SourceVerdict]:
        """Run every source concurrently, each under its own deadline.

        Three traps this avoids, all of which appeared in earlier drafts:

        * The executor's context manager calls ``shutdown(wait=True)``, so a
          source that sleeps through its timeout still blocks the whole check.
          Shutdown must be ``wait=False``.
        * Iterating futures and calling ``result(timeout=t)`` one at a time
          applies budgets sequentially, so three 3-second timeouts take nine
          seconds.
        * Waiting once with ``timeout=max(budgets)`` is better but still wrong:
          one generous source holds the whole check open. Three vendors on a
          0.3 s budget plus one source on 1.0 s took a full second.

        The fix is per-source *absolute* deadlines measured from a common start,
        re-armed in a loop so the call returns the moment every pending source
        has either answered or blown its own budget.
        """
        started = time.monotonic()
        pool = ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(self.sources)),
            thread_name_prefix="haafiz-intel",
        )

        # future -> (source, absolute deadline)
        bookkeeping: dict[object, tuple[ThreatSource, float]] = {}
        verdicts: dict[str, SourceVerdict] = {}

        try:
            for source in self.sources:
                budget = getattr(source, "timeout_seconds", self.default_timeout)
                future = pool.submit(self._invoke, source, url)
                bookkeeping[future] = (source, started + budget)

            pending = set(bookkeeping)
            while pending:
                now = time.monotonic()
                next_deadline = min(bookkeeping[f][1] for f in pending)
                done, pending = wait(
                    pending,
                    timeout=max(0.0, next_deadline - now),
                    return_when=ALL_COMPLETED,
                )
                for future in done:
                    source, _ = bookkeeping[future]
                    try:
                        verdicts[source.name] = future.result()
                    except Exception as exc:
                        verdicts[source.name] = SourceVerdict.unavailable(
                            source.name, f"{type(exc).__name__}: {exc}"
                        )
                for future in list(pending):
                    source, deadline = bookkeeping[future]
                    if time.monotonic() >= deadline:
                        verdicts[source.name] = SourceVerdict.unavailable(
                            source.name,
                            f"{getattr(source, 'timeout_seconds', self.default_timeout):.1f}s "
                            f"mein jawab nahi aya",
                        )
                        future.cancel()
                        pending.discard(future)
        finally:
            # Do not wait for stragglers: their verdict is already recorded as
            # unavailable, and blocking here would defeat the deadline.
            # cancel_futures clears anything that has not started yet.
            pool.shutdown(wait=False, cancel_futures=True)

        # Preserve the caller's source order for stable, readable output.
        return [verdicts[s.name] for s in self.sources if s.name in verdicts]

    def _invoke(self, source: ThreatSource, url: str) -> SourceVerdict:
        """Call one source, stamping the registered name and measured latency.

        The name is overwritten rather than trusted. An adapter that returns
        ``SourceVerdict(source="q")`` while registered as ``s1`` would make
        ``contributing`` disagree with ``unavailable`` and, worse, silently
        break per-source weight lookup -- every verdict would fall through to
        the default weight of 1.0.
        """
        started = time.monotonic()
        try:
            verdict = source.check(url)
        except Exception as exc:
            return SourceVerdict.unavailable(source.name, f"{type(exc).__name__}: {exc}")
        if not isinstance(verdict, SourceVerdict):
            return SourceVerdict.unavailable(source.name, "source ne galat type lotaya")
        return SourceVerdict(
            source=source.name,
            probability=min(max(verdict.probability, 0.0), 1.0),
            label=verdict.label or "unknown",
            evidence=tuple(e for e in verdict.evidence if e),
            applicable=verdict.applicable,
            latency_ms=verdict.latency_ms or int((time.monotonic() - started) * 1000),
        )

    def _combine(
        self, target: str, verdicts: list[SourceVerdict], started: float
    ) -> FederatedVerdict:
        speaking = [v for v in verdicts if v.applicable]
        silent = [v.source for v in verdicts if not v.applicable]

        weighted = [
            min(max(v.probability, 0.0), 1.0) * getattr(self._weight_of(v.source), "weight", 1.0)
            for v in speaking
        ]
        probability = noisy_or(weighted)

        contributing = [v.source for v in speaking if v.probability > 0]
        evidence: list[str] = []
        for verdict in speaking:
            evidence.extend(e for e in verdict.evidence if e)
        for source in silent:
            reason = next(
                (e for v in verdicts if v.source == source for e in v.evidence), ""
            )
            evidence.append(f"{source} se jawab nahi mila" + (f" ({reason})" if reason else ""))

        return FederatedVerdict(
            url=target,
            probability=probability,
            label=classify(probability),
            sources=verdicts,
            contributing=contributing,
            unavailable=silent,
            evidence=list(dict.fromkeys(evidence)),
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    def _weight_of(self, name: str) -> ThreatSource:
        for source in self.sources:
            if source.name == name:
                return source
        return ThreatSource()


def build_default_federation(
    detector: BrandImpersonationDetector,
    registry_entries: Iterable[str] = (),
    extra_sources: Iterable[ThreatSource] = (),
) -> Federation:
    """A federation that works with **no network configuration at all**.

    Brand impersonation plus the local registry are both offline, so a fresh
    deployment already answers the question VirusTotal cannot -- "is this
    twenty-minute-old domain pretending to be HBL?" -- before a single API key
    exists. Vendor sources are added on top when credentials are supplied.
    """
    sources: list[ThreatSource] = [
        LocalRegistrySource(registry_entries),
        BrandImpersonationSource(detector),
    ]
    sources.extend(extra_sources)
    return Federation(sources)


def url_fingerprint(url: str) -> str:
    """Stable short identifier for a URL, for logging without storing the URL.

    Privacy matters here: docs/SECURITY.md promises content is not retained.
    A fingerprint lets us deduplicate and count without keeping the link.
    """
    normalised = (url or "").strip().lower().rstrip("/")
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16]
