"""Brand-impersonation detection for domain names.

This is the piece that catches phishing a blocklist never can: a domain that was
registered twenty minutes ago has no reputation yet, so Google Safe Browsing,
VirusTotal and PhishTank all report it as clean. Its *name*, however, already
tells you what it is pretending to be.

Five techniques, from the Certificate Transparency literature
(docs/DETECTION.md):

1. typosquatting    hbl.com.pk  ->  hbl-com.pk, hblc0m.pk
2. homoglyph / IDN  apple.com   ->  аpple.com (Cyrillic а) -> xn--80ak6aa92e.com
3. keyword stuffing             ->  secure-hbl-login.com
4. subdomain abuse              ->  hbl-login.attacker.com
5. TLD variation                ->  hbl.co for hbl.com

Everything here is pure, offline and deterministic. No network calls, no third
party, no API quota -- which is the whole point. It runs in microseconds on the
client side and works on a feature-phone-grade server.

Public-domain caveat: this file must not decide "brand X exists". Brands come
from the verified registry (``data/verified_domains.txt``), because guessing at
who owns what is how you end up blocking a legitimate reseller.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, Sequence

# ---------------------------------------------------------------------------
# Public suffixes
# ---------------------------------------------------------------------------

# A real deployment should load the Public Suffix List. This subset covers the
# suffixes that matter for Pakistan plus the most common global ones, and it is
# deliberately explicit: getting this wrong silently breaks every other check.
#
# The trap: with ``hbl.com.pk`` a naive "last two labels" split yields
# ``com.pk`` as the registrable domain, so ``hbl`` looks like a subdomain and
# the brand match lands in the wrong place.
MULTI_PART_SUFFIXES: frozenset[str] = frozenset(
    {
        # Pakistan -- every second-level domain PKNIC operates. Missing
        # ``mobi.pk`` makes ``meezanbank.mobi.pk`` parse as a subdomain of
        # ``mobi.pk``, which is not a registrable domain at all.
        "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk", "web.pk", "fam.pk",
        "biz.pk", "info.pk", "mobi.pk", "gob.pk", "gok.pk", "gon.pk",
        "gop.pk", "gos.pk", "gog.pk", "res.pk",
        # South Asia / region
        "co.in", "net.in", "org.in", "gov.in", "edu.in", "ac.in",
        "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd",
        "com.np", "org.np", "gov.np", "edu.np",
        "com.af", "org.af", "gov.af", "net.af", "edu.af",
        "com.lk", "org.lk", "gov.lk", "edu.lk", "net.lk",
        # Middle East
        "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "pub.sa",
        "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae",
        "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
        "co.il", "net.il", "org.il", "gov.il",
        # Common global multi-part
        "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "co.za", "org.za", "net.za", "gov.za", "web.za",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.my", "net.my", "org.my", "gov.my", "edu.my",
        "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
        "com.hk", "org.hk", "net.hk", "gov.hk", "edu.hk",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "go.kr", "ne.kr",
        "com.mx", "org.mx", "gob.mx", "net.mx",
        "com.ar", "net.ar", "org.ar", "gob.ar",
        "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
        "com.ru", "net.ru", "org.ru",
        "com.vn", "net.vn", "org.vn", "gov.vn",
        "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
        "com.eg", "org.eg", "net.eg", "gov.eg", "edu.eg",
        "com.ng", "org.ng", "net.ng", "gov.ng", "edu.ng",
        "com.gh", "org.gh", "net.gh", "gov.gh", "edu.gh",
        "com.sg", "co.id", "web.id", "or.id", "go.id", "ac.id", "my.id",
    }
)

SINGLE_PART_SUFFIXES: frozenset[str] = frozenset(
    {
        "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
        "co", "me", "tv", "cc", "io", "ai", "app", "dev", "tech", "online",
        "site", "website", "store", "shop", "bank", "live", "life", "world",
        "xyz", "top", "click", "link", "loan", "win", "bid", "date", "racing",
        "download", "stream", "gdn", "men", "party", "science", "trade",
        "review", "cricket", "faith", "accountant", "kim", "work", "space",
        "fun", "host", "press", "pw", "rest", "icu", "cam", "monster",
        "sbs", "cyou", "quest", "beauty", "skin", "makeup", "autos", "homes",
        "yachts", "motorcycles", "bond", "cfd",
    }
)

# ccTLDs are a fixed, small, stable set -- listing the common ones is enough.
COUNTRY_SUFFIXES: frozenset[str] = frozenset(
    {
        "pk", "in", "bd", "np", "lk", "af", "sa", "ae", "tr", "il", "uk", "au",
        "nz", "br", "za", "cn", "my", "sg", "hk", "jp", "kr", "mx", "ar", "ua",
        "ru", "vn", "ph", "eg", "ng", "gh", "id", "de", "fr", "es", "it", "nl",
        "be", "ch", "at", "se", "no", "dk", "fi", "pl", "cz", "gr", "pt", "ie",
        "ca", "us", "gb", "eu", "ir", "iq", "qa", "kw", "om", "bh", "jo", "lb",
        "sy", "ye", "ly", "ma", "dz", "tn", "ke", "tz", "ug", "et", "mm", "kh",
        "la", "th", "mv", "bt", "sl", "bn", "tl", "pg", "fj",
    }
)


def split_registrable_domain(hostname: str) -> tuple[str, str]:
    """Split ``a.b.hbl.com.pk`` into ``("a.b", "hbl.com.pk")``.

    Returns ``("", hostname)`` when the hostname is already registrable or
    cannot be parsed. Never raises -- detection code must not crash on a
    malformed URL that an attacker crafted on purpose.
    """
    host = hostname.strip().strip(".").lower()
    if not host or "." not in host:
        return "", host

    labels = host.split(".")
    if len(labels) < 2:
        return "", host

    # Try the two-label suffix first (com.pk), then the single label (pk).
    #
    # Off-by-one here is silent and catastrophic: taking labels[:-2] as the
    # subdomain of a two-part-suffix host makes ``hblpayment.com.pk`` look like
    # it has a subdomain called ``hblpayment``, and the brand-embedded case is
    # then misreported as subdomain abuse. The subdomain is everything strictly
    # to the left of the registrable domain -- which means labels[:-3] when the
    # suffix is two labels wide, and labels[:-2] when it is one.
    two_part = ".".join(labels[-2:])
    if two_part in MULTI_PART_SUFFIXES:
        if len(labels) <= 3:
            return "", host
        return ".".join(labels[:-3]), ".".join(labels[-3:])

    last = labels[-1]
    if last in SINGLE_PART_SUFFIXES or last in COUNTRY_SUFFIXES:
        if len(labels) <= 2:
            return "", host
        return ".".join(labels[:-2]), ".".join(labels[-2:])

    # Unknown TLD -- fall back to treating the last two labels as registrable.
    if len(labels) <= 2:
        return "", host
    return ".".join(labels[:-2]), ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# Homoglyphs / IDN
# ---------------------------------------------------------------------------

# Characters that render almost identically to ASCII but are not ASCII. This is
# the Cyrillic/Greek confusion set that makes ``аpple.com`` (Cyrillic а)
# indistinguishable from ``apple.com`` in a browser address bar.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "к": "k",
    "м": "m", "т": "t", "н": "h", "в": "b", "л": "l", "г": "r", "п": "n",
    "з": "3", "ч": "4", "ш": "w", "ь": "b", "ъ": "b", "э": "e", "ю": "io",
    "я": "r", "ф": "f", "ц": "u", "и": "n", "щ": "w", "ё": "e", "ґ": "r",
    # Palochka renders as a bare vertical stroke and is a stand-in for both
    # ``l`` and ``I``. Omitting it silently deletes the character, so
    # ``аррӏе`` folded to ``appe`` and the Apple match was lost entirely.
    "ӏ": "l", "Ӏ": "l", "ӱ": "y", "ӳ": "y", "ӗ": "e", "ѐ": "e", "ѓ": "r",
    "ҕ": "r", "џ": "u", "ҽ": "e", "ҿ": "b", "ӂ": "x", "ҷ": "y", "ӄ": "k",
    "Ү": "y", "ү": "y", "ө": "o", "һ": "h", "ԁ": "d",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "η": "h", "ι": "i", "κ": "k", "ν": "v",
    "ρ": "p", "τ": "t", "υ": "y", "χ": "x", "ω": "w", "σ": "s", "β": "b",
    "γ": "y", "δ": "d", "ζ": "z", "θ": "th", "λ": "l", "μ": "m", "ξ": "x",
    "π": "p", "φ": "f", "ψ": "ps", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z",
    "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p",
    "Τ": "t", "Υ": "y", "Χ": "x", "Ϝ": "f", "ς": "s",
    # Fullwidth ASCII (U+FF01-FF5E) is normalised by NFKC below.
    # Other frequent look-alikes
    "ı": "i", "ł": "l", "đ": "d", "ø": "o", "ħ": "h", "ŧ": "t", "ŋ": "n",
    "ſ": "s", "ẛ": "s", "ǃ": "!", "·": ".", "․": ".", "‧": ".",
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-", "﹘": "-",
    "﹣": "-", "－": "-", "＿": "_", "．": ".", "⁄": "/", "∕": "/", "╱": "/",
    "⁢": "", "⁣": "", "⁤": "", "﻿": "", "\u200b": "", "\u200c": "",
    "\u200d": "", "\u2060": "",
}

# Digit <-> letter substitutions attackers use.
_LEET: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "9": "g", "2": "z", "6": "b",
}


def is_punycode(label: str) -> bool:
    """True for an IDN encoded as ACE (``xn--...``).

    Merely being punycode is not proof of malice -- legitimate Urdu-language
    sites use it too. But a punycode label that *decodes* to something visually
    close to an ASCII brand is a strong signal.
    """
    return label.lower().startswith("xn--")


def decode_idn(hostname: str) -> str:
    """Decode every punycode label. Returns the input unchanged on failure."""
    labels = hostname.split(".")
    out: list[str] = []
    for label in labels:
        if is_punycode(label):
            try:
                out.append(label.encode("ascii", "ignore").decode("idna"))
            except (UnicodeError, UnicodeDecodeError, ValueError):
                out.append(label)
        else:
            out.append(label)
    return ".".join(out)


def fold_to_ascii(text: str) -> str:
    """Fold homoglyphs, zero-width characters and leetspeak to plain ASCII.

    ``аpple`` (Cyrillic) -> ``apple``.  ``paypa1`` -> ``paypal``.

    Deliberately does NOT rewrite multi-character look-alikes such as ``rn``->``m``
    or ``lc``->``d``. An earlier version did, and it destroyed more than it
    found: ``hblc0m`` collapsed to ``hbdom`` through the ``lc``->``d`` rule, so
    the brand name vanished and the domain scored as clean. Edit distance
    already catches ``arnazon``/``amazon``, and Damerau catches transpositions.
    Substituting substrings blind is a net loss.
    """
    # NFKC collapses fullwidth forms and compatibility characters.
    normalised = unicodedata.normalize("NFKC", text).lower()

    folded: list[str] = []
    for char in normalised:
        if char in _CONFUSABLES:
            folded.append(_CONFUSABLES[char])
            continue
        # Strip combining marks left over from decomposition.
        if unicodedata.combining(char):
            continue
        folded.append(char)
    result = "".join(folded)

    # Drop anything still non-ASCII after folding (unrecognised scripts).
    result = "".join(c for c in result if c.isascii())

    return _fold_isolated_leet(result)


def _fold_isolated_leet(text: str) -> str:
    """Fold digits to letters only when a digit stands alone.

    ``hblc0m`` -> ``hblcom`` (the 0 is standing in for an o), but ``jazzcash88``
    keeps its digits: a numeric run is a distinguishing suffix, not a character
    substitution, and folding it invents a second, spurious brand match. A
    purely numeric label such as ``786`` is left completely alone.
    """
    if not any(c.isalpha() for c in text):
        return text

    out: list[str] = []
    for index, char in enumerate(text):
        if char in _LEET:
            prev_digit = index > 0 and text[index - 1].isdigit()
            next_digit = index + 1 < len(text) and text[index + 1].isdigit()
            if not prev_digit and not next_digit:
                out.append(_LEET[char])
                continue
        out.append(char)
    return "".join(out)


# ---------------------------------------------------------------------------
# Edit distance
# ---------------------------------------------------------------------------

_MAX_DISTANCE_LENGTH = 128  # guard against pathological input


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal-string-alignment distance: insert, delete, substitute, transpose.

    Transposition matters because it is the most common real typo --
    ``hbI`` vs ``ihb`` is one keystroke apart, and plain Levenshtein scores it 2.

    O(len(a) * len(b)). Capped inputs only; this runs on every URL.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    if la > _MAX_DISTANCE_LENGTH or lb > _MAX_DISTANCE_LENGTH:
        # Absurdly long hostnames are already suspicious; refuse to burn CPU.
        return max(la, lb)

    prev2: list[int] = []
    prev = list(range(lb + 1))

    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,        # deletion
                curr[j - 1] + 1,    # insertion
                prev[j - 1] + cost,  # substitution
            )
            if (
                i > 1
                and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                curr[j] = min(curr[j], prev2[j - 2] + 1)  # transposition
        prev2, prev = prev, curr

    return prev[lb]


# ---------------------------------------------------------------------------
# Brand registry
# ---------------------------------------------------------------------------

# Words that, sitting next to a brand name, almost never appear in a legitimate
# domain owned by that brand. From the CT-monitoring literature.
# Keywords split by how strongly they indicate phishing.
#
# Getting this wrong is expensive in both directions. A phisher builds
# ``hbl-secure-login-verify.com``; a bank legitimately owns
# ``hblstocks.com`` and ``meezaninvestments.com``. Both contain the brand
# name. What separates them is the *other* word:
#
#   STRONG -- credential capture, urgency, prize bait. Banks do not put these
#             in a registered domain name; phishers almost always do.
#   WEAK   -- ordinary business vocabulary. Contributes a little, never enough
#             on its own to reach the suspicion threshold.

STRONG_IMPERSONATION_KEYWORDS: frozenset[str] = frozenset(
    {
        "login", "signin", "logon", "auth", "authenticate",
        "verify", "verification", "validate",
        "secure", "security", "safe", "safepay",
        "account", "accounts", "myaccount",
        "reset", "recover", "recovery", "unlock", "unblock", "reactivate",
        "update", "upgrade", "confirm", "confirmation",
        "suspend", "suspended", "blocked", "restricted",
        "urgent", "final", "alert",
        "kyc", "cnic", "otp", "password", "credential", "credentials",
        "prize", "winner", "lucky", "reward", "refund", "claim",
        "nadra", "fbr", "pta",
    }
)

WEAK_IMPERSONATION_KEYWORDS: frozenset[str] = frozenset(
    {
        "support", "help", "helpdesk", "service", "services", "care",
        "customer", "client", "portal", "online", "netbanking", "ibanking",
        "mobile", "mobi", "wallet", "pay", "payment", "payments",
        "transfer", "profile", "notice", "notification", "important",
        "limit", "limited", "official", "verified", "approved", "authorized",
    }
)

#: Union, kept for callers that only care "is this a keyword at all".
IMPERSONATION_KEYWORDS: frozenset[str] = (
    STRONG_IMPERSONATION_KEYWORDS | WEAK_IMPERSONATION_KEYWORDS
)

_MIN_INFIX_KEYWORD_LENGTH = 6


def _keyword_hits(haystack: str) -> tuple[list[str], list[str]]:
    """Impersonation keywords in a hostname, split into strong and weak tiers.

    Word boundaries are respected. A naive ``keyword in haystack`` produces
    false positives: ``hbl-careers.info`` is a plausible recruitment domain,
    but ``care`` appears inside ``careers``.
    """
    if not haystack:
        return [], []

    tokens = [t for t in haystack.replace("_", "-").replace(".", "-").split("-") if t]
    strong: set[str] = set()
    weak: set[str] = set()

    # 1. Exact token match -- unambiguous.
    for token in tokens:
        if token in STRONG_IMPERSONATION_KEYWORDS:
            strong.add(token)
        elif token in WEAK_IMPERSONATION_KEYWORDS:
            weak.add(token)

    # 2. Separator-free composition inside a token: ``securehbl``,
    #    ``verifyhblaccount``. Applied per token, because a hostname can mix
    #    separated and glued parts (``securehbl.online``). Prefix/suffix only,
    #    long keywords only -- that is what keeps ``care`` out of ``careers``.
    for token in tokens:
        if token in IMPERSONATION_KEYWORDS:
            continue
        for keyword in IMPERSONATION_KEYWORDS:
            if len(keyword) < _MIN_INFIX_KEYWORD_LENGTH:
                continue
            if token.startswith(keyword) or token.endswith(keyword):
                (strong if keyword in STRONG_IMPERSONATION_KEYWORDS else weak).add(keyword)

    return sorted(strong), sorted(weak)


_TLD_WORDS: frozenset[str] = frozenset(
    {"com", "net", "org", "pk", "co", "web", "online", "info", "gov", "edu"}
)


def _separator_swap_forms(hostname: str) -> set[str]:
    """Candidate normalisations of a hostname, for collision testing.

    ``hbl-com.pk`` and ``hbl.com.pk`` are one character apart, and that one
    character is the whole trick: the attacker replaces the dot with a hyphen
    (or a zero with an o, or an l with a 1) so the *rendered* name still reads
    as the bank. Testing normalised forms against the verified registry turns
    that into a precise, low-false-positive signal.
    """
    host = (hostname or "").strip().strip(".").lower()
    if not host:
        return set()

    forms: set[str] = {host}
    folded = fold_to_ascii(host)
    forms.add(folded)

    for base in (host, folded):
        forms.add(base.replace("-", ".").replace("_", "."))
        forms.add(base.replace("-", "").replace("_", ""))
    # Folded leetspeak can expose ``hblc0m.pk`` -> ``hbl.com.pk``.
    for sep in ("-", "_"):
        forms.add(folded.replace(sep, "."))
    return {f for f in forms if f and f != host}


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(frozen=True)
class Brand:
    """A verified institution and the domains it legitimately owns."""

    name: str
    official_domains: frozenset[str]
    #: Brand strings to match against. Defaults to the second-level labels of
    #: ``official_domains``, but a registry entry may add abbreviations
    #: ("HBL" -> also match "habib") and product names ("Easypaisa").
    aliases: frozenset[str] = frozenset()

    def match_terms(self) -> frozenset[str]:
        terms = set(self.aliases)
        for domain in self.official_domains:
            _, registrable = split_registrable_domain(domain)
            if registrable:
                terms.add(registrable.split(".")[0])
        return frozenset(t for t in terms if t)


@dataclass
class DomainAssessment:
    """Result of comparing one hostname against the brand registry."""

    hostname: str
    registrable_domain: str
    subdomain: str
    suspicious: bool = False
    risk: float = 0.0
    impersonated_brand: str | None = None
    techniques: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "registrable_domain": self.registrable_domain,
            "subdomain": self.subdomain,
            "suspicious": self.suspicious,
            "risk": round(self.risk, 4),
            "impersonated_brand": self.impersonated_brand,
            "techniques": list(self.techniques),
            "evidence": list(self.evidence),
        }


class BrandImpersonationDetector:
    """Score a hostname against a registry of verified brands.

    Deterministic and offline. This is Layer 2 of docs/DETECTION.md -- the part
    that works on a domain nobody has ever reported.
    """

    #: Above this edit distance a match is coincidence, not impersonation.
    #: Scales with brand length so "UBL" (3 chars) is not matched to "UBLxyz".
    MAX_ABSOLUTE_DISTANCE = 2

    def __init__(self, brands: Iterable[Brand] = ()) -> None:
        self.brands: list[Brand] = list(brands)
        self._official: dict[str, str] = {}
        for brand in self.brands:
            for domain in brand.official_domains:
                self._official[domain.strip().lower()] = brand.name

    # -- construction ------------------------------------------------------

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[str, Iterable[str]]]) -> "BrandImpersonationDetector":
        """Build from ``[("HBL", ["hbl.com", "hbl.com.pk"]), ...]``."""
        return cls(
            Brand(name=n, official_domains=frozenset(d.lower() for d in domains))
            for n, domains in pairs
        )

    def add_brand(self, brand: Brand) -> None:
        self.brands.append(brand)
        for domain in brand.official_domains:
            self._official[domain.strip().lower()] = brand.name

    # -- public API --------------------------------------------------------

    def assess(self, hostname: str) -> DomainAssessment:
        """Full assessment of one hostname."""
        raw = (hostname or "").strip().strip(".").lower()
        if not raw:
            return DomainAssessment(hostname="", registrable_domain="", subdomain="")

        # Strip a leading scheme or a trailing path if someone passed a URL.
        raw = raw.split("://")[-1].split("/")[0].split("?")[0].split("#")[0]

        userinfo_decoy: str | None = None
        if "@" in raw:
            # ``hbl.com@evil.tld`` renders as hbl.com in most clients but
            # connects to evil.tld. Keep both halves: the decoy is evidence,
            # the tail is the real host.
            head, _, tail = raw.partition("@")
            userinfo_decoy = head
            raw = tail
            if not raw:
                raw = head
        # Bracketed IPv6 literal, optionally with a port: ``[2001:db8::1]:443``.
        if raw.startswith("["):
            literal = raw[1:].split("]", 1)[0]
            return DomainAssessment(
                hostname=f"[{literal}]", registrable_domain=literal, subdomain="",
                suspicious=True, risk=0.85,
                techniques=["ip_literal"],
                evidence=["Host aik IP address hai, domain name nahi"],
            )

        # Strip the port. Leaving it on corrupts suffix parsing: ``hbl.com:8443``
        # yields a last label of ``com:8443``, which matches no known suffix, so
        # the registrable domain comes out wrong. A bare colon anywhere else
        # means this is an unbracketed IPv6 literal rather than a hostname.
        if ":" in raw:
            head, _, port = raw.rpartition(":")
            if head and port.isdigit():
                raw = head
            else:
                return DomainAssessment(
                    hostname=raw, registrable_domain=raw, subdomain="",
                    suspicious=True, risk=0.85,
                    techniques=["ip_literal"],
                    evidence=["Host aik IP address hai, domain name nahi"],
                )

        if _IPV4_RE.match(raw):
            return DomainAssessment(
                hostname=raw, registrable_domain=raw, subdomain="",
                suspicious=True, risk=0.85,
                techniques=["ip_literal"],
                evidence=["Host aik IP address hai, domain name nahi"],
            )

        subdomain, registrable = split_registrable_domain(raw)
        assessment = DomainAssessment(
            hostname=raw, registrable_domain=registrable, subdomain=subdomain,
        )
        if userinfo_decoy:
            assessment.suspicious = True
            assessment.risk = 0.95
            assessment.techniques.append("userinfo_decoy")
            assessment.evidence.append(
                f"URL mein '@' hai: aap ko '{userinfo_decoy}' dikhta hai magar "
                f"asli host '{registrable}' hai"
            )
        if not registrable:
            return assessment

        # Exact match against the verified registry -> genuinely legitimate.
        if registrable in self._official:
            assessment.evidence.append(
                f"{self._official[registrable]} ka verified official domain"
            )
            return assessment

        punycode_used = any(is_punycode(label) for label in raw.split("."))
        decoded = decode_idn(raw)
        _, decoded_registrable = split_registrable_domain(decoded)
        decoded_subdomain, _ = split_registrable_domain(decoded)
        folded_registrable = fold_to_ascii(decoded_registrable)
        folded_label = folded_registrable.split(".")[0]
        folded_subdomain = fold_to_ascii(decoded_subdomain)

        best: tuple[float, str, list[str], list[str]] | None = None

        for brand in self.brands:
            for term in brand.match_terms():
                folded_term = fold_to_ascii(term)
                if not folded_term:
                    continue

                risk, techniques, evidence = self._compare(
                    term=folded_term,
                    brand_name=brand.name,
                    folded_label=folded_label,
                    folded_subdomain=folded_subdomain,
                    punycode_used=punycode_used,
                    raw_registrable=registrable,
                    official_domains=brand.official_domains,
                )
                if risk > 0 and (best is None or risk > best[0]):
                    best = (risk, brand.name, techniques, evidence)

        # Independent of any brand: a high-abuse TLD is weak evidence on its
        # own but meaningful as corroboration. Combined with noisy-OR so that
        # ``daraz-offer.win`` crosses the line while ``hblstocks.com`` does not.
        tld_score, tld_evidence = tld_risk(raw)

        if best is None:
            if tld_score and any(
                term in fold_to_ascii(registrable)
                for brand in self.brands
                for term in brand.match_terms()
            ):
                assessment.risk = tld_score
                assessment.evidence.append(tld_evidence or "")
                assessment.evidence = [e for e in assessment.evidence if e]
            return assessment

        risk, brand_name, techniques, evidence = best
        risk = 1.0 - (1.0 - risk) * (1.0 - tld_score)
        assessment.risk = risk
        assessment.suspicious = risk >= 0.5
        assessment.impersonated_brand = brand_name
        assessment.techniques = techniques
        assessment.evidence = list(dict.fromkeys(evidence))
        return assessment

    # -- internals ---------------------------------------------------------

    def _compare(
        self,
        term: str,
        brand_name: str,
        folded_label: str,
        folded_subdomain: str,
        punycode_used: bool,
        raw_registrable: str,
        official_domains: frozenset[str],
    ) -> tuple[float, list[str], list[str]]:
        """Score one hostname against one brand term.

        Rules run strongest-first. The ordering is load-bearing: a precise
        collision with a verified domain must outrank a fuzzy match against a
        *different* brand, otherwise ``hbl.co`` reports as a typo of ``ubl``.
        """
        techniques: list[str] = []
        evidence: list[str] = []
        risk = 0.0

        # --- Rule 0: separator substitution ------------------------------
        # ``hbl-com.pk`` is ``hbl.com.pk`` with one character changed. Testing
        # normalised forms against the verified registry catches this exactly,
        # with essentially no false positives -- a legitimate business does not
        # register a punctuation-shifted copy of its own domain.
        collided = sorted(_separator_swap_forms(raw_registrable) & official_domains)
        if collided:
            risk = max(risk, 0.92)
            techniques.append("separator_substitution")
            evidence.append(
                f"'{raw_registrable}' dar-asal '{collided[0]}' ({brand_name}) "
                f"hi hai -- sirf punctuation badla gaya hai"
            )

        # --- Rules 1-4: where the brand name sits ------------------------
        raw_first_label = raw_registrable.split(".")[0]
        candidates: list[tuple[str, str]] = [(raw_registrable, "domain")]
        # folded_label only adds information when folding changed something,
        # otherwise it re-reports the same finding as a duplicate reason.
        if folded_label and folded_label != raw_first_label:
            candidates.append((folded_label, "domain"))
        candidates.append((folded_subdomain, "subdomain"))

        for haystack, where in candidates:
            if not haystack or term not in haystack:
                continue
            strong, weak = _keyword_hits(haystack)

            if strong:
                risk = max(risk, 0.90)
                techniques.append("keyword_stuffing")
                evidence.append(
                    f"{brand_name} ke naam ke saath '{', '.join(strong[:4])}' "
                    f"jaise lafz {where} mein hain"
                )
            elif where == "subdomain":
                risk = max(risk, 0.80)
                techniques.append("subdomain_abuse")
                evidence.append(
                    f"{brand_name} ka naam kisi doosre domain ke subdomain "
                    f"mein hai: {raw_registrable}"
                )
            elif folded_label == term:
                # The brand's exact name on a TLD it does not own: hbl.co.
                risk = max(risk, 0.88)
                techniques.append("tld_variation")
                evidence.append(
                    f"{brand_name} ka naam bilkul yahi hai, magar ye official "
                    f"domain nahi: {raw_registrable}"
                )
            elif self._tld_concatenated(term, folded_label):
                # ``hblc0m.pk`` folds to ``hblcom`` = brand + a TLD word.
                risk = max(risk, 0.88)
                techniques.append("tld_concatenation")
                evidence.append(
                    f"'{raw_registrable}' mein {brand_name} ka naam seedha "
                    f"address ke saath jorr diya gaya hai"
                )
            else:
                # Brand name embedded in a longer, ordinary label. This is
                # where ``hblstocks.com`` and ``meezaninvestments.com`` land --
                # real subsidiaries of real brands. Weak on its own; it must
                # corroborate something else, never decide alone.
                techniques.append("brand_embedded")
                base = 0.45 if weak else 0.35
                risk = max(risk, base)
                detail = (
                    f" (saath '{', '.join(weak[:3])}' jaise lafz)" if weak else ""
                )
                evidence.append(
                    f"{brand_name} ka naam {where} mein shamil hai, magar ye "
                    f"official domain nahi: {raw_registrable}{detail}"
                )

        # --- Rule 5: typosquatting ---------------------------------------
        if folded_label and term:
            distance = damerau_levenshtein(folded_label, term)
            # Scale the tolerance: a 3-letter brand needs distance 1, a longer
            # one can afford 2. Without this "UBL" matches half the alphabet.
            allowed = 1 if len(term) <= 4 else self.MAX_ABSOLUTE_DISTANCE
            if 0 < distance <= allowed:
                length_ratio = min(len(folded_label), len(term)) / max(
                    len(folded_label), len(term), 1
                )
                base = 0.85 if distance == 1 else 0.70
                risk = max(risk, base * (0.6 + 0.4 * length_ratio))
                techniques.append("typosquatting")
                evidence.append(
                    f"Domain '{folded_label}' verified '{term}' se sirf "
                    f"{distance} harf ka farq rakhta hai"
                )

        # --- Rule 6: homoglyph / IDN -------------------------------------
        if punycode_used and term and folded_label and term in folded_label:
            risk = max(risk, 0.95)
            techniques.append("homoglyph_idn")
            evidence.append(
                f"Domain Unicode (IDN) characters istemal karta hai jo "
                f"'{term}' jaisa dikhta hai -- ye visual dhoka hai"
            )

        return risk, sorted(set(techniques)), evidence

    @staticmethod
    def _tld_concatenated(term: str, folded_label: str) -> bool:
        """True when ``folded_label`` is ``term`` glued to a TLD word.

        ``hblcom`` (from ``hblc0m``) = ``hbl`` + ``com``. Distinguishes an
        attacker collapsing the dot from a legitimate compound name such as
        ``hblstocks``, where the remainder is an ordinary word.
        """
        if not folded_label:
            return False
        for part in folded_label.replace("_", "-").split("-"):
            if part.startswith(term) and len(part) > len(term):
                if part[len(term):] in _TLD_WORDS:
                    return True
        return False


    def validate_registry(self) -> list[str]:
        """Report configuration errors in the brand registry.

        Registry mistakes produce silent false positives that look exactly like
        detection bugs, which makes them miserable to diagnose. Surfacing them
        as explicit warnings turns ``jazz.com.pk`` being flagged from a mystery
        into a one-line config fix.

        Returns a list of human-readable problems; empty means the registry is
        internally consistent.
        """
        problems: list[str] = []
        official_labels: dict[str, str] = {}
        for brand in self.brands:
            for domain in brand.official_domains:
                if "." not in domain:
                    problems.append(
                        f"{brand.name}: '{domain}' ek domain name nahi "
                        f"(dot chahiye, jaise example.com)"
                    )
                    continue
                _, registrable = split_registrable_domain(domain)
                if not registrable:
                    problems.append(
                        f"{brand.name}: '{domain}' parse nahi ho saka "
                        f"(suffix unknown?)"
                    )
                    continue
                official_labels[registrable.split(".")[0]] = brand.name

        for brand in self.brands:
            for alias in brand.aliases:
                folded = fold_to_ascii(alias)
                owner = official_labels.get(folded)
                if owner and owner != brand.name:
                    problems.append(
                        f"{brand.name}: alias '{alias}' doosre brand '{owner}' "
                        f"ka official domain label hai -- inhein alag brand "
                        f"entries banayein"
                    )
        return problems


# ---------------------------------------------------------------------------
# Suspicious-TLD signal (independent of any brand)
# ---------------------------------------------------------------------------

# TLDs with a high observed abuse ratio. Presence alone is weak evidence --
# legitimate sites use ``.xyz`` too -- so this contributes a small amount and
# is meant to be combined, never to decide alone.
HIGH_ABUSE_TLDS: frozenset[str] = frozenset(
    {
        "xyz", "top", "click", "link", "loan", "win", "bid", "date", "racing",
        "download", "stream", "gdn", "men", "party", "science", "trade",
        "review", "cricket", "faith", "accountant", "kim", "rest", "icu",
        "cam", "monster", "sbs", "cyou", "quest", "bond", "cfd", "tk", "ml",
        "ga", "cf", "gq", "pw", "work", "zip", "mov", "online", "site",
        "website", "buzz", "life", "live", "digital", "network", "email",
        "services", "systems", "solutions", "agency", "company", "group",
    }
)


def tld_risk(hostname: str) -> tuple[float, str | None]:
    """Small standalone risk contribution from the TLD alone."""
    host = (hostname or "").strip().strip(".").lower().split("://")[-1].split("/")[0]
    if not host or "." not in host:
        return 0.0, None
    tld = host.rsplit(".", 1)[-1]
    if tld in HIGH_ABUSE_TLDS:
        return 0.25, f"TLD '.{tld}' ka istemal phishing mein aam hai"
    return 0.0, None


def load_brands_from_file(path: str) -> list[Brand]:
    """Parse ``data/verified_domains.txt``-style files.

    Accepted line formats::

        hbl.com
        hbl.com.pk        # comment after whitespace
        HBL | hbl.com hbl.com.pk          # pipe = explicit brand grouping

    Bare domains are grouped by their second-level label, so ``hbl.com`` and
    ``hbl.com.pk`` become one brand called ``hbl``.
    """
    explicit: dict[str, set[str]] = {}
    grouped: dict[str, set[str]] = {}

    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "|" in stripped:
            name, _, rest = stripped.partition("|")
            name = name.strip()
            if not name:
                continue
            for domain in rest.split():
                domain = domain.split("#")[0].strip().lower()
                if domain:
                    explicit.setdefault(name, set()).add(domain)
            continue

        domain = stripped.split("#")[0].strip().lower()
        if not domain:
            continue
        _, registrable = split_registrable_domain(domain)
        if not registrable:
            continue
        key = registrable.split(".")[0]
        grouped.setdefault(key, set()).add(domain)

    brands: list[Brand] = [
        Brand(name=name, official_domains=frozenset(domains))
        for name, domains in explicit.items()
    ]
    explicit_domains = {d for b in brands for d in b.official_domains}
    for key, domains in grouped.items():
        remaining = domains - explicit_domains
        if remaining:
            brands.append(Brand(name=key.upper(), official_domains=frozenset(remaining)))
    return brands
