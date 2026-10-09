"""Detect which language to answer a WhatsApp user in.

WHY THIS IS ITS OWN MODULE
--------------------------
The whole thesis of the WhatsApp channel is that a user forwards something and
gets an answer they can act on. If the answer arrives in the wrong language the
interaction fails completely -- and unlike a website, there is no language
selector to fall back on. Most HAAFIZ users will never visit the web app.

Detection order, cheapest and most reliable first:
  1. **Remembered preference.** If this number previously chose a language (by
     sending ``LANG UR`` or tapping a button), use it. This always wins -- an
     explicit choice beats any guess.
  2. **Script detection.** Arabic script => Urdu; Devanagari => Hindi; Gurmukhi
     => Punjabi. Unambiguous and free.
  3. **Marker words.** Roman Urdu vs English vs Roman Sindhi vs Roman Pashto are
     all latin script, so we look for function words that are near-impossible to
     confuse.
  4. **Default to Roman Urdu.** Not Urdu script -- Roman Urdu is what Pakistanis
     actually type on phones, and it is legible to Urdu, Punjabi and Sindhi
     readers alike. Falling back to English would exclude the majority of the
     target audience.

Important caveat: Sindhi, Punjabi (Shahmukhi) and Balochi all use Arabic script,
so script detection alone maps them to Urdu. That is an acceptable default --
Urdu is widely understood across Pakistan and the verdict is still actionable --
but it is why step 1 (remembered preference) matters so much, and why the menu
offers an explicit language switch.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable

__all__ = ["SUPPORTED_REPLY_LANGS", "detect_language", "resolve_language"]

#: Languages HAAFIZ can answer in. Must stay in sync with
#: ``haafiz.verdict.render.SUPPORTED_LANGS``.
SUPPORTED_REPLY_LANGS: tuple[str, ...] = ("roman", "urdu", "en", "sd", "pa", "ps", "bal")

#: Accepted spellings users may type after the LANG command.
_LANG_ALIASES: dict[str, str] = {
    "roman": "roman",
    "roman urdu": "roman",
    "romanurdu": "roman",
    "r urdu": "roman",
    "ur": "urdu",
    "urdu": "urdu",
    "اردو": "urdu",
    "en": "en",
    "eng": "en",
    "english": "en",
    "sd": "sd",
    "sindhi": "sd",
    "سنڌي": "sd",
    "pa": "pa",
    "punjabi": "pa",
    "panjabi": "pa",
    "ਪੰਜਾਬੀ": "pa",
    "ps": "ps",
    "pus": "ps",
    "pashto": "ps",
    "pushto": "ps",
    "پښتو": "ps",
    "bal": "bal",
    "balochi": "bal",
    "brahui": "bal",
    "بروہی": "bal",
}

# Roman Urdu function words. Chosen because they are extremely unlikely in
# English text and are grammatical glue rather than content words -- a scam
# message will not avoid them.
_ROMAN_URDU_MARKERS: tuple[str, ...] = (
    " hai", " hain", " tha", " thi", " ho", " kya", " kyun", " nahi", " nahin",
    " mein", " ap ", " aap", " tum", " tumhara", " mera", " meri", " hum ",
    " karo", " karein", " kiya", " bhejo", " bhejein", " batao", " bataein",
    " foran", " abhi", " turant", " jaldi", " paisay", " paise", " paisa",
    " number", " wala", " wali", " ka ", " ki ", " ke ", " se ", " ko ",
    " ne ", " par ", " tak", " agar", " to ", " ya ", " aur ", " magar",
    " lekin", " koi", " kuch", " sab", " zaroori", " zarorat", " madad",
    " please", " shukriya", " salam", " assalam",
)

_ROMAN_SINDHI_MARKERS: tuple[str, ...] = (
    " aahin", " aahe", " aahey", " thiyan", " chha", " kite", " kayo",
    " monikho", " tawhanjo", " asa", " wari", " je ", " jo ", " khe ",
    " na ", " ditta", " kando", " thiyo", " hiyo",
)

_ROMAN_PASHTO_MARKERS: tuple[str, ...] = (
    " zama", " sta ", " da ", " che ", " ye ", " shi ", " kawi", " wai",
    " na ", " de ", " ke ", " sara", " lara", " wakړ", " zmonz", " tar ",
    " pa ", " ra", " wu ", " kray ", " krra",
)

_ROMAN_PUNJABI_MARKERS: tuple[str, ...] = (
    " tenu", " mainu", " assi", " tusi", " hor ", " da ", " di ", " de ",
    " kita", " kitta", " si ", " naal", " layi", " kol ", " vekh", " dass",
    " ehna", " ohna", " jaan", " ve ", " ji ",
)

# Explicit commands the bot understands. Kept tiny on purpose: a non-technical
# user will not read a manual, so the language menu is offered as tappable
# buttons rather than as commands to memorise.
_LANG_COMMAND = re.compile(r"^\s*lang(?:uage)?\s*[:\-]?\s*(.+?)\s*$", re.IGNORECASE)


# Arabic-script languages of Pakistan share most of their alphabet, so
# first-match detection is unreliable. We score by counting letters that are
# *distinctive* to one language and pick the winner, defaulting to Urdu on a tie
# (Urdu is the most widely understood across Pakistan).
#
# Critically, these sets must EXCLUDE characters Urdu itself uses heavily:
#   * ھ  (U+06BE heh doachashmee) -- Urdu aspiration: کہنا, دھوکہ, بہت, چاہیے
#   * ٿ  (U+067F)                  -- Urdu: تھک, تھپڑ
#   * ک  (U+06A9)                  -- this IS the Urdu kaf
#   * ئ  (U+0626)                  -- Urdu: کسی ئی,部份ی
# Including ھ was a real bug: it made ordinary Urdu text ("دھوکہ") detect as
# Sindhi, which would have replied to Urdu speakers in the wrong language.
_SINDHI_SPECIFIC = frozenset(
    "ڪڱڻڃڇڊڌڍڏٺٽ"  # Sindhi implosives and retroflexes
)
_PASHTO_SPECIFIC = frozenset(
    "ټځڅډړږښګڼۍې"  # Pashto retroflexes and distinctive ye forms
)
# ڳ (U+06B3), ڄ (U+0684) and ڀ (U+0680) are shared by Sindhi and Punjabi
# Shahmukhi, so they score for both rather than deciding between them.
_SHARED_SINDHI_PUNJABI = frozenset("ڳڄڀ")
_PUNJABI_SPECIFIC = frozenset("ٻݙڵ")  # Shahmukhi-only letters

# Shahmukhi Punjabi and Urdu share almost their entire alphabet, so many Punjabi
# sentences contain no distinctive letter at all ("ایہہ فراڈ اے، کسے نوں نہ دسو"
# is orthographically almost identical to Urdu). For that ambiguous case we fall
# back to function words that differ between the two.
#
# These are deliberately possessive/auxiliary markers, not content words:
#   دا دی دے  = Punjabi "of"      (Urdu writes کا کی کے)
#   وی        = Punjabi "also"    (Urdu writes بھی)
#   سی        = Punjabi "was"     (Urdu writes تھا)
#   ایہہ اوہ  = Punjabi "this/that" (Urdu writes یہ وہ)
#   نئیں      = Punjabi "no"      (Urdu writes نہیں)
# Only consulted when letter scoring produces no winner, so they cannot
# override an unambiguous Sindhi or Pashto text.
_PUNJABI_MARKERS: tuple[str, ...] = (
    " ایہہ", "ایہہ ", " اوہ", "اوہ ", " وی ", " سی ", " نئیں", "نئیں ",
    " دا ", "دی ", " دے ", " تیں ", " کریں ", " لئی ", " کول ", " ویکھ",
)


def _score_scripts(text: str) -> dict[str, int]:
    """Count distinctive Arabic-script letters per language."""
    chars = set(text)
    shared = len(chars & _SHARED_SINDHI_PUNJABI)
    return {
        "sd": len(chars & _SINDHI_SPECIFIC) + shared,
        "ps": len(chars & _PASHTO_SPECIFIC),
        "pa": len(chars & _PUNJABI_SPECIFIC) + shared,
        "urdu": 0,  # default; wins ties
    }


def _shahmukhi_marker_hits(text: str) -> int:
    """Count Punjabi-only function words, used only to break Urdu/Punjabi ties."""
    # Normalized outside the f-string: Python 3.11 forbids backslashes inside
    # f-string expressions, and the markers themselves contain significant spaces
    # that must line up with the normalized text.
    normalized = re.sub(r"\s+", " ", text)
    padded = f" {normalized} "
    return sum(1 for marker in _PUNJABI_MARKERS if marker in padded)


def _has_script(text: str, start: int, end: int) -> bool:
    return any(start <= ord(ch) <= end for ch in text)


def _count_markers(text: str, markers: Iterable[str]) -> int:
    lowered = f" {text.lower()} "
    return sum(1 for m in markers if m in lowered)


def parse_language_command(text: str) -> str | None:
    """If ``text`` is a language command, return the resolved language code.

    >>> parse_language_command("LANG UR")
    'urdu'
    >>> parse_language_command("lang: english")
    'en'
    >>> parse_language_command("ye scam hai kya") is None
    True
    """
    if not text:
        return None
    match = _LANG_COMMAND.match(text.strip())
    if not match:
        return None
    candidate = match.group(1).strip().lower()
    return _LANG_ALIASES.get(candidate)


def detect_language(text: str) -> str:
    """Infer the best reply language from a message body.

    Args:
        text: the inbound text, caption, or transcript.

    Returns:
        One of :data:`SUPPORTED_REPLY_LANGS`. Never raises; empty input returns
        the default (Roman Urdu).
    """
    if not text or not text.strip():
        return "roman"

    # An explicit command always wins.
    commanded = parse_language_command(text)
    if commanded:
        return commanded

    # --- Script detection -------------------------------------------------
    # Arabic script, including the extended blocks used by Sindhi/Pashto/Shahmukhi.
    if (
        _has_script(text, 0x0600, 0x06FF)
        or _has_script(text, 0x0750, 0x077F)
        or _has_script(text, 0xFB50, 0xFDFF)
    ):
        scores = _score_scripts(text)
        best = max(scores, key=lambda lang: (scores[lang], lang == "urdu"))
        if scores[best] > 0:
            return best

        # No distinctive letter at all. This is the Urdu/Shahmukhi ambiguity:
        # the two share nearly their whole alphabet, so a Punjabi sentence can be
        # orthographically identical to Urdu. Break the tie on function words
        # before falling back to Urdu.
        if _shahmukhi_marker_hits(text) >= 2:
            return "pa"

        # Urdu is the correct default: it is the most widely understood written
        # language across Pakistan, and a Shahmukhi reader can still act on it.
        return "urdu"

    # Gurmukhi => Punjabi (Shahmukhi is handled above).
    if _has_script(text, 0x0A00, 0x0A7F):
        return "pa"

    # Devanagari => Hindi, which we answer in Roman Urdu (closest readable
    # fallback and the language most Indian-origin scam templates in Pakistan
    # are actually written in).
    if _has_script(text, 0x0900, 0x097F):
        return "roman"

    # --- Latin script: marker-word scoring -------------------------------
    scores = {
        "roman": _count_markers(text, _ROMAN_URDU_MARKERS),
        "sd": _count_markers(text, _ROMAN_SINDHI_MARKERS),
        "ps": _count_markers(text, _ROMAN_PASHTO_MARKERS),
        "pa": _count_markers(text, _ROMAN_PUNJABI_MARKERS),
    }

    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        # No South Asian markers at all. If the text is substantial and purely
        # ASCII, treat it as English -- OCR'd English scam SMS is common.
        if re.search(r"[a-zA-Z]{4}", text):
            return "en"
        return "roman"
    return best


def resolve_language(
    text: str,
    sender: str,
    preference_lookup: Callable[[str], str | None] | None = None,
) -> tuple[str, bool]:
    """Choose the reply language, honoring any stored preference.

    Args:
        text: the inbound message text.
        sender: the user's phone number (the identity key -- there is no login).
        preference_lookup: optional callable returning a stored language code for
            this sender, or None if unknown. Injected so this module stays free
            of storage dependencies and is trivially testable.

    Returns:
        ``(language_code, was_explicit)``. ``was_explicit`` is True when the user
        issued a LANG command, which tells the caller to persist the choice.
    """
    commanded = parse_language_command(text or "")
    if commanded:
        return commanded, True

    if preference_lookup is not None and sender:
        stored = preference_lookup(sender)
        if stored:
            normalized = _LANG_ALIASES.get(stored.strip().lower())
            if normalized:
                return normalized, False

    return detect_language(text or ""), False
