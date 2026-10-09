"""WhatsApp Cloud API webhook signature verification.

WHY THIS FILE EXISTS
--------------------
The /webhook endpoint is publicly reachable -- Meta has to be able to POST to it
without authentication in the usual sense. Without signature verification,
anyone who discovers the URL can forge messages that HAAFIZ then analyzes and,
worse, that appear to come from a real user. An attacker could:

  * inject fake "scam detected" alerts into a Family Shield group (harassment,
    or worse: crying wolf until a real alert is ignored)
  * flood the analyzer to exhaust Whisper/playwright resources (DoS)
  * poison the crowdsourced threat registry with fake reports
  * exhaust WhatsApp API quota and get the number banned

Meta signs every webhook with HMAC-SHA256 over the raw request body, using the
app secret as the key, and sends the hex digest in ``X-Hub-Signature-256``.

Two details that are easy to get wrong and are handled here:
  1. Verification MUST run on the raw bytes. If a framework parses the JSON and
     you re-serialize it, key order and whitespace differ and every valid
     signature fails.
  2. Comparison MUST be constant-time. A byte-by-byte ``==`` leaks the digest
     through timing and allows an attacker to forge signatures incrementally.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["SignatureError", "verify_webhook_signature"]

_HEADER = "X-Hub-Signature-256"
_PREFIX = "sha256="


class SignatureError(ValueError):
    """Raised when a webhook request cannot be authenticated."""


def compute_signature(raw_body: bytes, app_secret: str) -> str:
    """Return the ``sha256=<hex>`` digest Meta would send for ``raw_body``.

    Exposed so tests and local development tooling can sign their own payloads.
    """
    if not app_secret:
        raise SignatureError("WHATSAPP_APP_SECRET is not configured")
    digest = hmac.new(app_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"{_PREFIX}{digest}"


def verify_webhook_signature(
    raw_body: bytes,
    signature_header: str | None,
    app_secret: str,
) -> None:
    """Verify Meta's signature, raising on any failure.

    Args:
        raw_body: the exact bytes received, unparsed.
        signature_header: value of the ``X-Hub-Signature-256`` header, or None.
        app_secret: the WhatsApp app secret.

    Raises:
        SignatureError: if the header is missing, malformed, or does not match.
            Callers must translate this into HTTP 401 -- never 500, which would
            tell an attacker the secret is misconfigured rather than wrong.
    """
    if not app_secret:
        # Fail closed. An unconfigured secret must not silently accept everything.
        raise SignatureError("WHATSAPP_APP_SECRET is not configured")

    if not signature_header:
        raise SignatureError(f"Missing {_HEADER} header")

    if not signature_header.startswith(_PREFIX):
        raise SignatureError("Signature header is not a sha256 digest")

    provided = signature_header[len(_PREFIX) :].strip().lower()
    if not provided or len(provided) != 64 or any(c not in "0123456789abcdef" for c in provided):
        raise SignatureError("Signature header is not 64 hex characters")

    expected = hmac.new(app_secret.encode("utf-8"), raw_body, hashlib.sha256).digest()

    try:
        provided_bytes = bytes.fromhex(provided)
    except ValueError as exc:  # pragma: no cover - guarded by the hex check above
        raise SignatureError("Signature header is not valid hex") from exc

    # Constant-time comparison. compare_digest accepts bytes and avoids the
    # short-circuit timing leak of the == operator.
    if not hmac.compare_digest(expected, provided_bytes):
        raise SignatureError("Signature does not match")
