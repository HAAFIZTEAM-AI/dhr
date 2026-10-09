"""Tests for WhatsApp webhook signature verification.

These are security tests. Every "blocked" case below is a forgery attempt against
a publicly reachable endpoint that triggers analysis and can inject alerts into
family groups.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from whatsapp.signature import SignatureError, compute_signature, verify_webhook_signature

SECRET = "test_app_secret_not_a_real_one"
BODY = b'{"object":"whatsapp_business_account","entry":[{"changes":[{"value":{"messages":[{"id":"wamid.1"}]}}]}]}'


def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class TestValidSignatures:
    def test_correct_signature_accepted(self):
        verify_webhook_signature(BODY, _sign(BODY), SECRET)

    def test_uppercase_hex_accepted(self):
        """Meta sends lowercase, but a proxy may upcase it; both must work."""
        verify_webhook_signature(BODY, _sign(BODY).upper().replace("SHA256", "sha256"), SECRET)

    def test_empty_body_with_correct_signature_accepted(self):
        empty = b""
        verify_webhook_signature(empty, _sign(empty), SECRET)

    def test_compute_signature_roundtrips(self):
        sig = compute_signature(BODY, SECRET)
        verify_webhook_signature(BODY, sig, SECRET)

    def test_unicode_body_signs_correctly(self):
        """Urdu text must survive encoding identically on both sides."""
        urdu = '{"text":"یہ فراڈ ہے"}'.encode("utf-8")
        verify_webhook_signature(urdu, _sign(urdu), SECRET)


class TestForgedSignatures:
    def test_missing_header_rejected(self):
        with pytest.raises(SignatureError, match="Missing"):
            verify_webhook_signature(BODY, None, SECRET)

    def test_empty_header_rejected(self):
        with pytest.raises(SignatureError, match="Missing"):
            verify_webhook_signature(BODY, "", SECRET)

    def test_wrong_secret_rejected(self):
        with pytest.raises(SignatureError, match="does not match"):
            verify_webhook_signature(BODY, _sign(BODY, "attacker_secret"), SECRET)

    def test_tampered_body_rejected(self):
        """Signature valid for the original body, but the body was altered."""
        sig = _sign(BODY)
        tampered = BODY.replace(b"wamid.1", b"wamid.2")
        with pytest.raises(SignatureError, match="does not match"):
            verify_webhook_signature(tampered, sig, SECRET)

    def test_missing_prefix_rejected(self):
        raw = hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest()
        with pytest.raises(SignatureError, match="not a sha256 digest"):
            verify_webhook_signature(BODY, raw, SECRET)

    def test_sha1_prefix_rejected(self):
        """sha1 is weaker and Meta does not send it for this header."""
        digest = hmac.new(SECRET.encode(), BODY, hashlib.sha1).hexdigest()
        with pytest.raises(SignatureError):
            verify_webhook_signature(BODY, f"sha1={digest}", SECRET)

    @pytest.mark.parametrize(
        "bad",
        ["sha256=", "sha256=xyz", "sha256=" + "0" * 63, "sha256=" + "g" * 64, "sha256=" + "0" * 65],
    )
    def test_malformed_digest_rejected(self, bad):
        with pytest.raises(SignatureError):
            verify_webhook_signature(BODY, bad, SECRET)

    def test_truncated_signature_rejected(self):
        """A short digest is malformed, so it is rejected before comparison."""
        with pytest.raises(SignatureError, match="not 64 hex characters"):
            verify_webhook_signature(BODY, _sign(BODY)[:40], SECRET)

    def test_full_length_but_wrong_digest_rejected(self):
        wrong = "sha256=" + ("0" * 64)
        with pytest.raises(SignatureError, match="does not match"):
            verify_webhook_signature(BODY, wrong, SECRET)


class TestFailClosed:
    """A misconfigured service must never accept everything."""

    def test_empty_secret_rejects_valid_looking_signature(self):
        with pytest.raises(SignatureError, match="not configured"):
            verify_webhook_signature(BODY, _sign(BODY, ""), "")

    def test_empty_secret_rejects_missing_header(self):
        with pytest.raises(SignatureError, match="not configured"):
            verify_webhook_signature(BODY, None, "")

    def test_compute_signature_requires_secret(self):
        with pytest.raises(SignatureError, match="not configured"):
            compute_signature(BODY, "")


class TestConstantTimeComparison:
    def test_uses_compare_digest_not_equality(self):
        """Guard against a refactor to ``==``, which leaks the digest by timing."""
        import inspect

        source = inspect.getsource(verify_webhook_signature)
        assert "compare_digest" in source
