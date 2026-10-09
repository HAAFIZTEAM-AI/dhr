"""Tests for inbound WhatsApp payload parsing.

Fixtures mirror the real Cloud API shapes. The nesting matters: getting
``entry[0].changes[0].value.messages[0]`` wrong silently drops every message.
"""

from __future__ import annotations

import base64

import pytest

from whatsapp.inbound import (
    MAX_MEDIA_BYTES,
    InboundMessage,
    encode_media_base64,
    parse_webhook_payload,
    verify_challenge,
)


def _payload(message: dict) -> dict:
    """Wrap one message in the real Cloud API envelope."""
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WABA_ID",
                "changes": [
                    {
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "923001112222",
                                "phone_number_id": "PHONE_NUMBER_ID",
                            },
                            "contacts": [{"profile": {"name": "Ammi"}, "wa_id": message.get("from", "")}],
                            "messages": [message],
                        },
                        "field": "messages",
                    }
                ],
            }
        ],
    }


def _text(body: str, **extra) -> dict:
    return {
        "from": "923001234567",
        "id": "wamid.TEXT1",
        "timestamp": "1760000000",
        "type": "text",
        "text": {"body": body},
        **extra,
    }


class TestTextMessages:
    def test_forwarded_scam_text(self):
        """The dominant real-world path: a forwarded SMS."""
        msg = parse_webhook_payload(
            _payload(_text("FIA: arrest warrant issued. Call 03001234567 foran.", context={"forwarded": True}))
        )
        assert msg is not None
        assert msg.kind == "text"
        assert msg.from_forwarded is True
        assert "arrest warrant" in msg.text
        assert msg.sender == "923001234567"
        assert msg.message_id == "wamid.TEXT1"
        assert msg.is_analyzable is True
        assert msg.needs_media_download is False

    def test_typed_question_is_not_marked_forwarded(self):
        msg = parse_webhook_payload(_payload(_text("kya ye scam hai?")))
        assert msg.from_forwarded is False

    def test_frequently_forwarded_flag(self):
        """A viral forward is itself a weak scam signal and worth capturing."""
        msg = parse_webhook_payload(
            _payload(_text("Congrats! You won 5 lakh.", context={"frequently_forwarded": True}))
        )
        assert msg.from_forwarded is True

    def test_reply_to_our_message_carries_thread_id(self):
        """Follow-ups must thread back to the original verdict."""
        msg = parse_webhook_payload(
            _payload(_text("lekin ye meri beti ka number hai", context={"id": "wamid.OURS99"}))
        )
        assert msg.replied_to_id == "wamid.OURS99"

    def test_urdu_script_text_preserved(self):
        urdu = "یہ ایف آئی اے سے بات ہو رہی ہے، آپ کا وارنٹ جاری ہے"
        msg = parse_webhook_payload(_payload(_text(urdu)))
        assert msg.text == urdu

    def test_empty_body_text(self):
        msg = parse_webhook_payload(_payload(_text("")))
        assert msg is not None
        assert msg.text == ""


class TestMediaMessages:
    def test_image_screenshot_with_caption(self):
        payload = _payload(
            {
                "from": "923001234567",
                "id": "wamid.IMG1",
                "type": "image",
                "image": {"id": "MEDIA_ID_1", "mime_type": "image/jpeg", "caption": "ye dekho"},
            }
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "image"
        assert msg.media_id == "MEDIA_ID_1"
        assert msg.media_mime == "image/jpeg"
        assert msg.text == "ye dekho"
        assert msg.needs_media_download is True

    def test_voice_note(self):
        """Voice notes are the key path for low-literacy users and scam calls."""
        payload = _payload(
            {
                "from": "923001234567",
                "id": "wamid.AUD1",
                "type": "audio",
                "audio": {"id": "MEDIA_ID_2", "mime_type": "audio/ogg; codecs=opus", "voice": True},
            }
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "audio"
        assert msg.media_id == "MEDIA_ID_2"
        assert msg.needs_media_download is True

    def test_voice_type_alias(self):
        payload = _payload(
            {"from": "923001234567", "id": "wamid.V1", "type": "voice", "voice": {"id": "M3", "mime_type": "audio/ogg"}}
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "voice"
        assert msg.media_id == "M3"

    def test_document(self):
        payload = _payload(
            {
                "from": "923001234567",
                "id": "wamid.DOC1",
                "type": "document",
                "document": {"id": "M4", "mime_type": "application/pdf", "filename": "FIR_notice.pdf"},
            }
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "document"
        assert msg.needs_media_download is True

    def test_video(self):
        payload = _payload(
            {"from": "923001234567", "id": "wamid.VID1", "type": "video", "video": {"id": "M5", "mime_type": "video/mp4"}}
        )
        assert parse_webhook_payload(payload).kind == "video"

    def test_location_becomes_analyzable_text(self):
        """A meetup point proposed by a scammer; encoded as text so one path handles it."""
        payload = _payload(
            {
                "from": "923001234567",
                "id": "wamid.LOC1",
                "type": "location",
                "location": {"latitude": 24.8607, "longitude": 67.0011, "name": "Saddar", "address": "Karachi"},
            }
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "location"
        assert "Saddar" in msg.text
        assert "24.8607" in msg.text
        assert msg.is_analyzable is True
        assert msg.needs_media_download is False


class TestInteractiveMessages:
    def test_button_reply_carries_payload_not_title(self):
        """Our buttons echo a stable token so feedback needs no NLP."""
        payload = _payload(
            {
                "from": "923001234567",
                "id": "wamid.BTN1",
                "type": "interactive",
                "interactive": {"type": "button_reply", "button_reply": {"id": "WRONG", "title": "⚠️ Galat"}},
            }
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "button"
        assert msg.text == "WRONG"

    def test_legacy_button_type(self):
        payload = _payload(
            {
                "from": "923001234567",
                "id": "wamid.BTN2",
                "type": "button",
                "button": {"payload": "FAMILY", "text": "Ghar ko bhejein"},
            }
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "button"
        assert msg.text == "FAMILY"

    def test_button_is_not_marked_analyzable(self):
        msg = parse_webhook_payload(
            _payload(
                {
                    "from": "923001234567",
                    "id": "wamid.BTN3",
                    "type": "interactive",
                    "interactive": {"type": "button_reply", "button_reply": {"id": "HELP", "title": "Madad"}},
                }
            )
        )
        assert msg.is_analyzable is False


class TestNonMessages:
    def test_status_callback_returns_none(self):
        """Sent/delivered/read receipts arrive constantly and need no reply."""
        payload = {
            "entry": [
                {
                    "changes": [
                        {
                            "value": {
                                "metadata": {"phone_number_id": "PID"},
                                "statuses": [{"id": "wamid.X", "status": "delivered", "recipient_id": "923001234567"}],
                            }
                        }
                    ]
                }
            ]
        }
        assert parse_webhook_payload(payload) is None

    def test_empty_entry_returns_none(self):
        assert parse_webhook_payload({"entry": []}) is None

    def test_missing_entry_returns_none(self):
        assert parse_webhook_payload({"object": "whatsapp_business_account"}) is None

    def test_non_dict_payload_returns_none(self):
        assert parse_webhook_payload([]) is None  # type: ignore[arg-type]
        assert parse_webhook_payload(None) is None  # type: ignore[arg-type]

    def test_message_without_sender_returns_none(self):
        payload = _payload({"id": "wamid.X", "type": "text", "text": {"body": "hi"}})
        assert parse_webhook_payload(payload) is None

    def test_sticker_is_acknowledged_but_not_analyzable(self):
        payload = _payload(
            {"from": "923001234567", "id": "wamid.S1", "type": "sticker", "sticker": {"id": "M9", "mime_type": "image/webp"}}
        )
        msg = parse_webhook_payload(payload)
        assert msg.kind == "sticker"
        assert msg.is_analyzable is False

    def test_unknown_type_is_unsupported_not_an_error(self):
        payload = _payload({"from": "923001234567", "id": "wamid.U1", "type": "reaction", "reaction": {"emoji": "👍"}})
        msg = parse_webhook_payload(payload)
        assert msg.kind == "unsupported"


class TestNumberNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("923001234567", "923001234567"),
            ("+923001234567", "923001234567"),
            ("0300-1234567", "03001234567"),
            ("92 300 1234567", "923001234567"),
        ],
    )
    def test_digits_only(self, raw, expected):
        payload = _payload({"from": raw, "id": "wamid.N", "type": "text", "text": {"body": "x"}})
        assert parse_webhook_payload(payload).sender == expected


# Module level, not a class attribute: class-level names are not visible bare
# inside methods in Python, which silently broke every test in this class.
VERIFY_TOKEN = "verify_token_123"


class TestVerifyChallenge:
    def test_valid_handshake_echoes_challenge(self):
        result = verify_challenge(
            {"hub.mode": "subscribe", "hub.verify_token": VERIFY_TOKEN, "hub.challenge": "1234567890"}, VERIFY_TOKEN
        )
        assert result == "1234567890"

    def test_wrong_token_rejected(self):
        assert verify_challenge({"hub.mode": "subscribe", "hub.verify_token": "bad", "hub.challenge": "1"}, VERIFY_TOKEN) is None

    def test_wrong_mode_rejected(self):
        assert verify_challenge({"hub.mode": "unsubscribe", "hub.verify_token": VERIFY_TOKEN, "hub.challenge": "1"}, VERIFY_TOKEN) is None

    def test_missing_challenge_rejected(self):
        assert verify_challenge({"hub.mode": "subscribe", "hub.verify_token": VERIFY_TOKEN}, VERIFY_TOKEN) is None

    def test_unconfigured_token_rejects_everything(self):
        """Fail closed: an empty verify token must not accept all handshakes."""
        assert verify_challenge({"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "1"}, "") is None

    def test_attacker_cannot_supply_both_token_and_challenge(self):
        """If the server has no token configured, no handshake may ever succeed."""
        assert verify_challenge(
            {"hub.mode": "subscribe", "hub.verify_token": "anything", "hub.challenge": "9"}, ""
        ) is None


class TestMediaEncoding:
    def test_encodes_bytes(self):
        assert encode_media_base64(b"hello") == base64.b64encode(b"hello").decode("ascii")

    def test_rejects_oversized_media(self):
        """A 100 MB voice note would hang Whisper; bound it at the choke point."""
        with pytest.raises(ValueError, match="limit"):
            encode_media_base64(b"\x00" * (MAX_MEDIA_BYTES + 1))

    def test_accepts_exactly_at_limit(self):
        assert encode_media_base64(b"\x00" * MAX_MEDIA_BYTES)


class TestDataclassHelpers:
    def test_defaults(self):
        msg = InboundMessage(kind="text", message_id="w1", sender="923001234567")
        assert msg.text == ""
        assert msg.media_id is None
        assert msg.from_forwarded is False
        assert msg.replied_to_id is None
        assert msg.is_analyzable is True
        assert msg.needs_media_download is False

    def test_raw_is_excluded_from_repr(self):
        """Payloads can contain user data; keep them out of logs that print repr."""
        msg = InboundMessage(kind="text", message_id="w1", sender="923001234567", raw={"secret": "x"})
        assert "secret" not in repr(msg)
