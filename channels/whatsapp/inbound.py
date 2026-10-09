"""Parse inbound WhatsApp Cloud API webhook payloads.

Meta's payload shape is deeply nested and varies by message type. This module
turns it into one flat :class:`InboundMessage` so the handler code never has to
know about ``entry[0].changes[0].value.messages[0]``.

Supported inbound types, in priority order for the product:
  * ``text``            -- a forwarded SMS, or a typed description
  * ``image``           -- a screenshot of a message or a fake bank app
  * ``audio`` / ``voice``-- a voice note, or a recording of a scam call
  * ``document``        -- a PDF "notice" or forged FIR
  * ``video``           -- recorded video-call fraud
  * ``location``        -- a meetup point proposed by a scammer
  * ``button`` / ``interactive`` -- the user tapped one of our reply buttons
                               (e.g. "GALAT" feedback, "FAMILY KO BHEJEIN")
  * ``sticker``         -- ignored, but acknowledged so the user is not left
                           staring at nothing

Anything unrecognised yields ``kind="unsupported"`` rather than raising: the
webhook must always return 200 to Meta quickly, and must always reply to the
user with *something*.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any

__all__ = ["InboundMessage", "parse_webhook_payload", "verify_challenge"]

#: Message kinds we can actually analyze.
_ANALYZABLE = frozenset({"text", "image", "audio", "voice", "document", "video", "location"})

#: Maximum inbound bytes we will accept. WhatsApp media can be up to 100 MB, but
#: Whisper transcription and OCR on that scale is a denial-of-service vector, and
#: a scam SMS screenshot is never larger than a few hundred KB.
MAX_MEDIA_BYTES = 5 * 1024 * 1024


@dataclass
class InboundMessage:
    """One normalized inbound message.

    Attributes:
        kind: text / image / audio / voice / document / video / location /
            button / sticker / unsupported.
        message_id: Meta's ``wamid``, unique and stable across retries. Used as
            the idempotency key.
        sender: the user's phone number in international format, digits only
            (e.g. ``923001234567``). This is HAAFIZ's only stable identifier for
            a user -- there is no login.
        text: text body, caption, or button reply payload, whichever applies.
        media_id: Meta media ID, needed to download image/audio/document bytes.
        media_mime: MIME type of the media, when known.
        from_forwarded: True if the user forwarded rather than typed it. This is
            the dominant path and is worth measuring.
        replied_to_id: if the user replied to one of OUR messages, the wamid of
            that message -- lets us thread follow-ups ("lekin ye meri beti ka
            number hai?") to the original verdict.
        raw: the original payload, for logging and debugging only.
    """

    kind: str
    message_id: str
    sender: str
    text: str = ""
    media_id: str | None = None
    media_mime: str | None = None
    from_forwarded: bool = False
    replied_to_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def is_analyzable(self) -> bool:
        return self.kind in _ANALYZABLE

    @property
    def needs_media_download(self) -> bool:
        return self.kind in {"image", "audio", "voice", "document", "video"} and bool(self.media_id)


def verify_challenge(params: dict[str, str], verify_token: str) -> str | None:
    """Handle Meta's one-time webhook subscription handshake.

    Meta GETs the webhook with ``hub.mode=subscribe``, ``hub.verify_token`` and
    ``hub.challenge``. We must echo the challenge back **as plain text, not JSON**
    -- returning JSON here is the single most common reason webhook setup fails.

    Args:
        params: the query string parameters.
        verify_token: our configured ``WHATSAPP_VERIFY_TOKEN``.

    Returns:
        The challenge string to echo, or None if the request is not a valid
        handshake.
    """
    mode = params.get("hub.mode")
    token = params.get("hub.verify_token")
    challenge = params.get("hub.challenge")

    if mode != "subscribe" or not challenge:
        return None
    if not verify_token:
        return None
    if token != verify_token:
        return None
    return challenge


def _first_message(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Extract the first message object and the receiving WABA phone number ID.

    Returns:
        ``(message_dict_or_None, phone_number_id)``.
    """
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            value = change.get("value") or {}
            phone_number_id = value.get("metadata", {}).get("phone_number_id")
            messages = value.get("messages") or []
            if messages:
                return messages[0], phone_number_id
            # A status callback (sent/delivered/read) with no messages. Not an
            # error -- Meta sends these for every outbound message.
            return None, phone_number_id
    return None, None


def parse_webhook_payload(payload: dict[str, Any]) -> InboundMessage | None:
    """Normalize a WhatsApp webhook payload.

    Args:
        payload: the decoded JSON body.

    Returns:
        An :class:`InboundMessage`, or ``None`` if the payload contains no user
        message (e.g. a delivery-status callback). Returning None is the correct
        signal for "acknowledge with 200 and do nothing" -- it is not an error.
    """
    if not isinstance(payload, dict):
        return None

    message, _phone_number_id = _first_message(payload)
    if not message:
        return None

    message_id = str(message.get("id") or "")
    sender = _normalize_number(message.get("from"))
    if not sender:
        return None

    context = message.get("context") or {}
    replied_to = context.get("id") or None
    forwarded = bool(context.get("forwarded")) or bool(context.get("frequently_forwarded"))

    kind, text, media_id, mime = _extract_body(message)

    return InboundMessage(
        kind=kind,
        message_id=message_id,
        sender=sender,
        text=text,
        media_id=media_id,
        media_mime=mime,
        from_forwarded=forwarded,
        replied_to_id=replied_to,
        raw=message,
    )


def _normalize_number(raw: Any) -> str:
    """WhatsApp sends numbers as ``923001234567``; normalize to digits only."""
    if raw is None:
        return ""
    return "".join(ch for ch in str(raw) if ch.isdigit())


def _extract_body(message: dict[str, Any]) -> tuple[str, str, str | None, str | None]:
    """Return ``(kind, text, media_id, mime)`` for any message type."""
    # Interactive replies (buttons / lists) come as type "interactive" or
    # "button". Our reply buttons carry the finding ID as the button id so we
    # can route feedback without any natural-language parsing.
    if message.get("type") in ("interactive", "button"):
        interactive = message.get("interactive") or {}
        if interactive.get("type") == "button_reply":
            reply = interactive.get("button_reply") or {}
            # NOTE: the Cloud API field for a button's developer-supplied value
            # is ``id``, not ``payload``. ``payload`` is accepted too because some
            # SDKs and older docs use that name, and because guessing wrong here
            # silently routes every feedback tap to the wrong handler.
            identifier = reply.get("id") or reply.get("payload") or ""
            title = str(reply.get("title") or "")
            return "button", str(identifier) or title, None, None
        if interactive.get("type") == "list_reply":
            list_reply = interactive.get("list_reply") or {}
            identifier = list_reply.get("id") or list_reply.get("payload") or ""
            return "button", str(identifier) or str(list_reply.get("title") or ""), None, None
        button = message.get("button") or {}
        return "button", str(button.get("payload") or button.get("text") or ""), None, None

    for kind in ("text", "image", "audio", "voice", "document", "video", "location", "sticker"):
        body = message.get(kind)
        if not isinstance(body, dict):
            continue

        if kind == "text":
            return "text", str(body.get("body") or ""), None, None

        if kind == "location":
            lat, lon = body.get("latitude"), body.get("longitude")
            name = body.get("name") or ""
            address = body.get("address") or ""
            # Encode the location as text so the same analyzer path handles it.
            text = f"{name} {address} {lat},{lon}".strip()
            return "location", text, None, None

        if kind == "sticker":
            return "sticker", "", body.get("id"), body.get("mime_type")

        # image / audio / voice / document / video all carry id + mime_type, and
        # an optional caption.
        caption = str(body.get("caption") or "")
        return kind, caption, body.get("id"), body.get("mime_type")

    return "unsupported", "", None, None


def encode_media_base64(media_bytes: bytes) -> str:
    """Encode downloaded media for the analyzers, which expect base64.

    Raises:
        ValueError: if the media exceeds :data:`MAX_MEDIA_BYTES`. Checked here as
            a single choke point rather than at each call site.
    """
    if len(media_bytes) > MAX_MEDIA_BYTES:
        raise ValueError(
            f"Media is {len(media_bytes)} bytes; the limit is {MAX_MEDIA_BYTES} bytes"
        )
    try:
        return base64.b64encode(media_bytes).decode("ascii")
    except (binascii.Error, UnicodeDecodeError) as exc:  # pragma: no cover
        raise ValueError("Media could not be encoded") from exc
