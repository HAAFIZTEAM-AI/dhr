"""WhatsApp Cloud API client.

Everything HAAFIZ *sends* goes through here. Deliberately small and dependency-
light so it is easy to audit -- this is the code that talks to real users who may
be about to lose money, and a silent failure here means a victim gets no warning.

Two constraints shape the design:

1. **The 24-hour customer service window.** A user-initiated conversation opens a
   free-form reply window for 24 hours. Outside it, only pre-approved template
   messages can be sent. Our flow is always user-initiated (they forward
   something), so free-form text is the normal path -- which matters, because
   templates must be pre-approved and cannot carry a dynamic verdict.

2. **Every reply must be attempted even if analysis fails.** A user who forwards
   a message and gets silence will conclude the service is broken and never come
   back. ``send_text`` failures are logged and surfaced, never swallowed.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

__all__ = ["WhatsAppGraphError", "WhatsAppClient"]

logger = logging.getLogger("haafiz.whatsapp")

GRAPH_BASE = "https://graph.facebook.com/v21.0"

#: Verdicts must be fast. A user waiting on a scam check is anxious; a 30-second
#: hang feels like failure. Media download is separately bounded because voice
#: notes are larger.
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=10.0, pool=5.0)
MEDIA_TIMEOUT = httpx.Timeout(connect=5.0, read=45.0, write=10.0, pool=5.0)


class WhatsAppGraphError(RuntimeError):
    """Raised when the Graph API rejects a call."""

    def __init__(self, message: str, *, status_code: int | None = None, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class WhatsAppClient:
    """Thin, typed wrapper over the WhatsApp Cloud API.

    Args:
        phone_number_id: the WABA phone number ID (not the public number).
        access_token: permanent system-user token. A 24-hour test token will
            silently break in production -- this is the most common Cloud API
            mistake and worth stating explicitly.
        base_url: override for tests.
    """

    def __init__(
        self,
        phone_number_id: str,
        access_token: str,
        *,
        base_url: str = GRAPH_BASE,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not phone_number_id:
            raise ValueError("WHATSAPP_PHONE_NUMBER_ID is required")
        if not access_token:
            raise ValueError("WHATSAPP_ACCESS_TOKEN is required")
        self._phone_number_id = phone_number_id
        self._token = access_token
        self._base = base_url.rstrip("/")
        self._transport = transport

    @property
    def _messages_url(self) -> str:
        return f"{self._base}/{self._phone_number_id}/messages"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    async def send_text(self, to: str, body: str, *, preview_url: bool = False) -> dict[str, Any]:
        """Send a free-form text message.

        Args:
            to: recipient in international format, digits only (``923001234567``).
            body: message text. WhatsApp supports a small markdown subset
                (``*bold*``, ``_italic_``, ``~strike~``) which the verdict
                renderer already uses.
            preview_url: whether to unfurl links. Kept off by default: we do not
                want HAAFIZ accidentally rendering a phishing preview inside the
                very conversation warning the user about that phishing page.

        Returns:
            The Graph API response body.

        Raises:
            WhatsAppGraphError: on HTTP or API-level failure.
        """
        if not to:
            raise ValueError("recipient is required")
        # WhatsApp rejects empty bodies with an opaque error; fail loudly here.
        if not body or not body.strip():
            raise ValueError("message body is required")
        # 4096 characters is the documented hard limit. A long OCR'd verdict can
        # exceed it, and a truncated send fails entirely rather than partially.
        if len(body) > 4096:
            body = body[:4090] + " [...]"

        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "text",
            "text": {"preview_url": preview_url, "body": body},
        }
        return await self._post(payload)

    async def send_audio_reply(self, to: str, media_id: str) -> dict[str, Any]:
        """Send a voice note by uploaded media ID.

        This is what makes the service usable for someone who cannot read: the
        verdict is *spoken* back. Pair with ``send_text`` so the written version
        is still there for a family member who checks the phone later.
        """
        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "audio",
            "audio": {"id": media_id},
        }
        return await self._post(payload)

    async def send_reply_buttons(self, to: str, body: str, buttons: list[tuple[str, str]]) -> dict[str, Any]:
        """Send an interactive message with up to three reply buttons.

        Buttons matter more than they look: they remove typing entirely. A user
        who cannot spell can still tap "GALAT" to report a wrong verdict, which
        is how we collect the training labels the model moat depends on.

        Args:
            buttons: ``(payload_id, label)`` pairs, max 3. The payload is echoed
                back to us as the inbound ``button`` message, so it should be a
                short stable token, not human text.
        """
        if len(buttons) > 3:
            raise ValueError("WhatsApp allows at most 3 reply buttons")
        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": {"text": body},
                "action": {
                    "buttons": [
                        {"type": "reply", "reply": {"id": pid, "title": label[:20]}}
                        for pid, label in buttons
                    ]
                },
            },
        }
        return await self._post(payload)

    async def send_template(self, to: str, template_name: str, language_code: str, body_params: list[str]) -> dict[str, Any]:
        """Send a pre-approved template message.

        Only usable outside the 24-hour window. Templates must be approved in
        Meta Business Manager in advance, which is why the primary verdict flow
        never depends on them.
        """
        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "template",
            "template": {
                "name": template_name,
                "language": {"code": language_code},
                "components": [
                    {"type": "body", "parameters": [{"type": "text", "text": p} for p in body_params]}
                ],
            },
        }
        return await self._post(payload)

    async def download_media(self, media_id: str) -> bytes:
        """Download inbound media by ID.

        Meta requires a two-step fetch: resolve the ID to a URL, then GET that URL
        with the token. The URL is short-lived.

        Raises:
            WhatsAppGraphError: on failure.
        """
        async with httpx.AsyncClient(timeout=MEDIA_TIMEOUT, transport=self._transport) as client:
            lookup = await client.get(
                f"{self._base}/{media_id}",
                headers={"Authorization": f"Bearer {self._token}"},
            )
            if lookup.status_code >= 400:
                raise WhatsAppGraphError(
                    f"Media lookup failed for {media_id}",
                    status_code=lookup.status_code,
                    payload=_safe_json(lookup),
                )
            url = (_safe_json(lookup) or {}).get("url")
            if not url:
                raise WhatsAppGraphError(f"Media lookup returned no URL for {media_id}")

            fetched = await client.get(url, headers={"Authorization": f"Bearer {self._token}"})
            if fetched.status_code >= 400:
                raise WhatsAppGraphError(
                    f"Media download failed for {media_id}",
                    status_code=fetched.status_code,
                )
            return fetched.content

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, transport=self._transport) as client:
            try:
                response = await client.post(self._messages_url, headers=self._headers(), json=payload)
            except httpx.HTTPError as exc:
                # Network failure. Do not retry here: the webhook handler owns
                # retry policy, and retrying inside a request handler turns a
                # slow dependency into a hung worker.
                raise WhatsAppGraphError(f"Graph API request failed: {exc}") from exc

        if response.status_code >= 400:
            body = _safe_json(response)
            error = (body or {}).get("error", {})
            raise WhatsAppGraphError(
                error.get("message") or f"Graph API returned {response.status_code}",
                status_code=response.status_code,
                payload=body,
            )
        return _safe_json(response) or {}


def _safe_json(response: httpx.Response) -> dict[str, Any] | None:
    try:
        data = response.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
