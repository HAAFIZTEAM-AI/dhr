"""HAAFIZ WhatsApp channel — the zero-friction front door.

WHY THIS SERVICE IS THE CENTRE OF THE PRODUCT
---------------------------------------------
See ``docs/BLUEPRINT.md``. In short: 52% of Pakistanis live under mobile-broadband
coverage and choose not to use it, citing affordability, literacy and trust — while
WhatsApp is the country's second-largest primary information source (19.9%). The
population has not rejected digital communication; it has rejected websites, apps,
forms and typing.

So HAAFIZ must not be a destination. It must be a contact:

    user receives something suspicious
      -> taps Forward -> picks HAAFIZ -> sends
      <- verdict in their language, in seconds, with what to do next

No install. No account. No typing. No percentage to interpret.

REQUEST FLOW
------------
1. Verify ``X-Hub-Signature-256`` (see ``signature.py``) — the endpoint is public,
   so without this anyone can forge messages.
2. De-duplicate on ``wamid`` (see ``dedupe.py``) — Meta retries webhooks.
3. Reply ``200`` to Meta *before* doing slow work. Meta's timeout is short and a
   slow analyzer must not cause a retry storm.
4. Analyze, render the verdict in the user's language, and send it.

Step 3/4 ordering is the reason analysis runs in a background task rather than
inline. It is also why failures in step 4 still attempt to send *something* to the
user: silence reads as a broken product.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Query, Request, Response
from fastapi.responses import PlainTextResponse

from .dedupe import InMemoryDedupe, MessageDedupe
from .graph_client import WhatsAppClient, WhatsAppGraphError
from .inbound import InboundMessage, encode_media_base64, parse_webhook_payload, verify_challenge
from .language import resolve_language
from .signature import SignatureError, verify_webhook_signature

logger = logging.getLogger("haafiz.whatsapp")

__all__ = ["create_app"]


class ConfigError(RuntimeError):
    """Raised when the service is misconfigured.

    Fail loudly at startup. A WhatsApp channel with a missing app secret must not
    boot and silently accept unsigned webhooks.
    """


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required but is not set")
    return value


#: Reply buttons. Payloads are short stable tokens echoed back to us, so routing
#: feedback needs no natural-language parsing. Labels are capped at 20 characters
#: by WhatsApp, which is why they are terse.
_BUTTONS_FEEDBACK: list[tuple[str, str]] = [
    ("CORRECT", "✅ Theek hai"),
    ("WRONG", "⚠️ Galat"),
    ("FAMILY", "👨‍👩‍👧 Ghar ko bhejein"),
]

_BUTTONS_MENU: list[tuple[str, str]] = [
    ("HELP", "❓ Madad"),
    ("LANG", "🌐 Zubaan"),
    ("FAMILY", "👨‍👩‍👧 Family Shield"),
]

_WELCOME = {
    "roman": (
        "Assalam-o-alaikum! Main HAAFIZ hoon.\n\n"
        "Koi bhi shakkī message, SMS, link, tasveer ya voice note yahan *forward* kar dein — "
        "main 3 second mein bata doon ga ke wo scam hai ya nahi.\n\n"
        "Koi app install karne ki zaroorat nahi. Koi account nahi. Bas forward karein."
    ),
    "urdu": (
        "السلام علیکم! میں حافظ ہوں۔\n\n"
        "کوئی بھی مشکوک پیغام، ایس ایم ایس، لنک، تصویر یا وائس نوٹ یہاں *فارورڈ* کر دیں — "
        "میں 3 سیکنڈ میں بتا دوں گا کہ وہ دھوکہ دہی ہے یا نہیں۔\n\n"
        "کوئی ایپ انسٹال کرنے کی ضرورت نہیں۔ کوئی اکاؤنٹ نہیں۔ بس فارورڈ کریں۔"
    ),
    "en": (
        "Assalam-o-alaikum! I am HAAFIZ.\n\n"
        "*Forward* any suspicious message, SMS, link, image or voice note here — "
        "I will tell you within 3 seconds whether it is a scam.\n\n"
        "No app to install. No account needed. Just forward it."
    ),
}


def create_app(
    *,
    app_secret: str | None = None,
    verify_token: str | None = None,
    phone_number_id: str | None = None,
    access_token: str | None = None,
    analyzer: Any = None,
    dedupe: MessageDedupe | None = None,
    preference_store: dict[str, str] | None = None,
) -> FastAPI:
    """Build the WhatsApp webhook app.

    Every collaborator is injectable so the whole request path is testable without
    network access or Meta credentials.

    Args:
        app_secret: WhatsApp app secret for signature verification.
        verify_token: token for the subscription handshake.
        phone_number_id: WABA phone number ID.
        access_token: permanent system-user token.
        analyzer: callable ``async (kind, payload) -> verdict dict``. Defaults to
            the AI service's HTTP API.
        dedupe: idempotency backend.
        preference_store: mutable mapping of sender -> language code. In production
            this is backed by the database; the dict default keeps tests simple.
    """
    secret = app_secret if app_secret is not None else os.environ.get("WHATSAPP_APP_SECRET", "")
    token = verify_token if verify_token is not None else os.environ.get("WHATSAPP_VERIFY_TOKEN", "")
    number_id = phone_number_id or os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "")
    api_token = access_token or os.environ.get("WHATSAPP_ACCESS_TOKEN", "")

    client: WhatsAppClient | None = None
    if number_id and api_token:
        client = WhatsAppClient(number_id, api_token)

    store: dict[str, str] = preference_store if preference_store is not None else {}
    dedupe_backend = dedupe or InMemoryDedupe()

    fastapi_app = FastAPI(
        title="HAAFIZ WhatsApp Channel",
        description="Zero-friction scam detection over WhatsApp. Forward anything, get a verdict.",
        version="6.0.0",
    )

    # ---- Webhook subscription handshake ---------------------------------
    @fastapi_app.get("/webhook")
    async def webhook_verify(
        request: Request,
        **_: Any,
    ) -> Response:
        params = dict(request.query_params)
        challenge = verify_challenge(params, token)
        if challenge is None:
            # 403, not 400: Meta treats 400 as a configuration error worth
            # retrying, and this endpoint is a credential check.
            return PlainTextResponse("Forbidden", status_code=403)
        # MUST be plain text. Returning JSON here is the single most common
        # reason webhook setup fails.
        return PlainTextResponse(challenge)

    # ---- Inbound messages ------------------------------------------------
    @fastapi_app.post("/webhook")
    async def webhook_receive(request: Request, background: BackgroundTasks) -> Response:
        raw_body = await request.body()

        try:
            verify_webhook_signature(raw_body, request.headers.get("X-Hub-Signature-256"), secret)
        except SignatureError as exc:
            logger.warning("Rejected unsigned webhook: %s", exc)
            return PlainTextResponse("Unauthorized", status_code=401)

        try:
            import json

            payload = json.loads(raw_body)
        except ValueError:
            logger.warning("Webhook body was not valid JSON")
            return PlainTextResponse("Bad Request", status_code=400)

        message = parse_webhook_payload(payload)

        # Status callbacks (sent/delivered/read) arrive constantly and need no
        # reply. Acknowledge and move on.
        if message is None:
            return PlainTextResponse("OK", status_code=200)

        if dedupe_backend.check_and_record(message.message_id).is_duplicate:
            logger.info("Duplicate wamid %s ignored", message.message_id)
            return PlainTextResponse("OK", status_code=200)

        # Acknowledge to Meta FIRST. Analysis can take seconds (Whisper,
        # playwright) and Meta retries aggressively on a slow response, which
        # would multiply load exactly when we are already slow.
        background.add_task(_handle_message, message)
        return PlainTextResponse("OK", status_code=200)

    @fastapi_app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "channel": "whatsapp",
            "graph_configured": client is not None,
        }

    async def _handle_message(message: InboundMessage) -> None:
        """Analyze and reply. Runs in the background after Meta is acknowledged."""
        if client is None:
            logger.error("Cannot reply to %s: Graph API is not configured", message.sender)
            return

        try:
            await _dispatch(message, client, store, analyzer)
        except WhatsAppGraphError as exc:
            # The user will see nothing. Log loudly: a silent failure here means
            # a victim got no warning.
            logger.error("Failed to reply to %s: %s", message.sender, exc)
        except Exception:
            logger.exception("Unhandled error while replying to %s", message.sender)

    return fastapi_app


async def _dispatch(
    message: InboundMessage,
    client: WhatsAppClient,
    store: dict[str, str],
    analyzer: Any,
) -> None:
    """Route one inbound message to the right handling path."""
    lookup = store.get if store else None
    lang, was_explicit = resolve_language(message.text, message.sender, preference_lookup=lookup)
    if was_explicit:
        # Persist an explicit choice. This is what stops the bot from guessing
        # wrong on every subsequent message.
        store[message.sender] = lang

    # --- Commands and button taps -------------------------------------
    if message.kind == "button":
        await _handle_button(message, client, store)
        return

    if message.kind in ("text",) and message.text.strip().upper() in ("HI", "HELLO", "SALAM", "START", "MENU"):
        await client.send_reply_buttons(message.sender, _WELCOME.get(lang, _WELCOME["roman"]), _BUTTONS_MENU)
        return

    if message.kind == "sticker":
        await client.send_text(
            message.sender,
            "Sticker ki janch nahi ho sakti. Message, link, tasveer ya voice note forward karein.",
        )
        return

    if message.kind == "unsupported":
        await client.send_text(
            message.sender,
            "Ye cheez main nahi parh sakta. Message ka text, screenshot, link ya voice note bhejein.",
        )
        return

    # --- Analyzable content -------------------------------------------
    if analyzer is None:
        logger.error("No analyzer configured; cannot process %s from %s", message.kind, message.sender)
        await client.send_text(
            message.sender,
            "Maaf kijiye, abhi janch nahi ho saki. Thori der baad dobara bhejein.",
        )
        return

    try:
        verdict = await _run_analyzer(analyzer, message, client, lang)
    except Exception:
        logger.exception("Analyzer failed for %s from %s", message.kind, message.sender)
        # Never leave the user in silence. Tell them it failed and what to do
        # instead -- the official PTA/NCCIA channels still work.
        await client.send_text(
            message.sender,
            "Maaf kijiye, is waqt janch nahi ho saki.\n"
            "Aap PTA ko 9000 par forward kar sakte hain, ya NCCIA 1930 par call kar sakte hain.",
        )
        return

    body = (verdict.get("text") or "").strip()
    if not body:
        # An analyzer that returns no renderable text is a bug on our side, but
        # the user still must not be met with silence.
        logger.error("Analyzer returned empty verdict text for %s from %s", message.kind, message.sender)
        await client.send_text(
            message.sender,
            "Maaf kijiye, natija nahi ban saka. Dobara bhejein ya PTA 9000 par forward karein.",
        )
        return

    await client.send_text(message.sender, body)

    # A spoken verdict is what makes the service usable for someone who cannot
    # read. Sent in addition to the text, never instead of it -- a family member
    # may pick up the phone later and need the written version.
    spoken_media_id = verdict.get("speech_media_id")
    if spoken_media_id:
        try:
            await client.send_audio_reply(message.sender, spoken_media_id)
        except WhatsAppGraphError:
            # The text verdict already arrived; a failed voice note is a
            # degraded experience, not a failure of the core promise.
            logger.warning("Voice reply failed for %s", message.sender)

    # Critical verdicts escalate to the Family Shield group. Isolation is the
    # scammer's main weapon, so reaching a relative is the structural counter --
    # and it happens without the user having to do anything.
    if verdict.get("notify_family") and verdict.get("family_alert"):
        await _notify_family(client, message.sender, str(verdict["family_alert"]))


async def _run_analyzer(analyzer: Any, message: InboundMessage, client: WhatsAppClient, lang: str) -> dict[str, Any]:
    """Call the analyzer, downloading media first when needed.

    The analyzer owns verdict *rendering* (it lives beside the string tables and
    the scoring engine in ``ai-service``), so this channel stays a thin transport
    and never has to import the detection internals. It must return a dict with
    at least ``text`` -- the message to send -- and may include:

      * ``speech_media_id``: an uploaded voice note to send as well
      * ``notify_family`` / ``family_alert``: escalate to Family Shield
      * ``label``, ``confidence``: for logging and metrics
    """
    payload: dict[str, Any] = {
        "kind": message.kind,
        "sender": message.sender,
        "language": lang,
        "replied_to_id": message.replied_to_id,
    }

    if message.text:
        payload["text"] = message.text

    if message.needs_media_download:
        media_bytes = await client.download_media(message.media_id or "")
        payload["media_base64"] = encode_media_base64(media_bytes)
        payload["mime"] = message.media_mime

    result = analyzer(payload)
    if hasattr(result, "__await__"):
        result = await result
    return result if isinstance(result, dict) else {"text": str(result)}


async def _notify_family(client: WhatsAppClient, sender: str, alert_text: str) -> None:
    """Push a critical verdict to the user's family group.

    Resolution of *who* the family members are is the backend's job (it owns the
    ``family_groups`` / ``family_members`` tables). Here we only deliver. A
    failure to notify must never prevent or corrupt the reply to the user
    themselves -- the primary promise is the verdict.
    """
    try:
        backend_url = os.environ.get("BACKEND_URL", "").rstrip("/")
        if not backend_url:
            logger.info("BACKEND_URL not set; skipping family notification for %s", sender)
            return
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.post(
                f"{backend_url}/api/family/alerts/escalate",
                json={"sender": sender, "message": alert_text},
                headers={"X-Internal-Token": os.environ.get("INTERNAL_API_TOKEN", "")},
            )
            if response.status_code >= 400:
                logger.warning(
                    "Family escalation for %s returned %s", sender, response.status_code
                )
    except Exception:
        logger.exception("Family escalation failed for %s", sender)


async def _handle_button(message: InboundMessage, client: WhatsAppClient, store: dict[str, str]) -> None:
    """Handle a reply-button tap.

    Buttons exist to remove typing entirely. The ``WRONG`` payload in particular
    is how we collect the human feedback labels that the detection model depends
    on (see ``docs/BLUEPRINT.md`` §5.1) — it must be frictionless, or we get none.
    """
    action = (message.text or "").strip().upper()

    if action == "WRONG":
        await client.send_text(
            message.sender,
            "Shukriya, aap ne bataya ke ye natija ghalat tha. Ye humein behtar banane mein madad dega.\n"
            "Agar aap ko lagta hai ye scam THA, to foran sender block karein aur PTA 9000 par forward karein.",
        )
        return

    if action == "CORRECT":
        await client.send_text(message.sender, "Shukriya. Apne ghar walon ko bhi is number ke baare mein batayein.")
        return

    if action == "FAMILY":
        await client.send_text(
            message.sender,
            "Family Shield: apne ghar ke kisi naujawan ko ye number bhejein aur kahein ke wo bhi save kar le.\n"
            "Jab aap kuch forward karein ge, unhein bhi khabar ho jaye gi.",
        )
        return

    if action == "HELP":
        await client.send_text(
            message.sender,
            _WELCOME.get(store.get(message.sender, "roman"), _WELCOME["roman"]),
        )
        return

    if action.startswith("LANG"):
        await client.send_text(
            message.sender,
            "Zubaan badalne ke liye ye likh kar bhejein:\n"
            "LANG ROMAN\nLANG URDU\nLANG ENGLISH\nLANG SINDHI\nLANG PUNJABI\nLANG PASHTO\nLANG BALOCHI",
        )
        return

    await client.send_text(message.sender, _WELCOME.get(store.get(message.sender, "roman"), _WELCOME["roman"]))
