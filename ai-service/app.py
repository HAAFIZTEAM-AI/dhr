"""HAAFIZ AI service -- FastAPI entrypoint.

Notes on things that are deliberately the way they are:

* Every analyzer is synchronous and CPU- or network-bound (Whisper, OCR,
  Playwright, WHOIS). Declaring the routes ``async def`` and calling those
  functions directly blocks the whole event loop for the duration of one
  request, so a single voice note freezes every other client. Each call is
  dispatched to a worker thread instead.
* CORS is configured from the environment. ``allow_origins=["*"]`` together
  with ``allow_credentials=True`` is invalid per the CORS specification and
  browsers reject the response outright -- it looks like it works in curl and
  fails in every real browser.
* ``/health`` exists because the Dockerfile HEALTHCHECK and the compose
  ``condition: service_healthy`` dependency both require it. Without it the
  container never becomes healthy and the backend never starts.
"""

from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
import os
import json
from analyzers.text_analyzer import analyze_text
from analyzers.website_analyzer import analyze_website
from analyzers.voice_analyzer import analyze_voice
from analyzers.phone_analyzer import analyze_phone
from analyzers.image_analyzer import analyze_image
from haafiz.intel.domain_similarity import (
    BrandImpersonationDetector,
    load_brands_from_file,
)
from haafiz.intel.federation import build_default_federation
from dotenv import load_dotenv

load_dotenv()
app = FastAPI(title="HAAFIZ AI Service", version="2.0.0")

# Comma-separated list of allowed origins, e.g.
#   CORS_ORIGINS=http://localhost:5173,https://haafiz.pk
# Wildcard is permitted only when credentials are disabled, because the
# combination is invalid and silently breaks every browser client.
_raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").strip()
_allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]
_allow_credentials = "*" not in _allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# Threat intelligence (offline by default)
# ---------------------------------------------------------------------------

_registry_path = os.environ.get(
    "HAAFIZ_VERIFIED_DOMAINS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "verified_domains.txt"),
)
_detector = BrandImpersonationDetector(load_brands_from_file(_registry_path))
_federation = build_default_federation(_detector)


class TextRequest(BaseModel):
    text: str
    language: str = "auto"


class WebsiteRequest(BaseModel):
    url: str


class VoiceRequest(BaseModel):
    audio_base64: str
    language: str = "auto"


class PhoneRequest(BaseModel):
    phone_number: str


class ImageRequest(BaseModel):
    image_base64: str


class IntelRequest(BaseModel):
    """A URL or bare hostname to check against every configured source."""

    url: str


# ---------------------------------------------------------------------------
# Liveness
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Touch nothing expensive: no model load, no network, no analyzer.

    A liveness probe that depends on the thing it is supposed to monitor
    reports "unhealthy" for the wrong reasons and gets ignored, which is worse
    than not having it.
    """
    return {
        "status": "ok",
        "service": "haafiz-ai",
        "brands_loaded": len(_detector.brands),
    }


# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------

@app.post("/analyze/text")
async def text_analysis(req: TextRequest):
    return await run_in_threadpool(analyze_text, req.text, req.language)


@app.post("/analyze/website")
async def website_analysis(req: WebsiteRequest):
    # The only genuinely async analyzer (Playwright).
    return await analyze_website(req.url)


@app.post("/analyze/voice")
async def voice_analysis(req: VoiceRequest):
    return await run_in_threadpool(analyze_voice, req.audio_base64, req.language)


@app.post("/analyze/phone")
async def phone_analysis(req: PhoneRequest):
    return await run_in_threadpool(analyze_phone, req.phone_number)


@app.post("/analyze/image")
async def image_analysis(req: ImageRequest):
    return await run_in_threadpool(analyze_image, req.image_base64)


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------

@app.post("/analyze/intel")
async def intel_check(req: IntelRequest):
    """Federated verdict on one URL.

    This is the endpoint that answers the question VirusTotal cannot: a domain
    registered twenty minutes ago, present on no blocklist anywhere, still gets
    a confident verdict from the brand-impersonation detector plus the local
    registry -- both of which are offline and instant.

    Runs sources concurrently under per-source deadlines, so total latency is
    the slowest source that is still inside its budget, not the sum.
    """
    # Two statements, not one: `await f().to_dict()` parses as
    # `await (f().to_dict())`, which calls to_dict on the coroutine itself.
    verdict = await run_in_threadpool(_federation.check, req.url)
    return verdict.to_dict()


@app.post("/analyze/domain")
async def domain_check(req: IntelRequest):
    """Brand-impersonation assessment only. No network, no quota, no latency.

    Pure and deterministic, so it runs inline rather than in a worker thread --
    dispatching to the pool would cost more than the check itself. Useful from
    a browser extension or a Call Directory builder, where the answer has to
    come back in microseconds on device.
    """
    host = req.url.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    return _detector.assess(host.split("/")[0]).as_dict()


@app.get("/intel/registry")
async def registry_summary():
    """Which institutions this deployment can vouch for.

    Public by design: it is a list of real, official domains, and publishing it
    lets users verify that HAAFIZ knows their bank before they trust a verdict.
    """
    return {
        "brands": len(_detector.brands),
        "domains": sum(len(b.official_domains) for b in _detector.brands),
        "problems": _detector.validate_registry(),
        "institutions": sorted(b.name for b in _detector.brands),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
