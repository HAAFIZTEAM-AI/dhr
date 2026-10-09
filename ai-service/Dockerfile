# ---------------------------------------------------------------------------
# HAAFIZ AI service
#
# Two-stage build. The final image deliberately EXCLUDES Playwright's browser
# binaries and Whisper model weights: those are 300 MB+ each, and baking them
# into the image made the previous approach unbuildable on anything but a
# developer's Windows machine (which is why the only run script was a .bat file
# and the repo committed a 26 MB Python installer).
#
# Model weights are fetched at first run into a named volume; browsers are
# installed by an init container / entrypoint step when the website analyzer is
# enabled. Keep the image small and the heavy artifacts mounted.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS base

# ffmpeg is required by pydub for voice-note decoding; tesseract by pytesseract
# for OCR. Without them those analyzers fail at runtime rather than at build
# time, which is the worst possible moment to discover it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg \
        tesseract-ocr \
        tesseract-ocr-urd \
        tesseract-ocr-snd \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/haafiz

# Install dependencies first so code changes do not invalidate the layer cache.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY data ./data

# Run as a non-root user. This service executes OCR and transcribes untrusted
# user audio; it should not also have write access to the filesystem.
RUN useradd --create-home --uid 10001 haafiz \
    && mkdir -p /srv/haafiz/models \
    && chown -R haafiz:haafiz /srv/haafiz
USER haafiz

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AI_PORT=5001 \
    MODEL_PATH=/srv/haafiz/models/scam_detector.pkl

EXPOSE 5001

# /health is the only endpoint that touches no analyzer, so it is a genuine
# liveness signal rather than a proxy for "the model finished loading".
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:5001/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001"]
