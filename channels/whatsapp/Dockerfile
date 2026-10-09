# ---------------------------------------------------------------------------
# HAAFIZ WhatsApp channel
#
# Deliberately dependency-light: this service is a transport. It verifies the
# webhook signature, de-duplicates, detects the reply language, downloads media
# and forwards to the AI service. It never imports the heavy analyzer stack, so
# it starts in under a second and cannot be starved by a Whisper transcription
# running in the same process.
# ---------------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /srv/haafiz

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root: this container terminates a publicly reachable webhook.
RUN useradd --create-home --uid 10001 haafiz && chown -R haafiz:haafiz /srv/haafiz
USER haafiz

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WHATSAPP_PORT=5002

EXPOSE 5002

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:5002/health || exit 1

CMD ["uvicorn", "app:create_app", "--factory", "--host", "0.0.0.0", "--port", "5002"]
