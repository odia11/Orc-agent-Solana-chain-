# ── OrcAgent — production image ──
# Sensitive variables (API keys, private keys, secrets) are NEVER set here.
# They are injected at runtime via Railway's Variables tab → os.environ.
FROM python:3.12-slim

# Safe, non-sensitive build/runtime configuration only
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first (layer-cached until requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Railway injects PORT at runtime; expose it as documentation only
EXPOSE 8080

# Start gunicorn — PORT is supplied by Railway at container start, not baked in
CMD ["sh", "-c", "gunicorn dashboard:app --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 4 --timeout 120"]
