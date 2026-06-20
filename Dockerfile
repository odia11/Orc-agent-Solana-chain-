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

# start.sh launches monitor.py in the background, then execs gunicorn as PID 1
RUN chmod +x start.sh
CMD ["sh", "start.sh"]
