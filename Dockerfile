# ── OrcAgent — production image ──
# Sensitive variables (API keys, private keys, secrets) are NEVER set here.
# They are injected at runtime via Railway's Variables tab → os.environ.
FROM python:3.12-slim

# Node.js 20 LTS (apt-based via NodeSource, no separate image)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Safe, non-sensitive build/runtime configuration only
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Bridge (Node) dependencies -- copied/installed before the Python deps below,
# same layer-caching reasoning as requirements.txt. Placed after WORKDIR /app
# (not immediately after the Node install above) so ./bridge/ resolves to
# /app/bridge/ -- copying it before WORKDIR is set would land it at /bridge/
# instead, which COPY . . below would then shadow with a second, dependency-
# less copy at /app/bridge/, breaking `require()` at runtime.
COPY bridge/ ./bridge/
RUN cd bridge && npm install --production

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
